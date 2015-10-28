/*
 * Copyright (c) 2015 Oracle and/or its affiliates. All rights reserved.
 *
 */

#include <xen/smp.h>
#include <xen/keyhandler.h>
#include <xen/spinlock.h>
#include <xen/mm.h>
#include <xen/list.h>
#include <xen/guest_access.h>
#include <xen/stdbool.h>
#include <xen/sched.h>
#include <xen/lib.h>
#include <xen/xsplice_elf.h>
#include <xen/xsplice.h>
#include <public/sysctl.h>

#include <asm/event.h>

static DEFINE_SPINLOCK(payload_list_lock);
static LIST_HEAD(payload_list);

static unsigned int payload_cnt;
static unsigned int payload_version = 1;

struct payload {
    int32_t state;     /* One of XSPLICE_STATE_*. */
    int32_t rc;         /* 0 or -EXX. */

    struct list_head   list;   /* Linked to 'payload_list'. */

    void *module_address;
    size_t module_pages;

    char  id[XEN_XSPLICE_NAME_SIZE + 1];          /* Name of it. */
};

static int load_module(struct payload *payload, uint8_t *raw, ssize_t len);
static void free_module(struct payload *payload);

static const char *state2str(int32_t state)
{
#define STATE(x) [XSPLICE_STATE_##x] = #x
    static const char *const names[] = {
            STATE(LOADED),
            STATE(CHECKED),
            STATE(APPLIED),
    };
#undef STATE

    if (state >= ARRAY_SIZE(names))
        return "unknown";

    if (state < 0)
        return "-EXX";

    if (!names[state])
        return "unknown";

    return names[state];
}

void xsplice_printall(unsigned char key)
{
    struct payload *data;

    spin_lock(&payload_list_lock);

    list_for_each_entry ( data, &payload_list, list )
    {
        printk(" id=%s state=%s(%d): \n", data->id,
               state2str(data->state), data->state);
    }
    spin_unlock(&payload_list_lock);
}

static int verify_id(xen_xsplice_id_t *id)
{
    if ( id->size == 0 || id->size > XEN_XSPLICE_NAME_SIZE )
        return -EINVAL;

    if ( id->pad != 0 )
        return -EINVAL;

    if ( !guest_handle_okay(id->name, id->size) )
        return -EINVAL;

    return 0;
}

int find_payload(xen_xsplice_id_t *id, bool_t need_lock, struct payload **f)
{
    struct payload *data;
    XEN_GUEST_HANDLE_PARAM(char) str;
    char name[XEN_XSPLICE_NAME_SIZE + 1] = { 0 }; /* 128 + 1 bytes on stack. Perhaps kzalloc? */
    int rc = -EINVAL;

    rc = verify_id(id);
    if ( rc )
        return rc;

    str = guest_handle_cast(id->name, char);
    if ( copy_from_guest(name, str, id->size) )
        return -EFAULT;

    if ( need_lock )
        spin_lock(&payload_list_lock);

    rc = -ENOENT;
    list_for_each_entry ( data, &payload_list, list )
    {
        if ( !strcmp(data->id, name) )
        {
            *f = data;
            rc = 0;
            break;
        }
    }

    if ( need_lock )
        spin_unlock(&payload_list_lock);

    return rc;
}


static int verify_payload(xen_sysctl_xsplice_upload_t *upload)
{
    if ( verify_id(&upload->id) )
        return -EINVAL;

    if ( upload->size == 0 )
        return -EINVAL;

    if ( !guest_handle_okay(upload->payload, upload->size) )
        return -EFAULT;

    return 0;
}

/*
 * We MUST be holding the spinlock.
 */
static void __free_payload(struct payload *data)
{
    list_del(&data->list);
    payload_cnt --;
    payload_version ++;
    free_module(data);
    xfree(data);
}

static int xsplice_upload(xen_sysctl_xsplice_upload_t *upload)
{
    struct payload *data = NULL;
    uint8_t *raw_data;
    int rc;

    rc = verify_payload(upload);
    if ( rc )
        return rc;

    rc = find_payload(&upload->id, true, &data);
    if ( rc == 0 /* Found. */ )
        return -EEXIST;

    if ( rc != -ENOENT )
        return rc;

    data = xzalloc(struct payload);
    if ( !data )
        return -ENOMEM;
    memset(data, 0, sizeof *data);

    rc = -EFAULT;
    if ( copy_from_guest(data->id, upload->id.name, upload->id.size) )
        goto err_data;

    rc = -ENOMEM;
    raw_data = alloc_xenheap_pages(get_order_from_bytes(upload->size), 0);
    if ( !raw_data )
        goto err_data;

    rc = -EFAULT;
    if ( copy_from_guest(raw_data, upload->payload, upload->size) )
        goto err_raw;

    rc = load_module(data, raw_data, upload->size);
    if ( rc )
        goto err_raw;

    data->state = XSPLICE_STATE_LOADED;
    data->rc = 0;
    INIT_LIST_HEAD(&data->list);

    spin_lock(&payload_list_lock);
    list_add_tail(&data->list, &payload_list);
    payload_cnt ++;
    payload_version ++;
    spin_unlock(&payload_list_lock);

    free_xenheap_pages(raw_data, get_order_from_bytes(upload->size));
    return 0;

err_raw:
    free_xenheap_pages(raw_data, get_order_from_bytes(upload->size));
err_data:
    xfree(data);
    return rc;
}

static int xsplice_get(xen_sysctl_xsplice_summary_t *summary)
{
    struct payload *data;
    int rc;

    if ( summary->status.state )
        return -EINVAL;

    if ( summary->status.rc != 0 )
        return -EINVAL;

    rc = verify_id(&summary->id );
    if ( rc )
        return rc;

    rc = find_payload(&summary->id, true, &data);
    if ( rc )
        return rc;

    summary->status.state = data->state;
    summary->status.rc = data->rc;

    return 0;
}

static int xsplice_list(xen_sysctl_xsplice_list_t *list)
{
    xen_xsplice_status_t status;
    struct payload *data;
    unsigned int idx = 0, i = 0;
    int rc = 0;
    unsigned int ver = payload_version;

    if ( list->nr > 1024 )
        return -E2BIG;

    if ( list->pad != 0 )
        return -EINVAL;

    if ( guest_handle_is_null(list->status) ||
         guest_handle_is_null(list->id) ||
         guest_handle_is_null(list->len) )
        return -EINVAL;

    if ( !guest_handle_okay(list->status, sizeof(status) * list->nr) ||
         !guest_handle_okay(list->id, XEN_XSPLICE_NAME_SIZE * list->nr) ||
         !guest_handle_okay(list->len, sizeof(uint32_t) * list->nr) )
        return -EINVAL;

    spin_lock(&payload_list_lock);
    if ( list->idx > payload_cnt )
    {
        spin_unlock(&payload_list_lock);
        return -EINVAL;
    }

    list_for_each_entry( data, &payload_list, list )
    {
        uint32_t len;

        if ( list->idx > i++ )
            continue;

        status.state = data->state;
        status.rc = data->rc;
        len = strlen(data->id);

        /* N.B. 'idx' != 'i'. */
        if ( copy_to_guest_offset(list->id, idx * XEN_XSPLICE_NAME_SIZE,
                                  data->id, len) ||
             copy_to_guest_offset(list->len, idx, &len, 1) ||
             copy_to_guest_offset(list->status, idx, &status, 1) )
        {
            rc = -EFAULT;
            break;
        }
        idx ++;
        if ( hypercall_preempt_check() || (idx + 1 > list->nr) )
        {
            break;
        }
    }
    list->nr = payload_cnt - i; /* Remaining amount. */
    spin_unlock(&payload_list_lock);
    list->version = ver;

    /* And how many we have processed. */
    return rc ? rc : idx;
}

static int xsplice_action(xen_sysctl_xsplice_action_t *action)
{
    struct payload *data;
    int rc;

    if ( action->pad != 0 )
        return -EINVAL;

    rc = verify_id(&action->id);
    if ( rc )
        return rc;

    spin_lock(&payload_list_lock);
    rc = find_payload(&action->id, false /* we are holding the lock. */, &data);
    if ( rc )
        goto out;

    switch ( action->cmd )
    {
    case XSPLICE_ACTION_CHECK:
        if ( (data->state == XSPLICE_STATE_LOADED) ||
             (data->state == XSPLICE_STATE_CHECKED) )
        {
            /* No implementation yet. */
            data->state = XSPLICE_STATE_CHECKED;
            data->rc = 0;
            rc = 0;
        }
        break;
    case XSPLICE_ACTION_UNLOAD:
        if ( (data->state == XSPLICE_STATE_LOADED) ||
             (data->state == XSPLICE_STATE_CHECKED) )
        {
            __free_payload(data);
            /* No touching 'data' from here on! */
            rc = 0;
        }
        break;
    case XSPLICE_ACTION_REVERT:
        if ( data->state == XSPLICE_STATE_APPLIED )
        {
            /* No implementation yet. */
            data->state = XSPLICE_STATE_CHECKED;
            data->rc = 0;
            rc = 0;
        }
        break;
    case XSPLICE_ACTION_APPLY:
        if ( (data->state == XSPLICE_STATE_CHECKED) )
        {
            /* No implementation yet. */
            data->state = XSPLICE_STATE_APPLIED;
            data->rc = 0;
            rc = 0;
        }
        break;
    case XSPLICE_ACTION_REPLACE:
        if ( data->state == XSPLICE_STATE_CHECKED )
        {
            /* No implementation yet. */
            data->state = XSPLICE_STATE_CHECKED;
            data->rc = 0;
            rc = 0;
        }
        break;
    default:
        rc = -ENOSYS;
        break;
    }

 out:
    spin_unlock(&payload_list_lock);

    return rc;
}

int xsplice_control(xen_sysctl_xsplice_op_t *xsplice)
{
    int rc;

    switch ( xsplice->cmd )
    {
    case XEN_SYSCTL_XSPLICE_UPLOAD:
        rc = xsplice_upload(&xsplice->u.upload);
        break;
    case XEN_SYSCTL_XSPLICE_GET:
        rc = xsplice_get(&xsplice->u.get);
        break;
    case XEN_SYSCTL_XSPLICE_LIST:
        rc = xsplice_list(&xsplice->u.list);
        break;
    case XEN_SYSCTL_XSPLICE_ACTION:
        rc = xsplice_action(&xsplice->u.action);
        break;
    default:
        rc = -ENOSYS;
        break;
   }

    return rc;
}


/*
 * The following functions prepare an xSplice module to be executed by
 * allocating space, loading the allocated sections, resolving symbols,
 * performing relocations, etc.
 */
#ifdef CONFIG_X86
static void *alloc_module(size_t size)
{
    mfn_t *mfn, *mfn_ptr;
    size_t pages, i;
    struct page_info *pg;
    unsigned long hole_start, hole_end, cur;
    struct payload *data, *data2;

    ASSERT(size);

    pages = PFN_UP(size);
    mfn = xmalloc_array(mfn_t, pages);
    if ( mfn == NULL )
        return NULL;

    for ( i = 0; i < pages; i++ )
    {
        pg = alloc_domheap_page(NULL, 0);
        if ( pg == NULL )
            goto error;
        mfn[i] = _mfn(page_to_mfn(pg));
    }

    hole_start = (unsigned long)module_virt_start;
    hole_end = hole_start + pages * PAGE_SIZE;
    spin_lock(&payload_list_lock);
    list_for_each_entry ( data, &payload_list, list )
    {
        list_for_each_entry ( data2, &payload_list, list )
        {
            unsigned long start, end;

            start = (unsigned long)data2->module_address;
            end = start + data2->module_pages * PAGE_SIZE;
            if ( hole_end > start && hole_start < end )
            {
                hole_start = end;
                hole_end = hole_start + pages * PAGE_SIZE;
                break;
            }
        }
        if ( &data2->list == &payload_list )
            break;
    }
    spin_unlock(&payload_list_lock);

    if ( hole_end >= module_virt_end )
        goto error;

    for ( cur = hole_start, mfn_ptr = mfn; pages--; ++mfn_ptr, cur += PAGE_SIZE )
    {
        if ( map_pages_to_xen(cur, mfn_x(*mfn_ptr), 1, PAGE_HYPERVISOR_RWX) )
        {
            if ( cur != hole_start )
                destroy_xen_mappings(hole_start, cur);
            goto error;
        }
    }
    xfree(mfn);
    return (void *)hole_start;

 error:
    while ( i-- )
        free_domheap_page(mfn_to_page(mfn_x(mfn[i])));
    xfree(mfn);
    return NULL;
}
#else
static void *alloc_module(size_t size)
{
    return NULL;
}
#endif

static void free_module(struct payload *payload)
{
    int i;
    struct page_info *pg;
    PAGE_LIST_HEAD(pg_list);
    void *va = payload->module_address;
    unsigned long addr = (unsigned long)va;

    if ( !payload->module_address )
        return;

    payload->module_address = NULL;

    for ( i = 0; i < payload->module_pages; i++ )
        page_list_add(vmap_to_page(va + i * PAGE_SIZE), &pg_list);

    destroy_xen_mappings(addr, addr + payload->module_pages * PAGE_SIZE);

    while ( (pg = page_list_remove_head(&pg_list)) != NULL )
        free_domheap_page(pg);

    payload->module_pages = 0;
}

static void alloc_section(struct xsplice_elf_sec *sec, size_t *core_size)
{
    size_t align_size = ROUNDUP(*core_size, sec->sec->sh_addralign);
    sec->sec->sh_entsize = align_size;
    *core_size = sec->sec->sh_size + align_size;
}

static int move_module(struct payload *payload, struct xsplice_elf *elf)
{
    uint8_t *buf;
    int i;
    size_t core_size = 0;

    /* Allocate text regions */
    for ( i = 0; i < elf->hdr->e_shnum; i++ )
    {
        if ( (elf->sec[i].sec->sh_flags & (SHF_ALLOC|SHF_EXECINSTR)) ==
             (SHF_ALLOC|SHF_EXECINSTR) )
            alloc_section(&elf->sec[i], &core_size);
    }

    /* Allocate rw data */
    for ( i = 0; i < elf->hdr->e_shnum; i++ )
    {
        if ( (elf->sec[i].sec->sh_flags & SHF_ALLOC) &&
             !(elf->sec[i].sec->sh_flags & SHF_EXECINSTR) &&
             (elf->sec[i].sec->sh_flags & SHF_WRITE) )
            alloc_section(&elf->sec[i], &core_size);
    }

    /* Allocate ro data */
    for ( i = 0; i < elf->hdr->e_shnum; i++ )
    {
        if ( (elf->sec[i].sec->sh_flags & SHF_ALLOC) &&
             !(elf->sec[i].sec->sh_flags & SHF_EXECINSTR) &&
             !(elf->sec[i].sec->sh_flags & SHF_WRITE) )
            alloc_section(&elf->sec[i], &core_size);
    }

    buf = alloc_module(core_size);
    if ( !buf ) {
        printk(XENLOG_ERR "Could not allocate memory for module\n");
        return -ENOMEM;
    }
    memset(buf, 0, core_size);

    for ( i = 0; i < elf->hdr->e_shnum; i++ )
    {
        if ( elf->sec[i].sec->sh_flags & SHF_ALLOC )
        {
            elf->sec[i].load_addr = buf + elf->sec[i].sec->sh_entsize;
            memcpy(elf->sec[i].load_addr, elf->sec[i].data,
                   elf->sec[i].sec->sh_size);
            printk(XENLOG_DEBUG "Loaded %s at 0x%p\n",
                   elf->sec[i].name, elf->sec[i].load_addr);
        }
    }

    payload->module_address = buf;
    payload->module_pages = PFN_UP(core_size);

    return 0;
}

static int resolve_symbols(struct xsplice_elf *elf)
{
    int i;

    for ( i = 1; i < elf->nsym; i++ )
    {
        switch ( elf->sym[i].sym->st_shndx )
        {
            case SHN_COMMON:
                printk(XENLOG_ERR "Unexpected common symbol: %s\n",
                       elf->sym[i].name);
                return -EINVAL;
                break;
            case SHN_UNDEF:
                printk(XENLOG_ERR "Unknown symbol: %s\n", elf->sym[i].name);
                return -ENOENT;
                break;
            case SHN_ABS:
                printk(XENLOG_DEBUG "Absolute symbol: %s => 0x%p\n",
                       elf->sym[i].name, (void *)elf->sym[i].sym->st_value);
                break;
            default:
                if ( elf->sec[elf->sym[i].sym->st_shndx].sec->sh_flags & SHF_ALLOC )
                {
                    elf->sym[i].sym->st_value +=
                        (unsigned long)elf->sec[elf->sym[i].sym->st_shndx].load_addr;
                    printk(XENLOG_DEBUG "Symbol resolved: %s => 0x%p\n",
                           elf->sym[i].name, (void *)elf->sym[i].sym->st_value);
                }
        }
    }

    return 0;
}

static int perform_relocs(struct xsplice_elf *elf)
{
    struct xsplice_elf_sec *rela, *base;
    int i, rc;

    for ( i = 0; i < elf->hdr->e_shnum; i++ )
    {
        rela = &elf->sec[i];

        /* Is it a valid relocation section? */
        if ( rela->sec->sh_info >= elf->hdr->e_shnum )
            continue;

        base = &elf->sec[rela->sec->sh_info];

        /* Don't relocate non-allocated sections */
        if ( !(base->sec->sh_flags & SHF_ALLOC) )
            continue;

        if ( elf->sec[i].sec->sh_type == SHT_RELA )
            rc = xsplice_perform_rela(elf, base, rela);
        else if ( elf->sec[i].sec->sh_type == SHT_REL )
            rc = xsplice_perform_rel(elf, base, rela);

        if ( rc )
            return rc;
    }

    return 0;
}

static int load_module(struct payload *payload, uint8_t *raw, ssize_t len)
{
    struct xsplice_elf elf;
    int rc = 0;

    rc = xsplice_verify_elf(raw, len);
    if ( rc )
        return rc;

    rc = xsplice_elf_load(&elf, raw, len);
    if ( rc )
        return rc;

    rc = move_module(payload, &elf);
    if ( rc )
        goto err_elf;

    rc = resolve_symbols(&elf);
    if ( rc )
        goto err_module;

    rc = perform_relocs(&elf);
    if ( rc )
        goto err_module;

    return 0;

 err_module:
    free_module(payload);
 err_elf:
    xsplice_elf_free(&elf);

    return rc;
}

static int __init xsplice_init(void)
{
    register_keyhandler('x', xsplice_printall, "print xsplicing info", 1);
    return 0;
}
__initcall(xsplice_init);
