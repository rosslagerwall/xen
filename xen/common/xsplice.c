/*
 * xSplice - Copyright Oracle Corp. Inc 2015.
 *
 * Author: Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>
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
#include <xen/version.h>
#include <xen/xsplice.h>
#include <xen/wait.h>
#include <xen/softirq.h>
#include <public/sysctl.h>

#include <asm/event.h>
#include <asm/alternative.h>
#include <asm/nmi.h>

#define return_where(x) { printk("%s:%d err=%d\n", __func__,__LINE__, x); return x; }
static DEFINE_SPINLOCK(payload_list_lock);
static LIST_HEAD(payload_list);

static LIST_HEAD(bug_list);

#define SHADOW_SLOTS 256
struct hlist_head shadow_tbl[SHADOW_SLOTS];
static DEFINE_SPINLOCK(shadow_lock);

struct shadow_var {
    struct hlist_node   list; /* Linked to 'shadow_tbl' */
    void *data;
    const void *obj;
    char var[16];
};

static unsigned int payload_cnt;
static unsigned int payload_version = 1;

struct payload {
    int32_t status;     /* XSPLICE_STATUS_* or Exx type value. */
    int32_t old_status; /* XSPLICE_STATUS_* or Exx type value. */

    struct spinlock cmd_lock; /* Lock against the action. */
    uint32_t cmd;       /* Action request. XSPLICE_ACTION_* */

    /* Boring things below: */
    struct list_head   list;   /* Linked to 'payload_list'. */

    struct xsplice_patch_func *funcs;
    int nfuncs;
    xsplice_loadcall_t *load_funcs;
    xsplice_unloadcall_t *unload_funcs;
    int n_load_funcs;
    int n_unload_funcs;
    void *module_address;
    size_t module_pages;
    struct bug_frame *start_bug_frames[4];
    struct bug_frame *stop_bug_frames[4];
    struct exception_table_entry *start_ex_table;
    struct exception_table_entry *stop_ex_table;
    struct list_head   bug_list;   /* Linked to 'bug_list'. */

    struct tasklet tasklet;

    char  id[XEN_XSPLICE_ID_SIZE + 1];          /* Name of it. */
};

struct xsplice_work
{
    atomic_t semaphore;          /* Used for rendezvous */
    atomic_t irq_semaphore;      /* Used to signal all IRQs disabled */
    struct payload *data;        /* The payload on which to act */
    volatile bool_t do_work;     /* Signals work to do */
    volatile bool_t ready;       /* Signals all CPUs synchronized */
};

static DEFINE_SPINLOCK(xsplice_work_lock);
static struct xsplice_work xsplice_work;

static void free_module(struct payload *payload);

static const char *status2str(int64_t status)
{
#define STATUS(x) [XSPLICE_STATUS_##x] = #x
    static const char *const names[] = {
            STATUS(LOADED),
            STATUS(PROGRESS),
            STATUS(CHECKED),
            STATUS(APPLIED),
            STATUS(REVERTED),
    };
#undef STATUS

    if (status >= ARRAY_SIZE(names))
        return "unknown";

    if (status < 0)
        return "-EXX";

    if (!names[status])
        return "unknown";

    return names[status];
}

#ifdef DEBUG_TRACE_DUMP
extern int debugtrace_dump_guest(unsigned int idx, ssize_t len,
                                 XEN_GUEST_HANDLE_PARAM(char) buffer);

static const char *action2str(uint32_t action)
{
#define ACTION(x) [XSPLICE_ACTION_##x] = #x
    static const char *const names[] = {
            ACTION(CHECK),
            ACTION(APPLY),
            ACTION(REVERT),
            ACTION(UNLOAD),
    };
#undef ACTION
    if (action >= ARRAY_SIZE(names))
        return "unknown";

    if (!names[action])
        return "unknown";

    return names[action];
}
#endif

void xsplice_printall(unsigned char key)
{
    struct payload *data;
    char *binary_id = NULL;
    unsigned int len = 0;
    int rc;

    rc = xen_build_id(&binary_id, &len);
    printk("build-id: ");
    if ( !rc )
    {
        unsigned int i;

        for ( i = 0; i < len; i++ )
        {
		    uint8_t c = binary_id[i];
		    printk("%02x", c);
        }
	    printk("\n");
    } else if ( rc < 0 )
        printk("rc = %d\n", rc);

    spin_lock(&payload_list_lock);

    list_for_each_entry ( data, &payload_list, list )
    {
        printk(" id=%s status=%s(%d,old=%d): \n", data->id,
               status2str(data->status), data->status, data->old_status);
    }
    spin_unlock(&payload_list_lock);
}

static int verify_id(xen_xsplice_id_t *id)
{
    if ( id->size == 0 || id->size > XEN_XSPLICE_ID_SIZE )
        return_where( -EINVAL);

    if ( id->_pad != 0 )
        return_where( -EINVAL);

    if ( !guest_handle_okay(id->name, id->size) )
        return_where( -EINVAL);

    return 0;
}

int find_payload(xen_xsplice_id_t *id, bool_t need_lock, struct payload **f)
{
    struct payload *data;
    XEN_GUEST_HANDLE_PARAM(char) str;
    char name[XEN_XSPLICE_ID_SIZE + 1] = {0}; /* 128 + 1 bytes on stack. Perhaps kzalloc? */
    int rc = -EINVAL;

    rc = verify_id(id);
    if ( rc )
        return_where( rc);

    str = guest_handle_cast(id->name, char);
    if ( copy_from_guest(name, str, id->size) )
        return_where( -EFAULT);

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

    return_where( rc);
}


static int verify_payload(xen_sysctl_xsplice_upload_t *upload)
{
    if ( verify_id(&upload->id) )
        return_where( -EINVAL);

    if ( upload->size == 0 )
        return_where( -EINVAL);

    if ( !guest_handle_okay(upload->payload, upload->size) )
        return_where( -EFAULT);

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
    tasklet_kill(&data->tasklet);
    debugtrace_printk("%s=freed\n", data->id);
    free_module(data);
    xfree(data);
}

static void *
alloc_module(size_t size)
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
            if (hole_end > start && hole_start < end) {
                hole_start = end;
                hole_end = hole_start + pages * PAGE_SIZE;
                break;
            }
        }
        if (&data2->list == &payload_list)
            break;
    }
    spin_unlock(&payload_list_lock);

    if (hole_end >= module_virt_end)
        goto error;

    for ( cur = hole_start, mfn_ptr = mfn; pages--; ++mfn_ptr, cur += PAGE_SIZE )
    {
        if ( map_pages_to_xen(cur, mfn_x(*mfn_ptr), 1, PAGE_HYPERVISOR_RWX) )
        {
            if (cur != hole_start)
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

static void
free_module(struct payload *payload)
{
    int i;
    struct page_info *pg;
    PAGE_LIST_HEAD(pg_list);
    void *va = payload->module_address;
    unsigned long addr = (unsigned long)va;

    if (!payload->module_address)
        return;

    payload->module_address = NULL;

    for ( i = 0; i < payload->module_pages; i++ )
        page_list_add(vmap_to_page(va + i * PAGE_SIZE), &pg_list);

    destroy_xen_mappings(addr, addr + payload->module_pages * PAGE_SIZE);

    while ( (pg = page_list_remove_head(&pg_list)) != NULL )
        free_domheap_page(pg);

    payload->module_pages = 0;
}

static void
alloc_section(struct Elf_Sec *sec, size_t *core_size)
{
    size_t align_size = ROUNDUP(*core_size, sec->sec->sh_addralign);
    sec->sec->sh_entsize = align_size;
    *core_size = sec->sec->sh_size + align_size;
}

static int
move_module(struct payload *payload, struct Elf *elf)
{
    uint8_t *buf;
    int i;
    size_t core_size = 0;

    /* Allocate text regions */
    for (i = 0; i < elf->hdr->e_shnum; i++) {
        if ((elf->sec[i].sec->sh_flags & (SHF_ALLOC|SHF_EXECINSTR)) ==
                (SHF_ALLOC|SHF_EXECINSTR))
            alloc_section(&elf->sec[i], &core_size);
    }

    /* Allocate rw data */
    for (i = 0; i < elf->hdr->e_shnum; i++) {
        if ((elf->sec[i].sec->sh_flags & SHF_ALLOC) &&
                !(elf->sec[i].sec->sh_flags & SHF_EXECINSTR) &&
                (elf->sec[i].sec->sh_flags & SHF_WRITE))
            alloc_section(&elf->sec[i], &core_size);
    }

    /* Allocate ro data */
    for (i = 0; i < elf->hdr->e_shnum; i++) {
        if ((elf->sec[i].sec->sh_flags & SHF_ALLOC) &&
                !(elf->sec[i].sec->sh_flags & SHF_EXECINSTR) &&
                !(elf->sec[i].sec->sh_flags & SHF_WRITE))
            alloc_section(&elf->sec[i], &core_size);
    }

    buf = alloc_module(core_size);
    if (!buf) {
        printk(XENLOG_ERR "Could not allocate memory for module\n");
        return -ENOMEM;
    }
    memset(buf, 0, core_size);

    for (i = 0; i < elf->hdr->e_shnum; i++) {
        if (elf->sec[i].sec->sh_flags & SHF_ALLOC) {
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

static int
resolve_symbols(struct Elf *elf)
{
    int i;

    for (i = 1; i < elf->nsym; i++) {
        switch (elf->sym[i].sym->st_shndx) {
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
                if (elf->sec[elf->sym[i].sym->st_shndx].sec->sh_flags & SHF_ALLOC) {
                    elf->sym[i].sym->st_value +=
                        (unsigned long)elf->sec[elf->sym[i].sym->st_shndx].load_addr;
                    printk(XENLOG_DEBUG "Symbol resolved: %s => 0x%p\n",
                           elf->sym[i].name, (void *)elf->sym[i].sym->st_value);
                }
        }
    }

    return 0;
}

static int
perform_relocs(struct Elf *elf)
{
    struct Elf_Sec *rela, *base;
    int i, rc;

    for (i = 0; i < elf->hdr->e_shnum; i++) {
        rela = &elf->sec[i];

        /* Is it a valid relocation section? */
        if (rela->sec->sh_info >= elf->hdr->e_shnum)
            continue;

        base = &elf->sec[rela->sec->sh_info];

        /* Don't relocate non-allocated sections */
        if (!(base->sec->sh_flags & SHF_ALLOC))
            continue;

        if (elf->sec[i].sec->sh_type == SHT_RELA)
            rc = xsplice_perform_rela(elf, base, rela);
        else if (elf->sec[i].sec->sh_type == SHT_REL)
            rc = xsplice_perform_rel(elf, base, rela);

        if ( rc )
            return rc;
    }

    return 0;
}

static int
find_special_sections(struct payload *payload, struct Elf *elf)
{
    struct Elf_Sec *sec;
    int i;

    sec = find_section_by_name(elf, ".xsplice.funcs");
    if (!sec) {
        printk(XENLOG_ERR ".xsplice.funcs is missing\n");
        return -1;
    }

    payload->funcs = (struct xsplice_patch_func *)sec->load_addr;
    payload->nfuncs = sec->sec->sh_size / (sizeof *payload->funcs);

    sec = find_section_by_name(elf, ".xsplice.hooks.load");
    if (sec) {
        payload->load_funcs = (xsplice_loadcall_t *)sec->load_addr;
        payload->n_load_funcs = sec->sec->sh_size / (sizeof *payload->load_funcs);
    }

    sec = find_section_by_name(elf, ".xsplice.hooks.unload");
    if (sec) {
        payload->unload_funcs = (xsplice_unloadcall_t *)sec->load_addr;
        payload->n_unload_funcs = sec->sec->sh_size / (sizeof *payload->unload_funcs);
    }

    sec = find_section_by_name(elf, ".altinstructions");
    if (sec) {
        local_irq_disable();
        apply_alternatives((struct alt_instr *)sec->data,
                           (struct alt_instr *)(sec->data + sec->sec->sh_size));
        local_irq_enable();
    }

    for (i = 0; i < 4; i++) {
        char str[14];

        snprintf(str, sizeof str, ".bug_frames.%d", i);
        sec = find_section_by_name(elf, str);
        if (!sec)
            continue;

        payload->start_bug_frames[i] = (struct bug_frame *)sec->load_addr;
        payload->stop_bug_frames[i] = (struct bug_frame *)(sec->load_addr + sec->sec->sh_size);
    }

    sec = find_section_by_name(elf, ".ex_table");
    if (sec) {
        payload->start_ex_table = (struct exception_table_entry *)sec->load_addr;
        payload->stop_ex_table = (struct exception_table_entry *)(sec->load_addr + sec->sec->sh_size);

        sort_exception_table(payload->start_ex_table, payload->stop_ex_table);
    }

    return 0;
}

static int load_payload(struct payload *payload, uint8_t *raw, ssize_t len)
{
    struct Elf elf;
    int rc = 0;

    rc = xsplice_verify_elf(raw, len);
    if ( rc )
        return rc;

    rc = elf_load(&elf, raw, len);
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

    rc = find_special_sections(payload, &elf);
    if ( rc )
        goto err_module;

    return 0;

err_module:
    free_module(payload);
err_elf:
    elf_free(&elf);

    return rc;
}

/* This function is executed having all other CPUs with no stack and IRQs
 * disabled. */
static int apply_payload(struct payload *data)
{
    int i;

    printk(XENLOG_DEBUG "Applying payload: %s\n", data->id);

    for (i = 0; i < data->nfuncs; i++)
        xsplice_apply_jmp(data->funcs + i);

    spin_debug_disable();
    for (i = 0; i < data->n_load_funcs; i++)
        data->load_funcs[i]();
    spin_debug_enable();

    INIT_LIST_HEAD(&data->bug_list);
    list_add_tail(&data->bug_list, &bug_list);

    return XSPLICE_STATUS_APPLIED;
}

/* This function is executed having all other CPUs with no stack and IRQs
 * disabled. */
static int revert_payload(struct payload *data)
{
    int i;

    printk(XENLOG_DEBUG "Reverting payload: %s\n", data->id);

    for (i = 0; i < data->nfuncs; i++)
        xsplice_revert_jmp(data->funcs + i);

    spin_debug_disable();
    for (i = 0; i < data->n_unload_funcs; i++)
        data->unload_funcs[i]();
    spin_debug_enable();

    list_del(&data->bug_list);

    return XSPLICE_STATUS_REVERTED;
}

static int mask_nmi_callback(const struct cpu_user_regs *regs, int cpu)
{
    return 1;
}

static void reschedule_fn(void *unused)
{
    smp_mb(); /* Synchronize with setting do_work */
    raise_softirq(SCHEDULE_SOFTIRQ);
}

void do_xsplice(void)
{
    int id;
    unsigned int total_cpus;
    nmi_callback_t saved_nmi_callback;

    if (likely(!xsplice_work.do_work))
        return;

    ASSERT(local_irq_is_enabled());

    spin_lock(&xsplice_work_lock);
    id = atomic_read(&xsplice_work.semaphore);
    atomic_inc(&xsplice_work.semaphore);
    spin_unlock(&xsplice_work_lock);

    total_cpus = num_online_cpus();

    if ( id == 0 )
    {
        s_time_t timeout, start;

        /* Trigger other CPUs to execute do_xsplice */
        smp_call_function(reschedule_fn, NULL, 0);

        /* Wait for other CPUs with a timeout */
        start = NOW();
        timeout = start + MILLISECS(5);
        while ( atomic_read(&xsplice_work.semaphore) != total_cpus &&
                NOW() < timeout )
            cpu_relax();

        if (atomic_read(&xsplice_work.semaphore) == total_cpus)
        {
            struct payload *data2;
            bool_t failed = false;

            /* "Mask" NMIs */
            saved_nmi_callback = set_nmi_callback(mask_nmi_callback);

            /* All CPUs are waiting, now signal to disable IRQs */
            xsplice_work.ready = true;
            smp_mb();

            /* Wait for irqs to be disabled */
            while ( atomic_read(&xsplice_work.irq_semaphore) != (total_cpus - 1) )
                cpu_relax();

            local_irq_disable();
            /* Now this function should be the only one on any stack.
             * No need to lock the payload list or bug table list. */
            switch ( xsplice_work.data->cmd ) {
            case XSPLICE_ACTION_APPLY:
                    xsplice_work.data->status = apply_payload(xsplice_work.data);
                    break;
            case XSPLICE_ACTION_REVERT:
                    xsplice_work.data->status = revert_payload(xsplice_work.data);
                    break;
            case XSPLICE_ACTION_REPLACE:
                    list_for_each_entry ( data2, &payload_list, list )
                    {
                        if (data2->status != XSPLICE_STATUS_APPLIED)
                            continue;

                        data2->status = revert_payload(data2);
                        if (data2->status != XSPLICE_STATUS_REVERTED)
                        {
                            xsplice_work.data->status = -EBUSY;
                            failed = true;
                            break;
                        }
                    }
                    if (!failed)
                        xsplice_work.data->status = apply_payload(xsplice_work.data);
                    break;
            default:
                    xsplice_work.data->status = -EINVAL;
            }

            local_irq_enable();
            set_nmi_callback(saved_nmi_callback);
        }
        else
        {
            xsplice_work.data->status = -EAGAIN;
        }

        xsplice_work.do_work = 0;
        smp_mb(); /* Synchronize with waiting CPUs */
    }
    else
    {
        /* Wait for all CPUs to rendezvous */
        while ( xsplice_work.do_work && !xsplice_work.ready )
        {
            cpu_relax();
            smp_mb();
        }

        /* Disable IRQs and signal */
        local_irq_disable();
        atomic_inc(&xsplice_work.irq_semaphore);

        /* Wait for patching to complete */
        while ( xsplice_work.do_work )
        {
            cpu_relax();
            smp_mb();
        }
        local_irq_enable();
    }
}

static void xsplice_tasklet(unsigned long _data)
{
    struct payload *data = (struct payload *)_data;

    debugtrace_printk("%s=%s \n", data->id, action2str(data->cmd));
    spin_lock(&data->cmd_lock);
    switch ( data->cmd ) {
    case XSPLICE_ACTION_CHECK:
            /* TODO: Do the operation here. */
            data->status = XSPLICE_STATUS_CHECKED;
            break;
    default:
            data->status = -EINVAL;
    }
    spin_unlock(&data->cmd_lock);
}

static int xsplice_upload(xen_sysctl_xsplice_upload_t *upload)
{
    struct payload *data = NULL;
    uint8_t *raw_data;
    int rc;

    rc = verify_payload(upload);
    if ( rc )
        return_where( rc);

    rc = find_payload(&upload->id, true, &data);
    if ( rc == 0 /* Found. */ )
        return_where( -EEXIST);

    if ( rc != -ENOENT )
        return_where( rc);

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

    rc = load_payload(data, raw_data, upload->size);
    if ( rc )
        goto err_raw;

    debugtrace_printk("%s=loaded\n", data->id);
    data->status = XSPLICE_STATUS_LOADED;
    INIT_LIST_HEAD(&data->list);
    spin_lock_init(&data->cmd_lock);
    data->cmd = 0;
    tasklet_init(&data->tasklet, xsplice_tasklet, (unsigned long)data);

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

    if ( summary->status.status )
        return_where( -EINVAL);

    if ( summary->status._pad != 0 )
        return_where( -EINVAL);

    rc = verify_id(&summary->id );
    if ( rc )
        return_where( rc);

    rc = find_payload(&summary->id, true, &data);
    if ( rc )
        return_where( rc);

    summary->status.status = data->status;

    return 0;
}

static int xsplice_list(xen_sysctl_xsplice_list_t *list)
{
    xen_xsplice_status_t status;
    struct payload *data;
    unsigned int idx = 0, i = 0;
    int rc = 0;
    unsigned int ver = payload_version;

    // TODO: Increase to a 64 or other value. Leave 4 for debug.
    if ( list->nr > 4 )
        return -E2BIG;

    if ( list->_pad != 0 )
        return_where( -EINVAL);

    if ( guest_handle_is_null(list->status) ||
         guest_handle_is_null(list->id) ||
         guest_handle_is_null(list->len) )
        return_where( -EINVAL);

    if ( !guest_handle_okay(list->status, sizeof(status) * list->nr) ||
         !guest_handle_okay(list->id, XEN_XSPLICE_ID_SIZE * list->nr) ||
         !guest_handle_okay(list->len, sizeof(uint32_t) * list->nr) )
        return_where( -EINVAL);

    spin_lock(&payload_list_lock);
    if ( list->idx > payload_cnt )
    {
        spin_unlock(&payload_list_lock);
        return_where( -EINVAL);
    }

    status._pad = 0; /* No stack leaking. */
    list_for_each_entry( data, &payload_list, list )
    {
        uint32_t len;

        if ( list->idx > i++ )
            continue;

        status.status = data->status;
        len = strlen(data->id);

        /* N.B. 'idx' != 'i'. */
        if ( copy_to_guest_offset(list->id, idx * XEN_XSPLICE_ID_SIZE,
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

static int
schedule_work(struct payload *data)
{
    /* Fail if an operation is already scheduled */
    if (xsplice_work.do_work)
        return -EAGAIN;

    xsplice_work.data = data;
    atomic_set(&xsplice_work.semaphore, 0);
    atomic_set(&xsplice_work.irq_semaphore, 0);
    xsplice_work.ready = false;
    smp_mb();
    xsplice_work.do_work = true;
    smp_mb();

    return 0;
}

static int xsplice_action(xen_sysctl_xsplice_action_t *action)
{
    struct payload *data;
    int rc;

    if ( action->_pad != 0 )
        return_where( -EINVAL);

    rc = verify_id(&action->id);
    if ( rc )
        return rc;

    spin_lock(&payload_list_lock);
    rc = find_payload(&action->id, false /* we are holding the lock. */, &data);
    if ( rc )
        goto out;

    if ( action->cmd != XSPLICE_ACTION_UNLOAD )
        spin_lock(&data->cmd_lock);

    switch ( action->cmd )
    {
    case XSPLICE_ACTION_CHECK:
        if ( ( data->status == XSPLICE_STATUS_LOADED ) )
        {
            data->old_status = data->status;
            data->status = XSPLICE_STATUS_PROGRESS;
            data->cmd = action->cmd;
            tasklet_schedule(&data->tasklet);
            rc = 0;
        } else if ( data->status == XSPLICE_STATUS_CHECKED )
        {
            rc = 0;
        }
        break;
    case XSPLICE_ACTION_UNLOAD:
        if ( ( data->status == XSPLICE_STATUS_REVERTED ) ||
             ( data->status == XSPLICE_STATUS_LOADED ) ||
             ( data->status == XSPLICE_STATUS_CHECKED ) )
        {
            __free_payload(data);
            /* No touching 'data' from here on! */
            rc = 0;
        }
        break;
    case XSPLICE_ACTION_REVERT:
        if ( data->status == XSPLICE_STATUS_APPLIED )
        {
            data->old_status = data->status;
            data->status = XSPLICE_STATUS_PROGRESS;
            data->cmd = action->cmd;
            rc = schedule_work(data);
        }
        break;
    case XSPLICE_ACTION_APPLY:
        if ( ( data->status == XSPLICE_STATUS_CHECKED ) ||
             ( data->status == XSPLICE_STATUS_REVERTED ))
        {
            data->old_status = data->status;
            data->status = XSPLICE_STATUS_PROGRESS;
            data->cmd = action->cmd;
            rc = schedule_work(data);
        }
        break;
    case XSPLICE_ACTION_REPLACE:
        if ( ( data->status == XSPLICE_STATUS_CHECKED ) ||
             ( data->status == XSPLICE_STATUS_REVERTED ))
        {
            data->old_status = data->status;
            data->status = XSPLICE_STATUS_PROGRESS;
            data->cmd = action->cmd;
            rc = schedule_work(data);
        }
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    if ( action->cmd != XSPLICE_ACTION_UNLOAD )
        spin_unlock(&data->cmd_lock);
 out:
    spin_unlock(&payload_list_lock);

    return_where( rc);
}

static int xsplice_info(xen_sysctl_xsplice_info_t *info)
{
    struct xen_xsplice_trace *trace;
    int rc = 0;

    if ( info->cmd != XEN_SYSCTL_XSPLICE_INFO_TRACE_CLEAR ||
         info->cmd != XEN_SYSCTL_XSPLICE_INFO_TRACE_GET )
        return -EINVAL;

    if ( info->_pad == 0 )
        return -EINVAL;

    switch ( info->cmd )
    {
    case XEN_SYSCTL_XSPLICE_INFO_TRACE_CLEAR:
        debugtrace_dump();
        break;

    case XEN_SYSCTL_XSPLICE_INFO_TRACE_GET:
        trace = &info->u.trace;

        if ( trace->size == 0 )
            return -EINVAL;

        if ( !guest_handle_okay(trace->info, trace->size) )
            return -EFAULT;

        rc = debugtrace_dump_guest(trace->idx, trace->size, trace->info);
        break;
    }
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
    case XEN_SYSCTL_XSPLICE_INFO:
        rc = xsplice_info(&xsplice->u.info);
        break;
    default:
        rc = -ENOSYS;
        break;
   }

    return rc;
}

struct bug_frame *
xsplice_handle_bug(const char *eip, int *id)
{
    struct payload *data;
    struct bug_frame *bug;
    int i;

    /* No locking since this list is only ever changed during apply or revert
     * context. */
    list_for_each_entry ( data, &bug_list, bug_list )
    {
        for (i = 0; i < 4; i++) {
            if (!data->start_bug_frames[i])
                continue;

            for ( bug = data->start_bug_frames[i]; bug != data->stop_bug_frames[i]; ++bug ) {
                if ( bug_loc(bug) == eip )
                {
                    *id = i;
                    return bug;
                }
            }
        }
    }

    return NULL;
}

unsigned long
xsplice_search_exception_tables(unsigned long addr)
{
    struct payload *data;
    unsigned long ret;

    /* No locking since this list is only ever changed during apply or revert
     * context. */
    list_for_each_entry ( data, &bug_list, bug_list )
    {
        if (!data->start_ex_table)
            continue;

        ret = search_one_table(data->start_ex_table, data->stop_ex_table-1,
                               addr);
        if (ret)
            return ret;
    }

    return 0;
}

/* TODO This check could be more accurate */
bool_t is_module(const void *ptr)
{
    unsigned long addr = (unsigned long)ptr;

    return addr >= module_virt_start && addr < module_virt_end;
}

/* TODO This check could be more accurate */
bool_t is_active_module_text(unsigned long addr)
{
    return addr >= module_virt_start && addr < module_virt_end;
}

void *xsplice_shadow_alloc(const void *obj, const char *var, size_t size)
{
    struct shadow_var *shadow;
    unsigned int slot;

    shadow = xmalloc(struct shadow_var);
    if (!shadow)
        return NULL;

    shadow->obj = obj;
    strlcpy(shadow->var, var, sizeof shadow->var);
    shadow->data = xmalloc_bytes(size);
    if (!shadow->data)
    {
        xfree(shadow);
        return NULL;
    }

    slot = (unsigned long)obj % SHADOW_SLOTS;
    spin_lock(&shadow_lock);
    hlist_add_head(&shadow->list, &shadow_tbl[slot]);
    spin_unlock(&shadow_lock);

    return shadow->data;
}

void xsplice_shadow_free(const void *obj, const char *var)
{
    struct shadow_var *entry, *shadow = NULL;
    unsigned int slot;
    struct hlist_node *next;

    slot = (unsigned long)obj % SHADOW_SLOTS;

    spin_lock(&shadow_lock);
    hlist_for_each_entry(entry, next, &shadow_tbl[slot], list)
    {
        if ( entry->obj == obj &&
             !strcmp(entry->var, var) )
        {
            shadow = entry;
            break;
        }
    }
    if (shadow) {
        hlist_del(&shadow->list);
        xfree(shadow->data);
        xfree(shadow);
    }
    spin_unlock(&shadow_lock);
}

void *xsplice_shadow_get(const void *obj, const char *var)
{
    struct shadow_var *entry;
    unsigned int slot;
    struct hlist_node *next;
    void *ret = NULL;

    slot = (unsigned long)obj % SHADOW_SLOTS;

    spin_lock(&shadow_lock);
    hlist_for_each_entry(entry, next, &shadow_tbl[slot], list)
    {
        if ( entry->obj == obj &&
             !strcmp(entry->var, var) )
        {
            ret = entry->data;
            break;
        }
    }

    spin_unlock(&shadow_lock);
    return ret;
}

static int __init xsplice_init(void)
{
    int i;

    for ( i = 0; i < SHADOW_SLOTS; i++ )
        INIT_HLIST_HEAD(&shadow_tbl[i]);

    register_keyhandler('x', xsplice_printall, "print xsplicing info", 1);

    return 0;
}
__initcall(xsplice_init);
