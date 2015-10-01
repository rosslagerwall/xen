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

    char  id[XEN_XSPLICE_NAME_SIZE + 1];          /* Name of it. */
};

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

static int __init xsplice_init(void)
{
    register_keyhandler('x', xsplice_printall, "print xsplicing info", 1);
    return 0;
}
__initcall(xsplice_init);
