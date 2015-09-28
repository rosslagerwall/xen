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
#include <xen/xsplice.h>
#include <public/sysctl.h>

#include <asm/event.h>

#define return_where(x) { printk("%s:%d err=%d\n", __func__,__LINE__, x); return x; }
static DEFINE_SPINLOCK(payload_list_lock);
static LIST_HEAD(payload_list);

static unsigned int payload_cnt;
static unsigned int payload_version = 1;

struct payload {
    char  *id;          /* Name of it. Past this structure. */
    ssize_t id_len;     /* Length of the name. */

    uint8_t *raw;       /* Pointer to Elf file. Past 'id'*/
    ssize_t raw_len;    /* Size of 'raw'. */

    int32_t status;     /* XSPLICE_STATUS_* or Exx type value. */
    int32_t old_status; /* XSPLICE_STATUS_* or Exx type value. */

    struct spinlock cmd_lock; /* Lock against the action. */
    uint32_t cmd;       /* Action request. XSPLICE_ACTION_* */

    /* Boring things below: */
    struct list_head   list;   /* Linked to 'payload_list'. */
    ssize_t len;        /* This structure + raw_len + id_len + 1. */

    struct tasklet tasklet;
};

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

void xsplice_printall(unsigned char key)
{
    struct payload *data;

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
    char name[XEN_XSPLICE_ID_SIZE]; /* 128 bytes on stack. Perhaps kzalloc? */
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
        if ( !strncmp(data->id, name, data->id_len) )
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
    free_xenheap_pages(data, get_order_from_bytes(data->len));
}

static void xsplice_tasklet(unsigned long _data)
{
    struct payload *data = (struct payload *)_data;

    spin_lock(&data->cmd_lock);
    switch ( data->cmd ) {
    case XSPLICE_ACTION_CHECK:
            /* TODO: Do the operation here. */
            data->status = XSPLICE_STATUS_CHECKED;
            break;
    case XSPLICE_ACTION_APPLY:
            /* TODO: Well, do the work :-) */
            data->status = XSPLICE_STATUS_APPLIED;
            break;
    case XSPLICE_ACTION_REVERT:
            /* TODO: Well, do the work :-) */
            data->status = XSPLICE_STATUS_REVERTED;
            break;
    default:
            data->status = -EINVAL;
    }
    spin_unlock(&data->cmd_lock);
}

static int xsplice_upload(xen_sysctl_xsplice_upload_t *upload)
{
    struct payload *data = NULL;
    int rc;
    ssize_t len;

    rc = verify_payload(upload);
    if ( rc )
        return_where( rc);

    rc = find_payload(&upload->id, true, &data);
    if ( rc == 0 /* Found. */ )
        return_where( -EEXIST);

    if ( rc != -ENOENT )
        return_where( rc);

    /*
     * Compute the size of the structures which need to be verified.
     * The 1 is for the extra \0 in case name does not have it.
     */
    len = sizeof(*data) + upload->id.size + 1 + upload->size;
    data = alloc_xenheap_pages(get_order_from_bytes(len), 0);
    if ( !data )
        return -ENOMEM;

    memset(data, 0, len);
    data->len = len;

    /* At the end of structure we put the name. */
    data->id = (char *)data + sizeof(*data);
    data->id_len = upload->id.size;
    /* And after the name + \0 we stick the raw ELF data. */
    data->raw = (uint8_t *)data + sizeof(*data) + data->id_len + 1;
    data->raw_len = upload->size;

    rc = -EFAULT;
    if ( copy_from_guest(data->raw, upload->payload, upload->size) )
        goto err_out;

    if ( copy_from_guest(data->id, upload->id.name, upload->id.size) )
        goto err_out;

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

    return 0;

 err_out:
    free_xenheap_pages(data, get_order_from_bytes(len));
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
        len = data->id_len;

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
            rc = 0;
            /* TODO: Tasklet is not good for this. We need a different vehicle. */
            tasklet_schedule(&data->tasklet);
        }
        break;
    case XSPLICE_ACTION_APPLY:
        if ( ( data->status == XSPLICE_STATUS_CHECKED ) ||
             ( data->status == XSPLICE_STATUS_REVERTED ))
        {
            data->old_status = data->status;
            data->status = XSPLICE_STATUS_PROGRESS;
            data->cmd = action->cmd;
            rc = 0;
            /* TODO: Tasklet is not good for this. We need a different vehicle. */
            tasklet_schedule(&data->tasklet);
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
