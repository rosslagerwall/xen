#include <xen/lib.h>
#include <xen/kernel.h>
#include <xen/init.h>
#include <xen/list.h>
#include <xen/spinlock.h>
#include <xen/xsplice_patch.h>

#define SHADOW_SLOTS 256
struct hlist_head shadow_tbl[SHADOW_SLOTS];
static DEFINE_SPINLOCK(shadow_lock);

struct shadow_var {
    struct hlist_node list;         /* Linked to 'shadow_tbl' */
    void *data;
    const void *obj;
    char var[16];
};

void *xsplice_shadow_alloc(const void *obj, const char *var, size_t size)
{
    struct shadow_var *shadow;
    unsigned int slot;

    shadow = xmalloc(struct shadow_var);
    if ( !shadow )
        return NULL;

    shadow->obj = obj;
    strlcpy(shadow->var, var, sizeof shadow->var);
    shadow->data = xmalloc_bytes(size);
    if ( !shadow->data )
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
    if (shadow)
    {
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

static int __init xsplice_shadow_init(void)
{
    int i;

    for ( i = 0; i < SHADOW_SLOTS; i++ )
        INIT_HLIST_HEAD(&shadow_tbl[i]);

    return 0;
}
__initcall(xsplice_shadow_init);
