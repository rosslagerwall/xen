#ifndef __XEN_XSPLICE_PATCH_H__
#define __XEN_XSPLICE_PATCH_H__

/*
 * The following definitions are to be used in patches. They are taken
 * from kpatch.
 */

/*
 * xsplice shadow variables
 *
 * These functions can be used to add new "shadow" fields to existing data
 * structures.  For example, to allocate a "newpid" variable associated with an
 * instance of task_struct, and assign it a value of 1000:
 *
 * struct task_struct *tsk = current;
 * int *newpid;
 * newpid = xsplice_shadow_alloc(tsk, "newpid", sizeof(int));
 * if (newpid)
 * 	*newpid = 1000;
 *
 * To retrieve a pointer to the variable:
 *
 * struct task_struct *tsk = current;
 * int *newpid;
 * newpid = xsplice_shadow_get(tsk, "newpid");
 * if (newpid)
 * 	printk("task newpid = %d\n", *newpid); // prints "task newpid = 1000"
 *
 * To free it:
 *
 * xsplice_shadow_free(tsk, "newpid");
 */

void *xsplice_shadow_alloc(const void *obj, const char *var, size_t size);
void xsplice_shadow_free(const void *obj, const char *var);
void *xsplice_shadow_get(const void *obj, const char *var);

#endif /* __XEN_XSPLICE_PATCH_H__ */
