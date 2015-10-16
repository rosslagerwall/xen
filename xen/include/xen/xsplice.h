#ifndef __XEN_XSPLICE_H__
#define __XEN_XSPLICE_H__

#include <xen/types.h>
#include <xen/elfstructs.h>

/* The following describes an Elf file */
struct Elf_Sec {
    Elf64_Shdr *sec;
    const char *name;
    const uint8_t *data;              /* A pointer to the data section */
    uint8_t *load_addr;   /* A pointer to the allocated destination */
};

struct Elf_Sym {
    Elf64_Sym *sym;
    const char *name;
};

struct Elf
{
    Elf64_Ehdr *hdr;
    struct Elf_Sec *sec; /* sections */
    struct Elf_Sym *sym; /* symbols */
    int nsym;
};

struct xsplice_patch_func {
	unsigned long new_addr;
	unsigned long new_size;
	unsigned long old_addr;
	unsigned long old_size;
	char *name;
        unsigned char undo[8];
};

struct Elf_Sec * find_section_by_name(struct Elf *elf, const char *name);
int elf_load(struct Elf *elf, uint8_t *data, ssize_t len);
void elf_free(struct Elf *elf);

struct xen_sysctl_xsplice_op;
int xsplice_control(struct xen_sysctl_xsplice_op *);

extern void xsplice_printall(unsigned char key);

struct bug_frame * xsplice_handle_bug(const char *eip, int *id);
unsigned long xsplice_search_exception_tables(unsigned long addr);

bool_t is_module(const void *addr);
bool_t is_active_module_text(unsigned long addr);

void xsplice_revert_jmp(struct xsplice_patch_func *func);
void xsplice_apply_jmp(struct xsplice_patch_func *func);
int xsplice_verify_elf(uint8_t *data, ssize_t len);
int xsplice_perform_rel(struct Elf *elf, struct Elf_Sec *base, struct Elf_Sec *rela);
int xsplice_perform_rela(struct Elf *elf, struct Elf_Sec *base, struct Elf_Sec *rela);

void do_xsplice(void);

/*
 * The following definitions are to be used in patches. They are taken
 * from kpatch.
 */
typedef void (*xsplice_loadcall_t)(void);
typedef void (*xsplice_unloadcall_t)(void);

/* This definition is taken from Linux. */
#define __UNIQUE_ID(prefix) __PASTE(__PASTE(__UNIQUE_ID_, prefix), __COUNTER__)
/*
 * XSPLICE_IGNORE_SECTION macro
 *
 * This macro is for ignoring sections that may change as a side effect of
 * another change or might be a non-bundlable section; that is one that does
 * not honor -ffunction-section and create a one-to-one relation from function
 * symbol to section.
 */
#define XSPLICE_IGNORE_SECTION(_sec) \
	char *__UNIQUE_ID(xsplice_ignore_section_) __section(".xsplice.ignore.sections") = _sec;

/*
 * XSPLICE_IGNORE_FUNCTION macro
 *
 * This macro is for ignoring functions that may change as a side effect of a
 * change in another function.
 */
#define XSPLICE_IGNORE_FUNCTION(_fn) \
	void *__xsplice_ignore_func_##_fn __section(".xsplice.ignore.functions") = _fn;

/*
 * XSPLICE_LOAD_HOOK macro
 *
 * Declares a function pointer to be allocated in a new
 * .xsplice.hook.load section.  This xsplice_load_data symbol is later
 * stripped by create-diff-object so that it can be declared in multiple
 * objects that are later linked together, avoiding global symbol
 * collision.  Since multiple hooks can be registered, the
 * .xsplice.hook.load section is a table of functions that will be
 * executed in series by the xsplice infrastructure at patch load time.
 */
#define XSPLICE_LOAD_HOOK(_fn) \
	xsplice_loadcall_t __attribute__((weak)) xsplice_load_data __section(".xsplice.hooks.load") = _fn;

/*
 * XSPLICE_UNLOAD_HOOK macro
 *
 * Same as LOAD hook with s/load/unload/
 */
#define XSPLICE_UNLOAD_HOOK(_fn) \
	xsplice_unloadcall_t __attribute__((weak)) xsplice_unload_data __section(".xsplice.hooks.unload") = _fn;

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

#endif /* __XEN_XSPLICE_H__ */
