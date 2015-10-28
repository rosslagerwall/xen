#ifndef __XEN_XSPLICE_H__
#define __XEN_XSPLICE_H__

struct xsplice_elf;
struct xsplice_elf_sec;
struct xsplice_elf_sym;

struct xsplice_patch_func {
    unsigned long new_addr;
    unsigned long new_size;
    unsigned long old_addr;
    unsigned long old_size;
    char *name;
    uint8_t undo[8];
    uint8_t pad[56];
};

struct xen_sysctl_xsplice_op;
int xsplice_control(struct xen_sysctl_xsplice_op *);

extern void xsplice_printall(unsigned char key);

void do_xsplice(void);

struct bug_frame * xsplice_find_bug(const char *eip, int *id);
bool_t is_module(const void *addr);
bool_t is_active_module_text(unsigned long addr);

unsigned long search_module_extables(unsigned long addr);

/* Arch hooks */
int xsplice_verify_elf(uint8_t *data, ssize_t len);
int xsplice_perform_rel(struct xsplice_elf *elf,
                        struct xsplice_elf_sec *base,
                        struct xsplice_elf_sec *rela);
int xsplice_perform_rela(struct xsplice_elf *elf,
                         struct xsplice_elf_sec *base,
                         struct xsplice_elf_sec *rela);
void xsplice_apply_jmp(struct xsplice_patch_func *func);
void xsplice_revert_jmp(struct xsplice_patch_func *func);

#endif /* __XEN_XSPLICE_H__ */
