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
    unsigned char undo[8];
};

struct xen_sysctl_xsplice_op;
int xsplice_control(struct xen_sysctl_xsplice_op *);

extern void xsplice_printall(unsigned char key);

/* Arch hooks */
int xsplice_verify_elf(uint8_t *data, ssize_t len);
int xsplice_perform_rel(struct xsplice_elf *elf,
                        struct xsplice_elf_sec *base,
                        struct xsplice_elf_sec *rela);
int xsplice_perform_rela(struct xsplice_elf *elf,
                         struct xsplice_elf_sec *base,
                         struct xsplice_elf_sec *rela);

#endif /* __XEN_XSPLICE_H__ */
