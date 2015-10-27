#ifndef __XEN_XSPLICE_ELF_H__
#define __XEN_XSPLICE_ELF_H__

#include <xen/types.h>
#include <xen/elfstructs.h>

/* The following describes an Elf file as consumed by xsplice. */
struct xsplice_elf_sec {
#ifdef CONFIG_ARM_32
    Elf32_Shdr *sec;
#else
    Elf64_Shdr *sec;
#endif
    const char *name;
    const uint8_t *data;           /* A pointer to the data section */
    uint8_t *load_addr;            /* A pointer to the allocated destination */
};

struct xsplice_elf_sym {
#ifdef CONFIG_ARM_32
    Elf32_Sym *sym;
#else
    Elf64_Sym *sym;
#endif
    const char *name;
};

struct xsplice_elf {
#ifdef CONFIG_ARM_32
    Elf32_Ehdr *hdr;
#else
    Elf64_Ehdr *hdr;
#endif
    struct xsplice_elf_sec *sec;   /* Array of sections */
    struct xsplice_elf_sym *sym;   /* Array of symbols */
    int nsym;
};

struct xsplice_elf_sec *xsplice_elf_sec_by_name(const struct xsplice_elf *elf,
                                                const char *name);
int xsplice_elf_load(struct xsplice_elf *elf, uint8_t *data, ssize_t len);
void xsplice_elf_free(struct xsplice_elf *elf);

#endif /* __XEN_XSPLICE_ELF_H__ */
