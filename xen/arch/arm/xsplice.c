#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/xsplice_elf.h>
#include <xen/xsplice.h>

int xsplice_verify_elf(uint8_t *data, ssize_t len)
{
    return -ENOSYS;
}

int xsplice_perform_rel(struct xsplice_elf *elf,
                        struct xsplice_elf_sec *base,
                        struct xsplice_elf_sec *rela)
{
    return -ENOSYS;
}

int xsplice_perform_rela(struct xsplice_elf *elf,
                         struct xsplice_elf_sec *base,
                         struct xsplice_elf_sec *rela)
{
    return -ENOSYS;
}
