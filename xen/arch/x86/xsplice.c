#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/xsplice_elf.h>
#include <xen/xsplice.h>

#define PATCH_INSN_SIZE 5

void xsplice_apply_jmp(struct xsplice_patch_func *func)
{
    uint32_t val;
    uint8_t *old_ptr;

    old_ptr = (uint8_t *)func->old_addr;
    memcpy(func->undo, old_ptr, PATCH_INSN_SIZE);
    *old_ptr++ = 0xe9; /* Relative jump */
    val = func->new_addr - func->old_addr - PATCH_INSN_SIZE;
    memcpy(old_ptr, &val, sizeof val);
}

void xsplice_revert_jmp(struct xsplice_patch_func *func)
{
    memcpy((void *)func->old_addr, func->undo, PATCH_INSN_SIZE);
}

int xsplice_verify_elf(uint8_t *data, ssize_t len)
{

    Elf64_Ehdr *hdr = (Elf64_Ehdr *)data;

    if ( len < (sizeof *hdr) ||
         !IS_ELF(*hdr) ||
         hdr->e_ident[EI_CLASS] != ELFCLASS64 ||
         hdr->e_ident[EI_DATA] != ELFDATA2LSB ||
         hdr->e_machine != EM_X86_64 )
    {
        printk(XENLOG_ERR "Invalid ELF file\n");
        return -EINVAL;
    }

    return 0;
}

int xsplice_perform_rel(struct xsplice_elf *elf,
                        struct xsplice_elf_sec *base,
                        struct xsplice_elf_sec *rela)
{
    printk(XENLOG_ERR "SHT_REL relocation unsupported\n");
    return -ENOSYS;
}

int xsplice_perform_rela(struct xsplice_elf *elf,
                         struct xsplice_elf_sec *base,
                         struct xsplice_elf_sec *rela)
{
    Elf64_Rela *r;
    int symndx, i;
    uint64_t val;
    uint8_t *dest;

    for ( i = 0; i < (rela->sec->sh_size / rela->sec->sh_entsize); i++ )
    {
        r = (Elf64_Rela *)(rela->data + i * rela->sec->sh_entsize);
        symndx = ELF64_R_SYM(r->r_info);
        dest = base->load_addr + r->r_offset;
        val = r->r_addend + elf->sym[symndx].sym->st_value;

        switch ( ELF64_R_TYPE(r->r_info) )
        {
            case R_X86_64_NONE:
                break;
            case R_X86_64_64:
                *(uint64_t *)dest = val;
                break;
            case R_X86_64_32:
                *(uint32_t *)dest = val;
                if (val != *(uint32_t *)dest)
                    goto overflow;
                break;
            case R_X86_64_32S:
                *(int32_t *)dest = val;
                if ((int64_t)val != *(int32_t *)dest)
                    goto overflow;
                break;
            case R_X86_64_PLT32:
                /*
                 * Xen uses -fpic which normally uses PLT relocations
                 * except that it sets visibility to hidden which means
                 * that they are not used.  However, when gcc cannot
                 * inline memcpy it emits memcpy with default visibility
                 * which then creates a PLT relocation.  It can just be
                 * treated the same as R_X86_64_PC32.
                 */
                /* Fall through */
            case R_X86_64_PC32:
                *(uint32_t *)dest = val - (uint64_t)dest;
                break;
            default:
                printk(XENLOG_ERR "Unhandled relocation %lu\n",
                       ELF64_R_TYPE(r->r_info));
                return -EINVAL;
        }
    }

    return 0;

 overflow:
    printk(XENLOG_ERR "Overflow in relocation %d in %s\n", i, rela->name);
    return -EOVERFLOW;
}
