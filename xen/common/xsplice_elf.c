#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/xsplice_elf.h>

struct xsplice_elf_sec *xsplice_elf_sec_by_name(const struct xsplice_elf *elf,
                                                const char *name)
{
    int i;

    for ( i = 0; i < elf->hdr->e_shnum; i++ )
    {
        if ( !strcmp(name, elf->sec[i].name) )
            return &elf->sec[i];
    }

    return NULL;
}

static int elf_get_sections(struct xsplice_elf *elf, uint8_t *data)
{
    struct xsplice_elf_sec *sec;
    int i;

    sec = xmalloc_array(struct xsplice_elf_sec, elf->hdr->e_shnum);
    if ( !sec )
    {
        printk(XENLOG_ERR "Could not find section table\n");
        return -ENOMEM;
    }

    for ( i = 0; i < elf->hdr->e_shnum; i++ )
    {
#ifdef CONFIG_ARM_32
        sec[i].sec = (Elf32_Shdr *)(data + elf->hdr->e_shoff +
                                    i * elf->hdr->e_shentsize);
#else
        sec[i].sec = (Elf64_Shdr *)(data + elf->hdr->e_shoff +
                                    i * elf->hdr->e_shentsize);
#endif
        sec[i].data = data + sec[i].sec->sh_offset;
    }
    elf->sec = sec;

    return 0;
}

static int elf_get_sym(struct xsplice_elf *elf, uint8_t *data)
{
    struct xsplice_elf_sec *symtab, *strtab_sec;
    struct xsplice_elf_sym *sym;
    const char *strtab;
    int i;

    symtab = xsplice_elf_sec_by_name(elf, ".symtab");
    if ( !symtab )
    {
        printk(XENLOG_ERR "Could not find symbol table\n");
        return -EINVAL;
    }

    strtab_sec = xsplice_elf_sec_by_name(elf, ".strtab");
    if ( !strtab_sec )
    {
        printk(XENLOG_ERR "Could not find string table\n");
        return -EINVAL;
    }
    strtab = (const char *)(data + strtab_sec->sec->sh_offset);

    elf->nsym = symtab->sec->sh_size / symtab->sec->sh_entsize;

    sym = xmalloc_array(struct xsplice_elf_sym, elf->nsym);
    if ( !sym )
    {
        printk(XENLOG_ERR "Could not allocate memory for symbols\n");
        return -ENOMEM;
    }

    for ( i = 0; i < elf->nsym; i++ )
    {
#ifdef CONFIG_ARM_32
        sym[i].sym = (Elf32_Sym *)(symtab->data + i * symtab->sec->sh_entsize);
#else
        sym[i].sym = (Elf64_Sym *)(symtab->data + i * symtab->sec->sh_entsize);
#endif
        sym[i].name = strtab + sym[i].sym->st_name;
    }
    elf->sym = sym;

    return 0;
}

int xsplice_elf_load(struct xsplice_elf *elf, uint8_t *data, ssize_t len)
{
    const char *shstrtab;
    int i, rc;

#ifdef CONFIG_ARM_32
    elf->hdr = (Elf32_Ehdr *)data;
#else
    elf->hdr = (Elf64_Ehdr *)data;
#endif

    rc = elf_get_sections(elf, data);
    if ( rc )
        return rc;

    shstrtab = (const char *)(data + elf->sec[elf->hdr->e_shstrndx].sec->sh_offset);
    for ( i = 0; i < elf->hdr->e_shnum; i++ )
        elf->sec[i].name = shstrtab + elf->sec[i].sec->sh_name;

    rc = elf_get_sym(elf, data);
    if ( rc )
        return rc;

    return 0;
}

void xsplice_elf_free(struct xsplice_elf *elf)
{
    xfree(elf->sec);
    xfree(elf->sym);
}
