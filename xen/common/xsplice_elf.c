#include <xen/lib.h>
#include <xen/xsplice.h>

struct Elf_Sec *
find_section_by_name(struct Elf *elf, const char *name)
{
    int i;

    for (i = 0; i < elf->hdr->e_shnum; i++) {
        if (!strcmp(name, elf->sec[i].name))
            return &elf->sec[i];
    }

    return NULL;
}

static int
elf_get_sections(struct Elf *elf, uint8_t *data)
{
    struct Elf_Sec *sec;
    int i;

    sec = xmalloc_array(struct Elf_Sec, elf->hdr->e_shnum);
    if (!sec) {
        printk(XENLOG_ERR "Could not find section table\n");
        return -ENOMEM;
    }

    for (i = 0; i < elf->hdr->e_shnum; i++) {
        sec[i].sec = (Elf64_Shdr *)(data + elf->hdr->e_shoff + i * elf->hdr->e_shentsize);
        sec[i].data = data + sec[i].sec->sh_offset;
    }
    elf->sec = sec;

    return 0;
}

static int
elf_get_sym(struct Elf *elf, uint8_t *data)
{
    struct Elf_Sec *symtab, *strtab_sec;
    struct Elf_Sym *sym;
    const char *strtab;
    int i;

    symtab = find_section_by_name(elf, ".symtab");
    if (!symtab) {
        printk(XENLOG_ERR "Could not find symbol table\n");
        return -EINVAL;
    }

    strtab_sec = find_section_by_name(elf, ".strtab");
    if (!strtab_sec) {
        printk(XENLOG_ERR "Could not find string table\n");
        return -EINVAL;
    }
    strtab = (const char *)(data + strtab_sec->sec->sh_offset);

    elf->nsym = symtab->sec->sh_size / symtab->sec->sh_entsize;

    sym = xmalloc_array(struct Elf_Sym, elf->nsym);
    if (!sym) {
        printk(XENLOG_ERR "Could not allocate memory for symbols\n");
        return -ENOMEM;
    }

    for (i = 0; i < elf->nsym; i++) {
        sym[i].sym = (Elf64_Sym *)(symtab->data + i * symtab->sec->sh_entsize);
        sym[i].name = strtab + sym[i].sym->st_name;
    }
    elf->sym = sym;

    return 0;
}

int
elf_load(struct Elf *elf, uint8_t *data, ssize_t len)
{
    const char *shstrtab;
    int i, rc;

    elf->hdr = (Elf64_Ehdr *)data;

    rc = elf_get_sections(elf, data);
    if ( rc )
        return rc;

    shstrtab = (const char *)(data + elf->sec[elf->hdr->e_shstrndx].sec->sh_offset);
    for (i = 0; i < elf->hdr->e_shnum; i++)
        elf->sec[i].name = shstrtab + elf->sec[i].sec->sh_name;

    rc = elf_get_sym(elf, data);
    if ( rc )
        return rc;

    return 0;
}

void
elf_free(struct Elf *elf)
{
    xfree(elf->sec);
    xfree(elf->sym);
}
