#include <xen/compile.h>
#include <xen/version.h>
#include <xen/types.h>
#include <xen/string.h>
#include <xen/elf.h>
#include <xen/errno.h>

const char *xen_compile_date(void)
{
    return XEN_COMPILE_DATE;
}

const char *xen_compile_time(void)
{
    return XEN_COMPILE_TIME;
}

const char *xen_compile_by(void)
{
    return XEN_COMPILE_BY;
}

const char *xen_compile_domain(void)
{
    return XEN_COMPILE_DOMAIN;
}

const char *xen_compile_host(void)
{
    return XEN_COMPILE_HOST;
}

const char *xen_compiler(void)
{
    return XEN_COMPILER;
}

unsigned int xen_major_version(void)
{
    return XEN_VERSION;
}

unsigned int xen_minor_version(void)
{
    return XEN_SUBVERSION;
}

const char *xen_extra_version(void)
{
    return XEN_EXTRAVERSION;
}

const char *xen_changeset(void)
{
    return XEN_CHANGESET;
}

const char *xen_banner(void)
{
    return XEN_BANNER;
}

#ifdef CONFIG_ARM
int xen_build_id(char **p, unsigned int *len)
{
    return -ENODATA;
}
#else
#define NT_GNU_BUILD_ID 3

extern const Elf_Note __note_gnu_build_id_start;  /* Defined in linker script. */
extern const char __note_gnu_build_id_end[];
int xen_build_id(char **p, unsigned int *len)
{
    const Elf_Note *n = &__note_gnu_build_id_start;

    /* Something is wrong. */
    if ( __note_gnu_build_id_end <= (char *)&__note_gnu_build_id_start )
        return -ENODATA;

    /* Check if we really have a build-id. */
    if ( NT_GNU_BUILD_ID != n->type )
        return -ENODATA;

    /* Sanity check, name should be "GNU" for ld-generated build-id. */
    if ( strncmp(ELFNOTE_NAME(n), "GNU", n->namesz) != 0 )
        return -ENODATA;

    *len = n->descsz;
    *p = ELFNOTE_DESC(n);

    return 0;
}
#endif
