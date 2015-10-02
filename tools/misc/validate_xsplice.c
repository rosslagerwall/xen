/*
 *
 */
#include <xenctrl.h>
#include <xenstore.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <stdarg.h>
#include <inttypes.h>
#include <xen/libelf/libelf.h>
#include "xsplice.h"

/* ------------------------------------------------------------------------ */
#define XC_MAX_ERROR_MSG_LEN 1024
void log_callback(struct elf_binary *elf, void *caller_data,
                         bool iserr, const char *fmt, va_list al)
{
    char msgbuf[XC_MAX_ERROR_MSG_LEN];
    char *msg;
    char fmt_nonewline[512];
    int fmt_l;

    fmt_l = strlen(fmt);
    if (fmt_l && fmt[fmt_l-1]=='\n' && fmt_l < sizeof(fmt_nonewline)) {
        memcpy(fmt_nonewline, fmt, fmt_l-1);
        fmt_nonewline[fmt_l-1] = 0;
        fmt = fmt_nonewline;
    }
    msg = msgbuf;
    vsnprintf(msg, XC_MAX_ERROR_MSG_LEN-1, fmt, al);
    msg[XC_MAX_ERROR_MSG_LEN-1] = '\0';
    fprintf(stderr, "[%s]\n", msg);
}

int main(int argc, char *argv[])
{
    int rc;
    struct elf_binary elf;
    char *filename;
    struct stat buf;
    ssize_t len;
    int fd = 0;
    char *fbuf;
    struct xsplice *x;

    filename = "./xen_extra_version.xsplice";
    fd = open(filename, O_RDONLY);
    if ( fd < 0 )
    {
        fprintf(stderr, "Could not open %s, error: %d(%s)\n",
                filename, errno, strerror(errno));
        return errno;
    }
    if ( stat(filename, &buf) != 0 )
    {
        fprintf(stderr, "Could not get right size %s, error: %d(%s)\n",
                filename, errno, strerror(errno));
        close(fd);
        return errno;
    }

    len = buf.st_size;
    fbuf = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if ( fbuf == MAP_FAILED )
    {
        fprintf(stderr,"Could not map: %s, error: %d(%s)\n",
                filename, errno, strerror(errno));
        close (fd);
        return errno;
    }

    fprintf(stdout, "%s sz = %zu mmap=%p elf=%p\n", filename, len, fbuf, &elf);

    memset(&elf, 0, sizeof(struct elf_binary));

    elf_set_log(&elf, log_callback, NULL, 1);

    rc = elf_init(&elf, fbuf, len);
    if ( rc ) {
        fprintf(stderr, "Could not init ELF file!\n");
        close(fd);
        return errno;
    }

    elf_parse_binary(&elf);
    if ( elf_check_broken(&elf) )
       fprintf(stderr, "%s\n", elf.broken);

    x = NULL;
    x = (struct xsplice *)elf_lookup_addr(&elf, "xsplice");
    /*  30: 0000000000000000    80 OBJECT  GLOBAL DEFAULT   12 xsplice */
    fprintf(stdout, "struct xsplice = 0x%lx\n", (unsigned long)x);
    if ( x ) {
        fprintf(stdout, "          .name = 0x%lx\n", (unsigned long)(x->name));
    }
    {
        if ( ELF_HANDLE_VALID(elf.sym_tab) )
        {
            fprintf(stdout, "e_ehsize: %zu shdr_count: %zu shentsize:%zu\n",
                    (unsigned long)elf_uval(&elf, elf.ehdr, e_ehsize),
                    (unsigned long)elf_shdr_count(&elf), (unsigned long)elf_uval(&elf, elf.ehdr, e_shentsize));
        }
    }
    rc = munmap(fbuf, len);
    if ( rc ) {
        fprintf(stderr, "Could not munmap file!\n");
    }
    close(fd);
    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
