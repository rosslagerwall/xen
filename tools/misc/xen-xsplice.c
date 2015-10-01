#include <xenctrl.h>
#include <xenstore.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
static xc_interface *xch;

void show_help(void)
{
    fprintf(stderr,
            "xen-xsplice: Xsplice test tool\n"
            "Usage: xen-xsplice <command> [args]\n"
            " <id> An unique name of payload. Up to %d characters.\n"
            "Commands:\n"
            "  help                 display this help\n"
            "  build-id             display build-id of hypervisor.\n"
            "  upload <id> <file>   upload file <cpuid> with <id> name\n"
            "  list                 list payloads uploaded.\n"
            "  apply <id>           apply <id> patch.\n"
            "  revert <id>          revert id <id> patch.\n"
            "  unload <id>          unload id <id> patch.\n"
            "  check <id>           check id <id> patch.\n"
            "  trace [clear]        get the trace from hypervisor.\n",
            XEN_XSPLICE_ID_SIZE);
}

/* wrapper function */
static int help_func(int argc, char *argv[])
{
    show_help();
    return 0;
}

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

static const char *status2str(long status)
{
#define STATUS(x) [XSPLICE_STATUS_##x] = #x
    static const char *const names[] = {
            STATUS(LOADED),
            STATUS(PROGRESS),
            STATUS(CHECKED),
            STATUS(APPLIED),
            STATUS(REVERTED),
    };
#undef STATUS
    if (status >= ARRAY_SIZE(names))
        return "unknown";

    if (status < 0)
        return "-EXX";

    if (!names[status])
        return "unknown";

    return names[status];
}

#define MAX_LEN 11
static int list_func(int argc, char *argv[])
{
    unsigned int idx, done, left, i;
    xen_xsplice_status_t *info = NULL;
    char *id = NULL;
    uint32_t *len = NULL;
    int rc = ENOMEM;

    if ( argc )
    {
        show_help();
        return -1;
    }
    idx = left = 0;
    info = malloc(sizeof(*info) * MAX_LEN);
    if ( !info )
        goto out;
    id = malloc(sizeof(*id) * XEN_XSPLICE_ID_SIZE * MAX_LEN);
    if ( !id )
        goto out;
    len = malloc(sizeof(*len) * MAX_LEN);
    if ( !len )
        goto out;

    fprintf(stdout," ID                                     | status\n"
                   "----------------------------------------+------------\n");
    do {
        done = 0;
        memset(info, 'A', sizeof(*info) * MAX_LEN); /* Optional. */
        memset(id, 'i', sizeof(*id) * MAX_LEN * XEN_XSPLICE_ID_SIZE); /* Optional. */
        memset(len, 'l', sizeof(*len) * MAX_LEN); /* Optional. */
        rc = xc_xsplice_list(xch, MAX_LEN, idx, info, id, len, &done, &left);
        if ( rc )
        {
            fprintf(stderr, "Failed to list %d/%d: %d(%s)!\n", idx, left, errno, strerror(errno));
            break;
        }
        for ( i = 0; i < done; i++ )
        {
            unsigned int j;
            uint32_t sz;
            char *str;

            sz = len[i];
            str = id + (i * XEN_XSPLICE_ID_SIZE);
            for ( j = sz; j < XEN_XSPLICE_ID_SIZE; j++ )
                str[j] = '\0';

            fprintf(stdout, "%-40s| ", str);
            if ( info[i].status < 0 )
                fprintf(stdout, "%s\n", strerror(info[i].status));
            else
                fprintf(stdout, "%s\n", status2str(info[i].status));
        }
        idx += done;
    } while ( left );

out:
    free(id);
    free(info);
    free(len);
    return rc;
}
#undef MAX_LEN

static int get_id(int argc, char *argv[], char *id)
{
    ssize_t len = strlen(argv[0]);
    if ( len > XEN_XSPLICE_ID_SIZE )
    {
        fprintf(stderr, "ID MUST be %d characters!\n", XEN_XSPLICE_ID_SIZE);
        errno = EINVAL;
        return errno;
    }
    /* Don't want any funny strings from the stack. */
    memset(id, 0, XEN_XSPLICE_ID_SIZE);
    strncpy(id, argv[0], len);
    return 0;
}

static int upload_func(int argc, char *argv[])
{
    char *filename;
    char id[XEN_XSPLICE_ID_SIZE];
    int fd = 0, rc;
    struct stat buf;
    unsigned char *fbuf;
    ssize_t len;
    DECLARE_HYPERCALL_BUFFER(char, payload);

    if ( argc != 2 )
    {
        show_help();
        return -1;
    }

    if ( get_id(argc, argv, id) )
        return EINVAL;

    filename = argv[1];
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
    printf("Uploading %s (%zu bytes)\n", filename, len);
    payload = xc_hypercall_buffer_alloc(xch, payload, len);
    memcpy(payload, fbuf, len);

    rc = xc_xsplice_upload(xch, id, payload, len);
    if ( rc )
    {
        fprintf(stderr, "Upload failed: %s, error: %d(%s)!\n",
                filename, errno, strerror(errno));
        goto out;
    }
    xc_hypercall_buffer_free(xch, payload);

out:
    if ( munmap( fbuf, len) )
    {
        fprintf(stderr, "Could not unmap!? error: %d(%s)!\n",
                errno, strerror(errno));
        rc = errno;
    }
    close(fd);

    return rc;
}

enum {
    ACTION_APPLY = 0,
    ACTION_REVERT = 1,
    ACTION_UNLOAD = 2,
    ACTION_CHECK = 3
};

struct {
    int allow; /* State it must be in to call function. */
    int expected; /* The state to be in after the function. */
    const char *name;
    int (*function)(xc_interface *xch, char *id);
    unsigned int executed; /* Has the function been called?. */
} action_options[] = {
    {   .allow = XSPLICE_STATUS_CHECKED | XSPLICE_STATUS_REVERTED,
        .expected = XSPLICE_STATUS_APPLIED,
        .name = "apply",
        .function = xc_xsplice_apply,
    },
    {   .allow = XSPLICE_STATUS_APPLIED,
        .expected = XSPLICE_STATUS_REVERTED,
        .name = "revert",
        .function = xc_xsplice_revert,
    },
    {   .allow = XSPLICE_STATUS_CHECKED | XSPLICE_STATUS_REVERTED | XSPLICE_STATUS_LOADED,
        .expected = ENOENT,
        .name = "unload",
        .function = xc_xsplice_unload,
    },
    {   .allow = XSPLICE_STATUS_CHECKED | XSPLICE_STATUS_LOADED,
        .expected = XSPLICE_STATUS_CHECKED,
        .name = "check",
        .function = xc_xsplice_check
    },
};

int action_func(int argc, char *argv[], unsigned int idx)
{
    char id[XEN_XSPLICE_ID_SIZE];
    int rc;
    xen_xsplice_status_t status;
    unsigned int retry = 0;

    if ( argc != 1 )
    {
        show_help();
        return -1;
    }

    if ( idx >= ARRAY_SIZE(action_options) )
        return -1;

    if ( get_id(argc, argv, id) )
        return EINVAL;

    do {
        rc = xc_xsplice_get(xch, id, &status);
        /* N.B. Successfull unload will return ENOENT. */
        if ( rc )
        {
            rc = errno; /* rc is just -1 and we want proper EXX. */
            break;
        }

        if ( status.status < 0 )
        { /* We report it outside the loop. */
            rc = status.status;
            break;
        }
        if ( status.status == XSPLICE_STATUS_PROGRESS )
        {
            if ( !action_options[idx].executed )
            {
                printf("%s is in progress and we didn't initiate it!\n", id);
                errno = EBUSY;
                rc = -1;
                break;
            }
            if ( retry++ < 30 )
            {
                printf(".");
                sleep(1);
                continue;
            }
            printf("%s: Waited more than 30 seconds! Bailing out.\n", id);
            errno = EBUSY;
            rc = -1;
            break;
        }
        /* We use rc outside loop to deal with EXX type expected values. */
        rc = status.status;
        if ( action_options[idx].expected == rc ) /* Yeey! */
            break;

        if ( action_options[idx].allow & rc )
        {
            if ( action_options[idx].executed )
            {
                printf(" (0x%x vs 0x%x) state not reached!?\n",
                       action_options[idx].expected, rc);
                errno = EINVAL;
                break;
            }
            printf("%s: State is 0x%x, ok are 0x%x. Commencing %s:",
                   id, rc, action_options[idx].allow,
                   action_options[idx].name);

            rc = action_options[idx].function(xch, id);
            if ( rc ) /* We report it outside the loop. */
                break;

            action_options[idx].executed = 1;
            rc = 1; /* Loop again so we can display the dots. */
        } else {
            printf("%s: in wrong state (0x%x), expected 0x%x\n",
                   id, rc, action_options[idx].expected);
            errno = EINVAL;
            rc = -1;
            break;
        }
    } while ( rc > 0 );

    if ( action_options[idx].expected == rc )
    {
            printf("completed!\n");
            rc = 0;
    } else
        printf("%s failed with %d(%s)\n", id, errno, strerror(errno));

    return rc;
}
static int all_func(int argc, char *argv[])
{
    int rc;

    rc = upload_func(argc, argv);
    if ( rc )
        return rc;

    rc = action_func(1 /* only id */, argv, ACTION_CHECK);
    if ( rc )
        goto unload;

    rc = action_func(1 /* only id */, argv, ACTION_APPLY);
    if ( rc )
        goto unload;

    return 0;
unload:
    action_func(argc, argv, ACTION_UNLOAD);
    return rc;
}

#define MAX_LEN 1024
static int build_id_func(int argc, char *argv[])
{
    char binary_id[MAX_LEN];
    char ascii_id[MAX_LEN];
    int rc;
    unsigned int i;

    if ( argc )
    {
        show_help();
        return -1;
    }

    memset(binary_id, 0, sizeof(binary_id));

    rc = xc_version_len(xch, XENVER_build_id, binary_id, MAX_LEN);
    if ( rc < 0 )
    {
        printf("Failed to get build_id: %d(%s)\n", errno, strerror(errno));
        return -1;
    }
    /* Convert to printable format. */
    if ( rc > MAX_LEN )
        rc = MAX_LEN;

    for ( i = 0; i < rc && (i + 1) * 2 < sizeof(binary_id); i++ )
        snprintf(&ascii_id[i * 2], 3, "%02hhx", binary_id[i]);

    ascii_id[i*2]='\0';
    printf("%s", ascii_id);

    return 0;
}
#undef MAX_LEN

#define MAX_LEN 1024
static int trace_func(int argc, char *argv[])
{
    char trace[MAX_LEN];
    int rc;
    unsigned int idx;

    if ( argc )
    {
        if ( strcmp(argv[0], "clear") != 0 )
        {
            show_help();
            return -1;
        }
        return xc_xsplice_trace_clear(xch);
    }

    rc = idx = 0;
    fprintf(stdout,"----------------------------------------+------------\n");
    do {
        memset(trace, 0, sizeof(trace));
        rc = xc_xsplice_trace(xch, idx, trace, MAX_LEN);
        if ( rc > 0 )
        {
            idx += rc;
            fprintf(stdout, "%s", trace);
        }
    } while ( rc > 0 );

    return rc;
}
#undef MAX_LEN

struct {
    const char *name;
    int (*function)(int argc, char *argv[]);
} main_options[] = {
    { "help", help_func },
    { "list", list_func },
    { "build-id", build_id_func },
    { "upload", upload_func },
    { "all", all_func },
    { "trace", trace_func },
};

int main(int argc, char *argv[])
{
    int i, j, ret;

    if ( argc  <= 1 )
    {
        show_help();
        return 0;
    }
    for ( i = 0; i < ARRAY_SIZE(main_options); i++ )
        if (!strncmp(main_options[i].name, argv[1], strlen(argv[1])))
            break;

    if ( i == ARRAY_SIZE(main_options) )
    {
        for ( j = 0; j < ARRAY_SIZE(action_options); j++ )
            if (!strncmp(action_options[j].name, argv[1], strlen(argv[1])))
                break;

        if ( j == ARRAY_SIZE(action_options) )
        {
            fprintf(stderr, "Unrecognised command '%s' -- try "
                   "'xen-xsplice help'\n", argv[1]);
            return 1;
        }
    } else
        j = ARRAY_SIZE(action_options);

    xch = xc_interface_open(0,0,0);
    if ( !xch )
    {
        fprintf(stderr, "failed to get the handler\n");
        return 0;
    }

    if ( i == ARRAY_SIZE(main_options) )
        ret = action_func(argc -2, argv + 2, j);
    else
        ret = main_options[i].function(argc -2, argv + 2);

    xc_interface_close(xch);

    return !!ret;
}
