/*
 * Copyright (c) 2015 Oracle and/or its affiliates. All rights reserved.
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
static xc_interface *xch;

void show_help(void)
{
    fprintf(stderr,
            "xen-xsplice: Xsplice test tool\n"
            "Usage: xen-xsplice <command> [args]\n"
            " <id> An unique name of payload. Up to %d characters.\n"
            "Commands:\n"
            "  help                 display this help\n"
            "  upload <id> <file>   upload file <file> with <id> name\n"
            "  list                 list payloads uploaded.\n"
            "  apply <id>           apply <id> patch.\n"
            "  revert <id>          revert id <id> patch.\n"
            "  replace <id>         apply <id> patch and revert all others.\n"
            "  unload <id>          unload id <id> patch.\n"
            "  check <id>           check id <id> patch.\n"
            "  all <id> <file>      upload, check and apply <file>.\n",
            XEN_XSPLICE_NAME_SIZE);
}

/* wrapper function */
static int help_func(int argc, char *argv[])
{
    show_help();
    return 0;
}

#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

static const char *state2str(long state)
{
#define STATE(x) [XSPLICE_STATE_##x] = #x
    static const char *const names[] = {
            STATE(LOADED),
            STATE(CHECKED),
            STATE(APPLIED),
    };
#undef STATE
    if (state >= ARRAY_SIZE(names))
        return "unknown";

    if (state < 0)
        return "-EXX";

    if (!names[state])
        return "unknown";

    return names[state];
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
    id = malloc(sizeof(*id) * XEN_XSPLICE_NAME_SIZE * MAX_LEN);
    if ( !id )
        goto out;
    len = malloc(sizeof(*len) * MAX_LEN);
    if ( !len )
        goto out;

    fprintf(stdout," ID                                     | Build ID                                  | status\n"
                   "----------------------------------------+---------------------------------------------------\n");
    do {
        done = 0;
        memset(info, 'A', sizeof(*info) * MAX_LEN); /* Optional. */
        memset(id, 'i', sizeof(*id) * MAX_LEN * XEN_XSPLICE_NAME_SIZE); /* Optional. */
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
            bool has_buildid = false;

            sz = len[i];
            str = id + (i * XEN_XSPLICE_NAME_SIZE);
            for ( j = sz; j < XEN_XSPLICE_NAME_SIZE; j++ )
                str[j] = '\0';

            printf("%-40s| ", str);
            for ( j = 0; j < BUILD_ID_LEN; j++ )
            {
                if ( info[i].buildid[j] )
                {
                    has_buildid = true;
                    break;
                }
            }

            for ( j = 0; j < BUILD_ID_LEN; j++ )
            {
                if ( has_buildid )
                    printf("%02hhx", info[i].buildid[j]);
                else
                    printf("  ");
            }
            printf("| %s", state2str(info[i].state));

            if ( info[i].rc )
                printf(" (%d, %s)\n", -info[i].rc, strerror(-info[i].rc));
            else
                puts("");
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
    if ( len > XEN_XSPLICE_NAME_SIZE )
    {
        fprintf(stderr, "ID MUST be %d characters!\n", XEN_XSPLICE_NAME_SIZE);
        errno = EINVAL;
        return errno;
    }
    /* Don't want any funny strings from the stack. */
    memset(id, 0, XEN_XSPLICE_NAME_SIZE);
    strncpy(id, argv[0], len);
    return 0;
}

static int upload_func(int argc, char *argv[])
{
    char *filename;
    char id[XEN_XSPLICE_NAME_SIZE];
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
    {   .allow = XSPLICE_STATE_CHECKED,
        .expected = XSPLICE_STATE_APPLIED,
        .name = "apply",
        .function = xc_xsplice_apply,
    },
    {   .allow = XSPLICE_STATE_APPLIED,
        .expected = XSPLICE_STATE_CHECKED,
        .name = "revert",
        .function = xc_xsplice_revert,
    },
    {   .allow = XSPLICE_STATE_CHECKED | XSPLICE_STATE_LOADED,
        .expected = -ENOENT,
        .name = "unload",
        .function = xc_xsplice_unload,
    },
    {   .allow = XSPLICE_STATE_CHECKED | XSPLICE_STATE_LOADED,
        .expected = XSPLICE_STATE_CHECKED,
        .name = "check",
        .function = xc_xsplice_check
    },
    {   .allow = XSPLICE_STATE_CHECKED,
        .expected = XSPLICE_STATE_APPLIED,
        .name = "replace",
        .function = xc_xsplice_replace,
    },
};

#define RETRIES 300
#define DELAY 100000

int action_func(int argc, char *argv[], unsigned int idx)
{
    char id[XEN_XSPLICE_NAME_SIZE];
    int rc, original_state;
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

    /* Check initial status. */
    rc = xc_xsplice_get(xch, id, &status);
    if ( rc )
        goto err;

    if ( status.rc == -EAGAIN )
    {
        printf("%s failed. Operation already in progress\n", id);
        return -1;
    }

    if ( status.state == action_options[idx].expected )
    {
        printf("No action needed\n");
        return 0;
    }

    /* Perform action. */
    if ( action_options[idx].allow & status.state )
    {
        printf("Performing %s:", action_options[idx].name);
        rc = action_options[idx].function(xch, id);
        if ( rc )
            goto err;
    }
    else
    {
        printf("%s: in wrong state (%s), expected (%s)\n",
               id, state2str(status.state),
               state2str(action_options[idx].expected));
        return -1;
    }

    original_state = status.state;
    do {
        rc = xc_xsplice_get(xch, id, &status);
        if ( rc )
        {
            rc = -errno;
            break;
        }

        if ( status.state != original_state )
            break;
        if ( status.rc && status.rc != -EAGAIN )
        {
            rc = status.rc;
            break;
        }

        printf(".");
        fflush(stdout);
        usleep(DELAY);
    } while ( ++retry < RETRIES );

    if ( retry >= RETRIES )
    {
        printf("%s: Operation didn't complete after 30 seconds.\n", id);
        return -1;
    }
    else
    {
        if ( rc == 0 )
            rc = status.state;

        if ( action_options[idx].expected == rc )
            printf(" completed\n");
        else if ( rc < 0 )
        {
            printf("%s failed with %d(%s)\n", id, -rc, strerror(-rc));
            return -1;
        }
        else
        {
            printf("%s: in wrong state (%s), expected (%s)\n",
               id, state2str(rc),
               state2str(action_options[idx].expected));
            return -1;
        }
    }

    return 0;

 err:
    printf("%s failed with %d(%s)\n", id, -rc, strerror(-rc));
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

struct {
    const char *name;
    int (*function)(int argc, char *argv[]);
} main_options[] = {
    { "help", help_func },
    { "list", list_func },
    { "upload", upload_func },
    { "all", all_func },
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
