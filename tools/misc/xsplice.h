
#include <stdint.h>
#include <sys/types.h>

#define XSPLICE_HOWTO_INLINE        0x1 /* It is an inline replacement. */
#define XSPLICE_HOWTO_RELOC_PATCH   0x2 /* Add an trampoline. */

#define XSPLICE_HOWTO_FLAG_PC_REL    0x1 /* Is PC relative. */
#define XSPLICE_HOWOT_FLAG_SIGN      0x2 /* Should the new value be treated as signed value. */

struct xsplice_reloc_howto {
    uint32_t    howto;/* XSPLICE_HOWTO_* */
    uint32_t    flag; /* XSPLICE_HOWTO_FLAG_* */
    uint32_t    size; /* Size, in bytes, of the item to be relocated. */
    uint32_t    r_shift; /* The value the final relocation is shifted right by; used to drop unwanted data from the relocation. */
    uint64_t    mask; /* Bitmask for which parts of the instruction or data are replaced with the relocated value. */
    uint8_t     pad[8]; /* Must be zero. */
};

struct xsplice_symbol {
    const char *name; /* The ELF name of the symbol. */
    const char *label; /* A unique xSplice name for the symbol. */
    uint8_t pad[16]; /* Must be zero. */
};
#define XSPLICE_PATCH_INLINE_TEXT   0x1
#define XSPLICE_PATCH_INLINE_DATA   0x2
#define XSPLICE_PATCH_RELOC_TEXT    0x3

struct xsplice_patch {
    uint32_t type; /* XSPLICE_PATCH_* .*/
    uint64_t addr; /* The address of the inline new code (or data). */
    const void *content; /* The bytes to be installed. */
    const char *size; /* The size bytes to be installed. */
    uint8_t pad[40]; /* Must be zero. */
};

#define XSPLICE_SECTION_TEXT   0x00000001 /* Section is in .text */
#define XSPLICE_SECTION_RODATA 0x00000002 /* Section is in .rodata */
#define XSPLICE_SECTION_DATA   0x00000004 /* Section is in .data */
#define XSPLICE_SECTION_STRING 0x00000008 /* Section is in .str */

#define XSPLICE_SECTION_TEXT_INLINE 0x00000200 /* Change is to be inline. */ 
#define XSPLICE_SECTION_MATCH_EXACT 0x00000400 /* Must match exactly. */
#define XSPLICE_SECTION_NO_STACKCHECK 0x00000800 /* Do not check the stack. */

struct xsplice_section {
    const struct xsplice_symbol *symbol; /* The symbol associated with this change. */
    uint64_t address; /* The address of the section (if known). */
    uint32_t flags; /* Various XSPLICE_SECTION_* flags. */
    char *size; /* The size of the section. */
    uint8_t pad[28]; /* To be zero. */
};

struct xsplice_reloc {
    uint64_t addr; /* The address of the relocation (if known). */
    const struct xsplice_symbol *symbol; /* Symbol for this relocation. */
    int64_t isns_target; /* rest of the ELF addend.  This is equal to the offset against the symbol that the relocation refers to. */
    const struct xsplice_reloc_howto  *howto; /* Pointer to the above structure. */
    int64_t isns_added; /* ELF addend resulting from quirks of instruction one of whose operands is the relocation. For example, this is -4 on x86 pc-relative jumps. */
    uint8_t pad[24];  /* Must be zero. */
};

struct xsplice_code {
    const struct xsplice_reloc *relocs; /* How to patch it. */
    const struct xsplice_section *sections; /* Safety data. */
    const struct xsplice_patch *patches; /* Patch code and data */
    const uint32_t *relocs_len;
    const uint32_t *sections_len;
    const uint32_t *patches_len;
    uint8_t pad[28]; /* Must be zero. */
};
struct xsplice {
    const char *name; /* A sensible name for the patch. */
    const char *build_id; /* ID of the hypervisor this binary was built against. */
    const struct xsplice_code *new; /* Pointer to the new code to be patched. */
    const struct xsplice_code *old; /* Pointer to the old code to be checked against. */
    uint32_t version;
    uint32_t *name_len;
    uint32_t *build_id_len;
    uint8_t pad[20];  /* Must be zero. */
};
