OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(xsplice)
SECTIONS
{
    . = 0x0;

    /* XXX: To be generated. */
    _xen_extra_version_size = xen_changeset - xen_extra_version;

    .xsplice_code : { *(.data.xsplice_code*) }
    _xsplice_code_size = SIZEOF(.xsplice_code);

    .xsplice_relocs : { *(.data.xsplice_relocs*) }
    _xsplice_relocs_size = SIZEOF(.xsplice_relocs);

    .xsplice_sections : { *(.data.xsplice_sections*) }
    _xsplice_sections_size = SIZEOF(.xsplice_sections);

    .xsplice_reloc_howto : { *(.data.xsplice_reloc_howto*) }

    .xsplice_symbols : { *(.data.xsplice_symbol*) }

    .xsplice_patches : { *(.data.xsplice_patches*) }
    _xsplice_patches_size = SIZEOF(.xsplice_patches);

    .xsplice : { *(.data.xsplice) /* No wildcard */ }
    .xsplice_size = SIZEOF(.xsplice);

    . = ALIGN(4096);

    .xen_build_id : {
        *(.__note_gnu_build_id_start)
        *(.note.gnu.build-id)
    }
    xen_build_id_size = SIZEOF(.xen_build_id);

    . = ALIGN(4096);

    .text ALIGN(4096) : { KEEP (*(SORT(.text))) }

    .data ALIGN(4096) : { KEEP(*(SORT(.data))) }

    .bss ALIGN(4096) : { KEEP(*(SORT(.bss))) }

    .rodata ALIGN(4096) : { KEEP(*(SORT(.rodata))) }

    /DISCARD/ : {
        *(.comment)
        *(.note.GNU-stack)
        *(.debug* /* Wildcard!*/)
    }
}
