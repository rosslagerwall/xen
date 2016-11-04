    .section .init.rodata, "a", @progbits
    .align 8
GLOBAL(builtin_payload_key_buffer)
    .incbin "builtin_payload_key.bin"
