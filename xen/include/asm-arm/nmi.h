#ifndef ASM_NMI_H
#define ASM_NMI_H

#define register_guest_nmi_callback(a)  (-ENOSYS)
#define unregister_guest_nmi_callback() (-ENOSYS)

typedef int (*nmi_callback_t)(const struct cpu_user_regs *regs, int cpu);

/**
 * set_nmi_callback
 *
 * Set a handler for an NMI. Only one handler may be
 * set. Return the old nmi callback handler.
 */
static inline nmi_callback_t set_nmi_callback(nmi_callback_t callback)
{
    return NULL;
}

#endif /* ASM_NMI_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
