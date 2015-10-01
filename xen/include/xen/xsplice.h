#ifndef __XEN_XSPLICE_H__
#define __XEN_XSPLICE_H__

struct xen_sysctl_xsplice_op;
int xsplice_control(struct xen_sysctl_xsplice_op *);

extern void xsplice_printall(unsigned char key);

#endif /* __XEN_XSPLICE_H__ */
