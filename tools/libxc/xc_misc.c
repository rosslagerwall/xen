/******************************************************************************
 * xc_misc.c
 *
 * Miscellaneous control interface functions.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "xc_bitops.h"
#include "xc_private.h"
#include <xen/hvm/hvm_op.h>

int xc_get_max_cpus(xc_interface *xch)
{
    static int max_cpus = 0;
    xc_physinfo_t physinfo;

    if ( max_cpus )
        return max_cpus;

    if ( !xc_physinfo(xch, &physinfo) )
    {
        max_cpus = physinfo.max_cpu_id + 1;
        return max_cpus;
    }

    return -1;
}

int xc_get_online_cpus(xc_interface *xch)
{
    xc_physinfo_t physinfo;

    if ( !xc_physinfo(xch, &physinfo) )
        return physinfo.nr_cpus;

    return -1;
}

int xc_get_max_nodes(xc_interface *xch)
{
    static int max_nodes = 0;
    xc_physinfo_t physinfo;

    if ( max_nodes )
        return max_nodes;

    if ( !xc_physinfo(xch, &physinfo) )
    {
        max_nodes = physinfo.max_node_id + 1;
        return max_nodes;
    }

    return -1;
}

int xc_get_cpumap_size(xc_interface *xch)
{
    int max_cpus = xc_get_max_cpus(xch);

    if ( max_cpus < 0 )
        return -1;
    return (max_cpus + 7) / 8;
}

int xc_get_nodemap_size(xc_interface *xch)
{
    int max_nodes = xc_get_max_nodes(xch);

    if ( max_nodes < 0 )
        return -1;
    return (max_nodes + 7) / 8;
}

xc_cpumap_t xc_cpumap_alloc(xc_interface *xch)
{
    int sz;

    sz = xc_get_cpumap_size(xch);
    if (sz <= 0)
        return NULL;
    return calloc(1, sz);
}

/*
 * xc_bitops.h has macros that do this as well - however they assume that
 * the bitmask is word aligned but xc_cpumap_t is only guaranteed to be
 * byte aligned and so we need byte versions for architectures which do
 * not support misaligned accesses (which is basically everyone
 * but x86, although even on x86 it can be inefficient).
 */
#define BITS_PER_CPUMAP(map) (sizeof(*map) * 8)
#define CPUMAP_ENTRY(cpu, map) ((map))[(cpu) / BITS_PER_CPUMAP(map)]
#define CPUMAP_SHIFT(cpu, map) ((cpu) % BITS_PER_CPUMAP(map))
void xc_cpumap_clearcpu(int cpu, xc_cpumap_t map)
{
    CPUMAP_ENTRY(cpu, map) &= ~(1U << CPUMAP_SHIFT(cpu, map));
}

void xc_cpumap_setcpu(int cpu, xc_cpumap_t map)
{
    CPUMAP_ENTRY(cpu, map) |= (1U << CPUMAP_SHIFT(cpu, map));
}

int xc_cpumap_testcpu(int cpu, xc_cpumap_t map)
{
    return (CPUMAP_ENTRY(cpu, map) >> CPUMAP_SHIFT(cpu, map)) & 1;
}

xc_nodemap_t xc_nodemap_alloc(xc_interface *xch)
{
    int sz;

    sz = xc_get_nodemap_size(xch);
    if (sz <= 0)
        return NULL;
    return calloc(1, sz);
}

int xc_readconsolering(xc_interface *xch,
                       char *buffer,
                       unsigned int *pnr_chars,
                       int clear, int incremental, uint32_t *pindex)
{
    int ret;
    unsigned int nr_chars = *pnr_chars;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(buffer, nr_chars, XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( xc_hypercall_bounce_pre(xch, buffer) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_readconsole;
    set_xen_guest_handle(sysctl.u.readconsole.buffer, buffer);
    sysctl.u.readconsole.count = nr_chars;
    sysctl.u.readconsole.clear = clear;
    sysctl.u.readconsole.incremental = 0;
    if ( pindex )
    {
        sysctl.u.readconsole.index = *pindex;
        sysctl.u.readconsole.incremental = incremental;
    }

    if ( (ret = do_sysctl(xch, &sysctl)) == 0 )
    {
        *pnr_chars = sysctl.u.readconsole.count;
        if ( pindex )
            *pindex = sysctl.u.readconsole.index;
    }

    xc_hypercall_bounce_post(xch, buffer);

    return ret;
}

int xc_send_debug_keys(xc_interface *xch, char *keys)
{
    int ret, len = strlen(keys);
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(keys, len, XC_HYPERCALL_BUFFER_BOUNCE_IN);

    if ( xc_hypercall_bounce_pre(xch, keys) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_debug_keys;
    set_xen_guest_handle(sysctl.u.debug_keys.keys, keys);
    sysctl.u.debug_keys.nr_keys = len;

    ret = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, keys);

    return ret;
}

int xc_physinfo(xc_interface *xch,
                xc_physinfo_t *put_info)
{
    int ret;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_physinfo;

    memcpy(&sysctl.u.physinfo, put_info, sizeof(*put_info));

    if ( (ret = do_sysctl(xch, &sysctl)) != 0 )
        return ret;

    memcpy(put_info, &sysctl.u.physinfo, sizeof(*put_info));

    return 0;
}

int xc_cputopoinfo(xc_interface *xch, unsigned *max_cpus,
                   xc_cputopo_t *cputopo)
{
    int ret;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(cputopo, *max_cpus * sizeof(*cputopo),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( (ret = xc_hypercall_bounce_pre(xch, cputopo)) )
        goto out;

    sysctl.u.cputopoinfo.num_cpus = *max_cpus;
    set_xen_guest_handle(sysctl.u.cputopoinfo.cputopo, cputopo);

    sysctl.cmd = XEN_SYSCTL_cputopoinfo;

    if ( (ret = do_sysctl(xch, &sysctl)) != 0 )
        goto out;

    *max_cpus = sysctl.u.cputopoinfo.num_cpus;

out:
    xc_hypercall_bounce_post(xch, cputopo);

    return ret;
}

int xc_numainfo(xc_interface *xch, unsigned *max_nodes,
                xc_meminfo_t *meminfo, uint32_t *distance)
{
    int ret;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(meminfo, *max_nodes * sizeof(*meminfo),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_HYPERCALL_BOUNCE(distance,
                             *max_nodes * *max_nodes * sizeof(*distance),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( (ret = xc_hypercall_bounce_pre(xch, meminfo)) )
        goto out;
    if ((ret = xc_hypercall_bounce_pre(xch, distance)) )
        goto out;

    sysctl.u.numainfo.num_nodes = *max_nodes;
    set_xen_guest_handle(sysctl.u.numainfo.meminfo, meminfo);
    set_xen_guest_handle(sysctl.u.numainfo.distance, distance);

    sysctl.cmd = XEN_SYSCTL_numainfo;

    if ( (ret = do_sysctl(xch, &sysctl)) != 0 )
        goto out;

    *max_nodes = sysctl.u.numainfo.num_nodes;

out:
    xc_hypercall_bounce_post(xch, meminfo);
    xc_hypercall_bounce_post(xch, distance);

    return ret;
}

int xc_pcitopoinfo(xc_interface *xch, unsigned num_devs,
                   physdev_pci_device_t *devs,
                   uint32_t *nodes)
{
    int ret = 0;
    unsigned processed = 0;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(devs, num_devs * sizeof(*devs),
                             XC_HYPERCALL_BUFFER_BOUNCE_IN);
    DECLARE_HYPERCALL_BOUNCE(nodes, num_devs* sizeof(*nodes),
                             XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    if ( (ret = xc_hypercall_bounce_pre(xch, devs)) )
        goto out;
    if ( (ret = xc_hypercall_bounce_pre(xch, nodes)) )
        goto out;

    sysctl.cmd = XEN_SYSCTL_pcitopoinfo;

    while ( processed < num_devs )
    {
        sysctl.u.pcitopoinfo.num_devs = num_devs - processed;
        set_xen_guest_handle_offset(sysctl.u.pcitopoinfo.devs, devs,
                                    processed);
        set_xen_guest_handle_offset(sysctl.u.pcitopoinfo.nodes, nodes,
                                    processed);

        if ( (ret = do_sysctl(xch, &sysctl)) != 0 )
                break;

        processed += sysctl.u.pcitopoinfo.num_devs;
    }

 out:
    xc_hypercall_bounce_post(xch, devs);
    xc_hypercall_bounce_post(xch, nodes);

    return ret;
}

int xc_sched_id(xc_interface *xch,
                int *sched_id)
{
    int ret;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_sched_id;

    if ( (ret = do_sysctl(xch, &sysctl)) != 0 )
        return ret;

    *sched_id = sysctl.u.sched_id.sched_id;

    return 0;
}

#if defined(__i386__) || defined(__x86_64__)
int xc_mca_op(xc_interface *xch, struct xen_mc *mc)
{
    int ret = 0;
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BOUNCE(mc, sizeof(*mc), XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    if ( xc_hypercall_bounce_pre(xch, mc) )
    {
        PERROR("Could not bounce xen_mc memory buffer");
        return -1;
    }
    mc->interface_version = XEN_MCA_INTERFACE_VERSION;

    hypercall.op = __HYPERVISOR_mca;
    hypercall.arg[0] = HYPERCALL_BUFFER_AS_ARG(mc);
    ret = do_xen_hypercall(xch, &hypercall);
    xc_hypercall_bounce_post(xch, mc);
    return ret;
}
#endif

int xc_perfc_reset(xc_interface *xch)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_perfc_op;
    sysctl.u.perfc_op.cmd = XEN_SYSCTL_PERFCOP_reset;
    set_xen_guest_handle(sysctl.u.perfc_op.desc, HYPERCALL_BUFFER_NULL);
    set_xen_guest_handle(sysctl.u.perfc_op.val, HYPERCALL_BUFFER_NULL);

    return do_sysctl(xch, &sysctl);
}

int xc_perfc_query_number(xc_interface *xch,
                          int *nbr_desc,
                          int *nbr_val)
{
    int rc;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_perfc_op;
    sysctl.u.perfc_op.cmd = XEN_SYSCTL_PERFCOP_query;
    set_xen_guest_handle(sysctl.u.perfc_op.desc, HYPERCALL_BUFFER_NULL);
    set_xen_guest_handle(sysctl.u.perfc_op.val, HYPERCALL_BUFFER_NULL);

    rc = do_sysctl(xch, &sysctl);

    if ( nbr_desc )
        *nbr_desc = sysctl.u.perfc_op.nr_counters;
    if ( nbr_val )
        *nbr_val = sysctl.u.perfc_op.nr_vals;

    return rc;
}

int xc_perfc_query(xc_interface *xch,
                   struct xc_hypercall_buffer *desc,
                   struct xc_hypercall_buffer *val)
{
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BUFFER_ARGUMENT(desc);
    DECLARE_HYPERCALL_BUFFER_ARGUMENT(val);

    sysctl.cmd = XEN_SYSCTL_perfc_op;
    sysctl.u.perfc_op.cmd = XEN_SYSCTL_PERFCOP_query;
    set_xen_guest_handle(sysctl.u.perfc_op.desc, desc);
    set_xen_guest_handle(sysctl.u.perfc_op.val, val);

    return do_sysctl(xch, &sysctl);
}

int xc_lockprof_reset(xc_interface *xch)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_lockprof_op;
    sysctl.u.lockprof_op.cmd = XEN_SYSCTL_LOCKPROF_reset;
    set_xen_guest_handle(sysctl.u.lockprof_op.data, HYPERCALL_BUFFER_NULL);

    return do_sysctl(xch, &sysctl);
}

int xc_lockprof_query_number(xc_interface *xch,
                             uint32_t *n_elems)
{
    int rc;
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_lockprof_op;
    sysctl.u.lockprof_op.max_elem = 0;
    sysctl.u.lockprof_op.cmd = XEN_SYSCTL_LOCKPROF_query;
    set_xen_guest_handle(sysctl.u.lockprof_op.data, HYPERCALL_BUFFER_NULL);

    rc = do_sysctl(xch, &sysctl);

    *n_elems = sysctl.u.lockprof_op.nr_elem;

    return rc;
}

int xc_lockprof_query(xc_interface *xch,
                      uint32_t *n_elems,
                      uint64_t *time,
                      struct xc_hypercall_buffer *data)
{
    int rc;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BUFFER_ARGUMENT(data);

    sysctl.cmd = XEN_SYSCTL_lockprof_op;
    sysctl.u.lockprof_op.cmd = XEN_SYSCTL_LOCKPROF_query;
    sysctl.u.lockprof_op.max_elem = *n_elems;
    set_xen_guest_handle(sysctl.u.lockprof_op.data, data);

    rc = do_sysctl(xch, &sysctl);

    *n_elems = sysctl.u.lockprof_op.nr_elem;

    return rc;
}

int xc_getcpuinfo(xc_interface *xch, int max_cpus,
                  xc_cpuinfo_t *info, int *nr_cpus)
{
    int rc;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(info, max_cpus*sizeof(*info), XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( xc_hypercall_bounce_pre(xch, info) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_getcpuinfo;
    sysctl.u.getcpuinfo.max_cpus = max_cpus;
    set_xen_guest_handle(sysctl.u.getcpuinfo.info, info);

    rc = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, info);

    if ( nr_cpus )
        *nr_cpus = sysctl.u.getcpuinfo.nr_cpus;

    return rc;
}


int xc_hvm_set_pci_intx_level(
    xc_interface *xch, domid_t dom,
    uint8_t domain, uint8_t bus, uint8_t device, uint8_t intx,
    unsigned int level)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(struct xen_hvm_set_pci_intx_level, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
    {
        PERROR("Could not allocate memory for xc_hvm_set_pci_intx_level hypercall");
        return -1;
    }

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_set_pci_intx_level;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);

    arg->domid  = dom;
    arg->domain = domain;
    arg->bus    = bus;
    arg->device = device;
    arg->intx   = intx;
    arg->level  = level;

    rc = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);

    return rc;
}

int xc_hvm_set_isa_irq_level(
    xc_interface *xch, domid_t dom,
    uint8_t isa_irq,
    unsigned int level)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(struct xen_hvm_set_isa_irq_level, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
    {
        PERROR("Could not allocate memory for xc_hvm_set_isa_irq_level hypercall");
        return -1;
    }

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_set_isa_irq_level;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);

    arg->domid   = dom;
    arg->isa_irq = isa_irq;
    arg->level   = level;

    rc = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);

    return rc;
}

int xc_hvm_set_pci_link_route(
    xc_interface *xch, domid_t dom, uint8_t link, uint8_t isa_irq)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(struct xen_hvm_set_pci_link_route, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
    {
        PERROR("Could not allocate memory for xc_hvm_set_pci_link_route hypercall");
        return -1;
    }

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_set_pci_link_route;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);

    arg->domid   = dom;
    arg->link    = link;
    arg->isa_irq = isa_irq;

    rc = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);

    return rc;
}

int xc_hvm_inject_msi(
    xc_interface *xch, domid_t dom, uint64_t addr, uint32_t data)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(struct xen_hvm_inject_msi, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
    {
        PERROR("Could not allocate memory for xc_hvm_inject_msi hypercall");
        return -1;
    }

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_inject_msi;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);

    arg->domid = dom;
    arg->addr  = addr;
    arg->data  = data;

    rc = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);

    return rc;
}

int xc_hvm_track_dirty_vram(
    xc_interface *xch, domid_t dom,
    uint64_t first_pfn, uint64_t nr,
    unsigned long *dirty_bitmap)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BOUNCE(dirty_bitmap, (nr+7) / 8, XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_HYPERCALL_BUFFER(struct xen_hvm_track_dirty_vram, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL || xc_hypercall_bounce_pre(xch, dirty_bitmap) )
    {
        PERROR("Could not bounce memory for xc_hvm_track_dirty_vram hypercall");
        rc = -1;
        goto out;
    }

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_track_dirty_vram;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);

    arg->domid     = dom;
    arg->first_pfn = first_pfn;
    arg->nr        = nr;
    set_xen_guest_handle(arg->dirty_bitmap, dirty_bitmap);

    rc = do_xen_hypercall(xch, &hypercall);

out:
    xc_hypercall_buffer_free(xch, arg);
    xc_hypercall_bounce_post(xch, dirty_bitmap);
    return rc;
}

int xc_hvm_modified_memory(
    xc_interface *xch, domid_t dom, uint64_t first_pfn, uint64_t nr)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(struct xen_hvm_modified_memory, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
    {
        PERROR("Could not allocate memory for xc_hvm_modified_memory hypercall");
        return -1;
    }

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_modified_memory;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);

    arg->domid     = dom;
    arg->first_pfn = first_pfn;
    arg->nr        = nr;

    rc = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);

    return rc;
}

int xc_hvm_set_mem_type(
    xc_interface *xch, domid_t dom, hvmmem_type_t mem_type, uint64_t first_pfn, uint64_t nr)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(struct xen_hvm_set_mem_type, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
    {
        PERROR("Could not allocate memory for xc_hvm_set_mem_type hypercall");
        return -1;
    }

    arg->domid        = dom;
    arg->hvmmem_type  = mem_type;
    arg->first_pfn    = first_pfn;
    arg->nr           = nr;

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_set_mem_type;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);

    rc = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);

    return rc;
}

int xc_hvm_inject_trap(
    xc_interface *xch, domid_t dom, int vcpu, uint32_t vector,
    uint32_t type, uint32_t error_code, uint32_t insn_len,
    uint64_t cr2)
{
    DECLARE_HYPERCALL;
    DECLARE_HYPERCALL_BUFFER(struct xen_hvm_inject_trap, arg);
    int rc;

    arg = xc_hypercall_buffer_alloc(xch, arg, sizeof(*arg));
    if ( arg == NULL )
    {
        PERROR("Could not allocate memory for xc_hvm_inject_trap hypercall");
        return -1;
    }

    arg->domid       = dom;
    arg->vcpuid      = vcpu;
    arg->vector      = vector;
    arg->type        = type;
    arg->error_code  = error_code;
    arg->insn_len    = insn_len;
    arg->cr2         = cr2;

    hypercall.op     = __HYPERVISOR_hvm_op;
    hypercall.arg[0] = HVMOP_inject_trap;
    hypercall.arg[1] = HYPERCALL_BUFFER_AS_ARG(arg);

    rc = do_xen_hypercall(xch, &hypercall);

    xc_hypercall_buffer_free(xch, arg);

    return rc;
}

int xc_xsplice_upload(xc_interface *xch,
                      char *id,
                      char *payload,
                      uint32_t size)
{
    int rc;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(payload, size, XC_HYPERCALL_BUFFER_BOUNCE_IN);
    DECLARE_HYPERCALL_BOUNCE(id, 0 /* adjust later */, XC_HYPERCALL_BUFFER_BOUNCE_IN);
    ssize_t len;

    if ( !id || !payload )
        return -1;

    len = strlen(id);
    if ( len > XEN_XSPLICE_ID_SIZE )
        return -1;

    HYPERCALL_BOUNCE_SET_SIZE(id, len);

    if ( xc_hypercall_bounce_pre(xch, id) )
        return -1;

    if ( xc_hypercall_bounce_pre(xch, payload) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_xsplice_op;
    sysctl.u.xsplice.cmd = XEN_SYSCTL_XSPLICE_UPLOAD;
    sysctl.u.xsplice.u.upload.size = size;
    set_xen_guest_handle(sysctl.u.xsplice.u.upload.payload, payload);

    sysctl.u.xsplice.u.upload.id.size = len;
    sysctl.u.xsplice.u.upload.id._pad = 0;
    set_xen_guest_handle(sysctl.u.xsplice.u.upload.id.name, id);

    rc = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, payload);
    xc_hypercall_bounce_post(xch, id);

    return rc;
}

int xc_xsplice_get(xc_interface *xch,
                   char *id,
                   xen_xsplice_status_t *status)
{
    int rc;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(id, 0 /*adjust later */, XC_HYPERCALL_BUFFER_BOUNCE_IN);
    ssize_t len;

    if ( !id )
        return -1;

    len = strlen(id);
    if ( len > XEN_XSPLICE_ID_SIZE )
        return -1;

    HYPERCALL_BOUNCE_SET_SIZE(id, len);

    if ( xc_hypercall_bounce_pre(xch, id) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_xsplice_op;
    sysctl.u.xsplice.cmd = XEN_SYSCTL_XSPLICE_GET;

    sysctl.u.xsplice.u.get.status.status = 0;

    sysctl.u.xsplice.u.get.id.size = len;
    sysctl.u.xsplice.u.get.id._pad = 0;
    set_xen_guest_handle(sysctl.u.xsplice.u.get.id.name, id);

    rc = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, id);

    memcpy(status, &sysctl.u.xsplice.u.get.status, sizeof(*status));

    return rc;
}

int xc_xsplice_list(xc_interface *xch, unsigned int max, unsigned int start,
                    xen_xsplice_status_t *info,
                    char *id, uint32_t *len,
                    unsigned int *done,
                    unsigned int *left)
{
    int rc;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(info, 0 /* adjust later. */, XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_HYPERCALL_BOUNCE(id, 0 /* adjust later. */, XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_HYPERCALL_BOUNCE(len, 0 /* adjust later. */, XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    uint32_t max_batch_sz, nr;
    uint32_t version = 0, retries = 0;
    uint32_t adjust = 0;

    if ( !max || !info || !id || !len )
        return -1;

    sysctl.cmd = XEN_SYSCTL_xsplice_op;
    sysctl.u.xsplice.cmd = XEN_SYSCTL_XSPLICE_LIST;
    sysctl.u.xsplice.u.list.version = 0;
    sysctl.u.xsplice.u.list.idx = start;
    sysctl.u.xsplice.u.list._pad = 0;

    max_batch_sz = max;

    *done = 0;
    *left = 0;
    do {
        if ( adjust )
            adjust = 0; /* Used when adjusting the 'max_batch_sz' or 'retries'. */

        nr = min(max - *done, max_batch_sz);

        sysctl.u.xsplice.u.list.nr = nr;
        /* Fix the size (may vary between hypercalls). */
        HYPERCALL_BOUNCE_SET_SIZE(info, nr * sizeof(*info));
        HYPERCALL_BOUNCE_SET_SIZE(id, nr * sizeof(*id) * XEN_XSPLICE_ID_SIZE);
        HYPERCALL_BOUNCE_SET_SIZE(len, nr * sizeof(*len));
        /* Move the pointer to proper offset into 'info'. */
        (HYPERCALL_BUFFER(info))->ubuf = info + *done;
        (HYPERCALL_BUFFER(id))->ubuf = id + (sizeof(*id) * XEN_XSPLICE_ID_SIZE * *done);
        (HYPERCALL_BUFFER(len))->ubuf = len + *done;
        /* Allocate memory. */
        rc = xc_hypercall_bounce_pre(xch, info);
        if ( rc )
            return rc;

        rc = xc_hypercall_bounce_pre(xch, id);
        if ( rc )
        {
            xc_hypercall_bounce_post(xch, info);
            return rc;
        }
        rc = xc_hypercall_bounce_pre(xch, len);
        if ( rc )
        {
            xc_hypercall_bounce_post(xch, info);
            xc_hypercall_bounce_post(xch, id);
            return rc;
        }
        set_xen_guest_handle(sysctl.u.xsplice.u.list.status, info);
        set_xen_guest_handle(sysctl.u.xsplice.u.list.id, id);
        set_xen_guest_handle(sysctl.u.xsplice.u.list.len, len);

        rc = do_sysctl(xch, &sysctl);
        /*
         * From here on we MUST call xc_hypercall_bounce. If rc < 0 we
         * end up doing it (outside the loop), so using a break is OK.
         */
        if ( rc < 0 && errno == E2BIG )
        {
            if ( max_batch_sz <= 1 )
                break;
            max_batch_sz >>= 1;
            adjust = 1; /* For the loop conditional to let us loop again. */
            /* No memory leaks! */
            xc_hypercall_bounce_post(xch, info);
            xc_hypercall_bounce_post(xch, id);
            xc_hypercall_bounce_post(xch, len);
            continue;
        }
        else if ( rc < 0 ) /* For all other errors we bail out. */
            break;

        if ( !version )
            version = sysctl.u.xsplice.u.list.version;

        if ( sysctl.u.xsplice.u.list.version != version )
        {
            /* TODO: retries should be configurable? */
            if ( retries++ > 3 )
            {
                rc = -1;
                errno = EBUSY;
                break;
            }
            *done = 0; /* Retry from scratch. */
            version = sysctl.u.xsplice.u.list.version;
            adjust = 1; /* And make sure we continue in the loop. */
            /* No memory leaks. */
            xc_hypercall_bounce_post(xch, info);
            xc_hypercall_bounce_post(xch, id);
            xc_hypercall_bounce_post(xch, len);
            continue;
        }

        /* We should never hit this, but just in case. */
        if ( rc > nr )
        {
            errno = EINVAL; /* Overflow! */
            rc = -1;
            break;
        }
        *left = sysctl.u.xsplice.u.list.nr; /* Total remaining count. */
        /* Copy only up 'rc' of data' - we could add 'min(rc,nr) if desired. */
        HYPERCALL_BOUNCE_SET_SIZE(info, (rc * sizeof(*info)));
        HYPERCALL_BOUNCE_SET_SIZE(id, (rc * sizeof(*id) * XEN_XSPLICE_ID_SIZE));
        HYPERCALL_BOUNCE_SET_SIZE(len, (rc * sizeof(*len)));
        /* Bounce the data and free the bounce buffer. */
        xc_hypercall_bounce_post(xch, info);
        xc_hypercall_bounce_post(xch, id);
        xc_hypercall_bounce_post(xch, len);
        /* And update how many elements of info we have copied into. */
        *done += rc;
        /* Update idx. */
        sysctl.u.xsplice.u.list.idx = *done;
    } while ( adjust || (*done < max && *left != 0) );

    if ( rc < 0 )
    {
        xc_hypercall_bounce_post(xch, len);
        xc_hypercall_bounce_post(xch, id);
        xc_hypercall_bounce_post(xch, info);
    }

    return rc > 0 ? 0 : rc;
}

static int _xc_xsplice_action(xc_interface *xch,
                              char *id,
                              unsigned int action)
{
    int rc;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(id, 0 /* adjust later */, XC_HYPERCALL_BUFFER_BOUNCE_IN);
    ssize_t len;

    len = strlen(id);

    if ( len > XEN_XSPLICE_ID_SIZE )
        return -1;

    HYPERCALL_BOUNCE_SET_SIZE(id, len);

    if ( xc_hypercall_bounce_pre(xch, id) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_xsplice_op;
    sysctl.u.xsplice.cmd = XEN_SYSCTL_XSPLICE_ACTION;
    sysctl.u.xsplice.u.action.cmd = action;
    sysctl.u.xsplice.u.action._pad = 0;
    sysctl.u.xsplice.u.action.time = 0; /* TODO */

    sysctl.u.xsplice.u.action.id.size = len;
    sysctl.u.xsplice.u.action.id._pad = 0;
    set_xen_guest_handle(sysctl.u.xsplice.u.action.id.name, id);

    rc = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, id);

    return rc;
}

int xc_xsplice_apply(xc_interface *xch, char *id)
{
    return _xc_xsplice_action(xch, id, XSPLICE_ACTION_APPLY);
}

int xc_xsplice_revert(xc_interface *xch, char *id)
{
    return _xc_xsplice_action(xch, id, XSPLICE_ACTION_REVERT);
}

int xc_xsplice_unload(xc_interface *xch, char *id)
{
    return _xc_xsplice_action(xch, id, XSPLICE_ACTION_UNLOAD);
}

int xc_xsplice_check(xc_interface *xch, char *id)
{
    return _xc_xsplice_action(xch, id, XSPLICE_ACTION_CHECK);
}

int xc_xsplice_replace(xc_interface *xch, char *id)
{
    return _xc_xsplice_action(xch, id, XSPLICE_ACTION_REPLACE);
}

int xc_xsplice_trace(xc_interface *xch, unsigned int idx, char *info,
                     unsigned int max)
{
    int rc;
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(info, max, XC_HYPERCALL_BUFFER_BOUNCE_OUT);

    if ( !info || !max )
        return -1;

    if ( xc_hypercall_bounce_pre(xch, info) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_xsplice_op;
    sysctl.u.xsplice.cmd = XEN_SYSCTL_XSPLICE_INFO;

    sysctl.u.xsplice.u.info.cmd = XEN_SYSCTL_XSPLICE_INFO_TRACE_GET;
    sysctl.u.xsplice.u.info._pad = 0;
    sysctl.u.xsplice.u.info.u.trace.size = max;
    sysctl.u.xsplice.u.info.u.trace.idx = idx;

    set_xen_guest_handle(sysctl.u.xsplice.u.info.u.trace.info, info);

    rc = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, info);

    return rc;
}

int xc_xsplice_trace_clear(xc_interface *xch)
{
    DECLARE_SYSCTL;

    sysctl.cmd = XEN_SYSCTL_xsplice_op;
    sysctl.u.xsplice.cmd = XEN_SYSCTL_XSPLICE_INFO;

    sysctl.u.xsplice.u.info.cmd = XEN_SYSCTL_XSPLICE_INFO_TRACE_CLEAR;
    sysctl.u.xsplice.u.info._pad = 0;

    return do_sysctl(xch, &sysctl);
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
