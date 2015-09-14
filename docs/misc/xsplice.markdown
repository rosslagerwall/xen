# xSplice Design v1

## Rationale

A mechanism is required to binarily patch the running hypervisor with new
opcodes that have come about due to primarily security updates.

This document describes the design of the API that would allow us to
upload to the hypervisor binary patches.

The document is split in four sections:

 * Detailed descriptions of the problem statement.
 * Design of the data structures.
 * Design of the hypercalls.
 * Implementation notes that should be taken into consideration.


## Glossary

 * splice - patch in the binary code with new opcodes
 * trampoline - a jump to a new instruction.
 * payload - telemetries of the old code along with binary blob of the new
   function (if needed).
 * reloc - telemetries contained in the payload to construct proper trampoline.

## History

The document has gone under various reviews and only covers v1 design.

The end of the document has a section titled `Not Yet Done` which
outlines ideas and design for the v2 version of this work.

## Multiple ways to patch

The mechanism needs to be flexible to patch the hypervisor in multiple ways
and be as simple as possible. The compiled code is contiguous in memory with
no gaps - so we have no luxury of 'moving' existing code and must either
insert a trampoline to the new code to be executed - or only modify in-place
the code if there is sufficient space. The placement of new code has to be done
by hypervisor and the virtual address for the new code is allocated dynamically.

This implies that the hypervisor must compute the new offsets when splicing
in the new trampoline code. Where the trampoline is added (inside
the function we are patching or just the callers?) is also important.

To lessen the amount of code in hypervisor, the consumer of the API
is responsible for identifying which mechanism to employ and how many locations
to patch. Combinations of modifying in-place code, adding trampoline, etc
has to be supported. The API should allow read/write any memory within
the hypervisor virtual address space.

We must also have a mechanism to query what has been applied and a mechanism
to revert it if needed.

## Workflow

The expected workflows of higher-level tools that manage multiple patches
on production machines would be:

 * The first obvious task is loading all available / suggested
   hotpatches around system start.
 * Whenever new hotpatches are installed, they should be loaded too.
 * One wants to query which modules have been loaded at runtime.
 * If unloading is deemed safe (see unloading below), one may want to
   support a workflow where a specific hotpatch is marked as bad and
   unloaded.
 * If we do no restrict module activation order and want to report tboot
   state on sequences, we might have a complexity explosion problem, in
   what system hashes should be considered acceptable.

## Patching code

The first mechanism to patch that comes in mind is in-place replacement.
That is replace the affected code with new code. Unfortunately the x86
ISA is variable size which places limits on how much space we have available
to replace the instructions. That is not a problem if the change is smaller
than the original opcode and we can fill it with nops. Problems will
appear if the replacement code is longer.

The second mechanism is by replacing the call or jump to the
old function with the address of the new function.

A third mechanism is to add a jump to the new function at the
start of the old function.

### Example of trampoline and in-place splicing

As example we will assume the hypervisor does not have XSA-132 (see
*domctl/sysctl: don't leak hypervisor stack to toolstacks*
4ff3449f0e9d175ceb9551d3f2aecb59273f639d) and we would like to binary patch
the hypervisor with it. The original code looks as so:

<pre>
   48 89 e0                  mov    %rsp,%rax  
   48 25 00 80 ff ff         and    $0xffffffffffff8000,%rax  
</pre>

while the new patched hypervisor would be:

<pre>
   48 c7 45 b8 00 00 00 00   movq   $0x0,-0x48(%rbp)  
   48 c7 45 c0 00 00 00 00   movq   $0x0,-0x40(%rbp)  
   48 c7 45 c8 00 00 00 00   movq   $0x0,-0x38(%rbp)  
   48 89 e0                  mov    %rsp,%rax  
   48 25 00 80 ff ff         and    $0xffffffffffff8000,%rax  
</pre>

This is inside the arch_do_domctl. This new change adds 21 extra
bytes of code which alters all the offsets inside the function. To alter
these offsets and add the extra 21 bytes of code we might not have enough
space in .text to squeeze this in.

As such we could simplify this problem by only patching the site
which calls arch_do_domctl:

<pre>
<do_domctl>:  
 e8 4b b1 05 00          callq  ffff82d08015fbb9 <arch_do_domctl>  
</pre>

with a new address for where the new `arch_do_domctl` would be (this
area would be allocated dynamically).

Astute readers will wonder what we need to do if we were to patch `do_domctl`
- which is not called directly by hypervisor but on behalf of the guests via
the `compat_hypercall_table` and `hypercall_table`.
Patching the offset in `hypercall_table` for `do_domctl:
(ffff82d080103079 <do_domctl>:)
<pre>

 ffff82d08024d490:   79 30  
 ffff82d08024d492:   10 80 d0 82 ff ff   

</pre>
with the new address where the new `do_domctl` is possible. The other
place where it is used is in `hvm_hypercall64_table` which would need
to be patched in a similar way. This would require an in-place splicing
of the new virtual address of `arch_do_domctl`.

In summary this example patched the callee of the affected function by
 * allocating memory for the new code to live in,
 * changing the virtual address in all the functions which called the old
   code (computing the new offset, patching the callq with a new callq).
 * changing the function pointer tables with the new virtual address of
   the function (splicing in the new virtual address). Since this table
   resides in the .rodata section we would need to temporarily change the
   page table permissions during this part.


However it has severe drawbacks - the safety checks which have to make sure
the function is not on the stack - must also check every caller. For some
patches this could mean - if there were an sufficient large amount of
callers - that we would never be able to apply the update.

### Example of different trampoline patching.

An alternative mechanism exists where we can insert a trampoline in the
existing function to be patched to jump directly to the new code. This
lessens the locations to be patched to one but it puts pressure on the
CPU branching logic (I-cache, but it is just one unconditional jump).

For this example we will assume that the hypervisor has not been compiled
with fe2e079f642effb3d24a6e1a7096ef26e691d93e (XSA-125: *pre-fill structures
for certain HYPERVISOR_xen_version sub-ops*) which mem-sets an structure
in `xen_version` hypercall. This function is not called **anywhere** in
the hypervisor (it is called by the guest) but referenced in the
`compat_hypercall_table` and `hypercall_table` (and indirectly called
from that). Patching the offset in `hypercall_table` for the old
`do_xen_version` (ffff82d080112f9e <do_xen_version>)

</pre>
 ffff82d08024b270 <hypercall_table>  
 ...  
 ffff82d08024b2f8:   9e 2f 11 80 d0 82 ff ff  

</pre>
with the new address where the new `do_xen_version` is possible. The other
place where it is used is in `hvm_hypercall64_table` which would need
to be patched in a similar way. This would require an in-place splicing
of the new virtual address of `do_xen_version`.

An alternative solution would be to patch insert a trampoline in the
old `do_xen_version' function to directly jump to the new `do_xen_version`.

<pre>
 ffff82d080112f9e <do_xen_version>:  
 ffff82d080112f9e:       48 c7 c0 da ff ff ff    mov    $0xffffffffffffffda,%rax  
 ffff82d080112fa5:       83 ff 09                cmp    $0x9,%edi  
 ffff82d080112fa8:       0f 87 24 05 00 00       ja     ffff82d0801134d2 <do_xen_version+0x534>  
</pre>

with:

<pre>
 ffff82d080112f9e <do_xen_version>:  
 ffff82d080112f9e:       e9 XX YY ZZ QQ          jmpq   [new do_xen_version]  
</pre>

which would lessen the amount of patching to just one location.

In summary this example patched the affected function to jump to the
new replacement function which required:
 * allocating memory for the new code to live in,
 * inserting trampoline with new offset in the old function to point to the
   new function.
 * Optionally we can insert in the old function a trampoline jump to an function
   providing an BUG_ON to catch errant code.

The disadvantage of this are that the unconditional jump will consume a small
I-cache penalty. However the simplicity of the patching and higher chance
of passing safety checks make this a worthwhile option.

### Security

With this method we can re-write the hypervisor - and as such we **MUST** be
diligent in only allowing certain guests to perform this operation.

Furthermore with SecureBoot or tboot, we **MUST** also verify the signature
of the payload to be certain it came from a trusted source and integrity
was intact.

As such the hypercall **MUST** support an XSM policy to limit what the guest
is allowed to invoke. If the system is booted with signature checking the
signature checking will be enforced.

## Design of payload format

The payload **MUST** contain enough data to allow us to apply the update
and also safely reverse it. As such we **MUST** know:

 * The locations in memory to be patched. This can be determined dynamically
   via symbols or via virtual addresses.
 * The new code that will be patched in.
 * Signature to verify the payload.

This binary format can be constructed using an custom binary format but
there are severe disadvantages of it:

 * The format might need to be changed and we need an mechanism to accommodate
   that.
 * It has to be platform agnostic.
 * Easily constructed using existing tools.

As such having the payload in an ELF file is the sensible way. We would be
carrying the various sets of structures (and data) in the ELF sections under
different names and with definitions. The prefix for the ELF section name
would always be: *.xsplice* to match up to the names of the structures.

Note that every structure has padding. This is added so that the hypervisor
can re-use those fields as it sees fit.

Earlier design attempted to ineptly explain the relations of the ELF sections
to each other without using proper ELF mechanism (sh_info, sh_link, data
structures using Elf types, etc). This design will explain in detail
the structures and how they are used together and not dig in the ELF
format - except mention that the section names should match the
structure names.

The xSplice payload is a relocatable ELF binary. A typical binary would have:

 * One or more .text sections
 * Zero or more read-only data sections
 * Zero or more data sections
 * Relocations for each of these sections

It may also have some architecture-specific sections. For example:

 * Alternatives instructions
 * Bug frames
 * Exception tables
 * Relocations for each of these sections

The xSplice core code loads the payload as a standard ELF binary, relocates it
and handles the architecture-specifc sections as needed. This process is much
like what the Linux kernel module loader does. It contains no xSplice-specific
details and thus will not be discussed further.

Importantly, the payload also contains a section with an array of structures
describing the functions to be patched:
<pre>
struct xsplice_patch_func {
    unsigned long new_addr;
    unsigned long new_size;
    unsigned long old_addr;
    unsigned long old_size;
    char *name;
    uint8_t pad[64];
};
<pre>

* `old_addr` is the address of the function to be patched and is filled in at
  compile time if the payload is statically linked and at run time if the
  payload is dynamically linked.
* `new_addr` is the address of the function that is replacing the old
  function. The address is filled in during relocation.
* `old_size` and `new_size` contain the sizes of the respective functions.
* `name` is used for looking up the old function address during dynamic
  linking.

The size of the `xsplice_patch_func` array is determined from the ELF section
size.

During patch apply, for each `xsplice_patch_func`, the core code inserts a
trampoline at `old_addr` to `new_addr`. During patch revert, for each
`xsplice_patch_func`, the core code copies the data from the undo buffer to
`old_addr`.

## Hypercalls

We will employ the sub operations of the system management hypercall (sysctl).
There are to be four sub-operations:

 * upload the payloads.
 * listing of payloads summary uploaded and their state.
 * getting an particular payload summary and its state.
 * command to apply, delete, or revert the payload.

Most of the actions are asynchronous therefore the caller is responsible
to verify that it has been applied properly by retrieving the summary of it
and verifying that there are no error codes associated with the payload.

We **MUST** make some of them asynchronous due to the nature of patching
it requires every physical CPU to be lock-step with each other.
The patching mechanism while an implementation detail, is not an short
operation and as such the design **MUST** assume it will be an long-running
operation.

The sub-operations will spell out how preemption is to be handled (if at all).

Furthermore it is possible to have multiple different payloads for the same
function. As such an unique id per payload has to be visible to allow proper manipulation.

The hypercall is part of the `xen_sysctl`. The top level structure contains
one uint32_t to determine the sub-operations:

<pre>
struct xen_sysctl_xsplice_op {  
    uint32_t cmd;  
	union {  
          ... see below ...  
        } u;  
};  

</pre>
while the rest of hypercall specific structures are part of the this structure.

### Basic type: struct xen_xsplice_id

Most of the hypercalls employ an shared structure called `struct xen_xsplice_id`
which contains:

 * `name` - pointer where the string for the id is located.
 * `size` - the size of the string
 * `_pad` - padding - to be zero.

The structure is as follow:

<pre>
#define XEN_XSPLICE_NAME_SIZE 128
struct xen_xsplice_id {  
    XEN_GUEST_HANDLE_64(char) name;         /* IN, pointer to name. */  
    uint32_t    size;                       /* IN, size of name. May be upto   
                                               XEN_XSPLICE_NAME_SIZE. */  
    uint32_t    _pad;  
};  
</pre>
### XEN_SYSCTL_XSPLICE_UPLOAD (0)

Upload a payload to the hypervisor. The payload is verified
against basic checks and if there are any issues the proper return code
will be returned. The payload is not applied at this time - that is
controlled by *XEN_SYSCTL_XSPLICE_ACTION*.

The caller provides:

 * A `struct xen_xsplice_id` called `id` which has the unique id.
 * `size` the size of the ELF payload (in bytes).
 * `payload` the virtual address of where the ELF payload is.

The `id` could be an UUID in mind that stays fixed forever for a given
hotpatch. It can be embedded into the Elf payload at creation time
and extracted by tools.

The return value is zero if the payload was succesfully uploaded.
Otherwise an XEN_EXX return value is provided. Duplicate `id` are not supported.
The payload at this point is verified against the basic checks.

The `payload` is the ELF payload as mentioned in the `Payload format` section.

The structure is as follow:

<pre>
struct xen_sysctl_xsplice_upload {  
    xen_xsplice_id_t id;        /* IN, name of the patch. */  
    uint64_t size;              /* IN, size of the ELF file. */
    XEN_GUEST_HANDLE_64(uint8) payload; /* IN: ELF file. */  
}; 
</pre>

### XEN_SYSCTL_XSPLICE_GET (1)

Retrieve an status of an specific payload. This caller provides:

 * A `struct xen_xsplice_id` called `id` which has the unique id.
 * A `struct xen_xsplice_status` structure which has all members
   set to zero: That is:
   * `status` *MUST* be set to zero.
   * `rc` *MUST* be set to zero.

Upon completion the `struct xen_xsplice_status` is updated.

 * `status` - whether it has been:
   * *XSPLICE_STATUS_LOADED* (0x1) has been loaded.
   * *XSPLICE_STATUS_CHECKED*  (0x2) the ELF payload safety checks passed.
   * *XSPLICE_STATUS_APPLIED* (0x4) loaded, checked, and applied.
   *  Negative values is an error. The error would be of XEN_EXX format.
 * `rc` - XEN_EXX type errors encountered while performing the `status`
   operation. The expected values are zero and XEN_EAGAIN which
   respectively mean: success and operation in progress.

The return value is zero on success and XEN_EXX on failure. This operation
is synchronous and does not require preemption.

The structure is as follow:

<pre>
struct xen_xsplice_status {  
#define XSPLICE_STATUS_LOADED       0x01  
#define XSPLICE_STATUS_CHECKED      0x02  
#define XSPLICE_STATUS_APPLIED      0x04  
	int32_t status;                 /* OUT: XSPLICE_STATE_*. IN: MUST be zero. */  
    uint32_t rc;                    /* OUT: 0 if no error, otherwise -XEN_EXX. */  
                                    /* IN: MUST be zero. */
};  

struct xen_sysctl_xsplice_summary {  
    xen_xsplice_id_t    id;         /* IN, the name of the payload. */  
    xen_xsplice_status_t status;    /* IN/OUT: status of the payload. */  
};  
</pre>

### XEN_SYSCTL_XSPLICE_LIST (2)

Retrieve an array of abbreviated status and names of payloads that are loaded in the
hypervisor.

The caller provides:

 * `version`. Initially (on first hypercall) *MUST* be zero.
 * `idx` index iterator. On first call *MUST* be zero, subsequent calls varies.
 * `nr` the max number of entries to populate.
 * `_pad` - *MUST* be zero.
 * `status` virtual address of where to write `struct xen_xsplice_status`
   structures. *MUST* allocate up to `nr` of them.
 * `id` - virtual address of where to write the unique id of the payload.
   *MUST* allocate up to `nr` of them. Each *MUST* be of
   **XEN_XSPLICE_NAME_SIZE** size.
 * `len` - virtual address of where to write the length of each unique id
   of the payload. *MUST* allocate up to `nr` of them. Each *MUST* be
   of sizeof(uint32_t) (4 bytes).

If the hypercall returns an positive number, it is the number (up to `nr`)
of the payloads returned, along with `nr` updated with the number of remaining
payloads, `version` updated (it may be the same across hypercalls. If it
varies the data is stale and further calls could fail). The `status`,
`id`, and `len`' are updated at their designed index value (`idx`) with
the returned value of data.

If the hypercall returns E2BIG the `count` is too big and should be
lowered.

This operation can be preempted by the hypercall returning EAGAIN.
Retry.

Note that due to the asynchronous nature of hypercalls the domain might have
added or removed the number of payloads making this information stale. It is
the responsibility of the toolstack to use the `version` field to check
between each invocation. if the version differs it should discard the stale
data and start from scratch. It is OK for the toolstack to use the new
`version` field.

The `struct xen_xsplice_status` structure contains an status of payload which includes:

 * `status` - whether it has been:
   * *XSPLICE_STATUS_LOADED* (0x1) has been loaded.
   * *XSPLICE_STATUS_CHECKED*  (0x2) the ELF payload safety checks passed.
   * *XSPLICE_STATUS_APPLIED* (0x4) loaded, checked, and applied.
 * `rc` - XEN_EXX type errors encountered while performing the `status`
   operation. The expected values are zero and XEN_EAGAIN which
   respectively mean: success and operation in progress.

The structure is as follow:

<pre>
struct xen_sysctl_xsplice_list {  
    uint32_t version;                       /* IN/OUT: Initially *MUST* be zero.  
                                               On subsequent calls reuse value.  
                                               If varies between calls, we are  
                                             * getting stale data. */  
    uint32_t idx;                           /* IN/OUT: Index into array. */  
    uint32_t nr;                            /* IN: How many status, id, and len  
                                               should populate.  
                                               OUT: How many payloads left. */  
    uint32_t _pad;                          /* IN: Must be zero. */  
    XEN_GUEST_HANDLE_64(xen_xsplice_status_t) status;  /* OUT. Must have enough  
                                               space allocate for n of them. */  
    XEN_GUEST_HANDLE_64(char) id;           /* OUT: Array of ids. Each member  
                                               MUST XEN_XSPLICE_NAME_SIZE in size.  
                                               Must have n of them. */  
    XEN_GUEST_HANDLE_64(uint32) len;        /* OUT: Array of lengths of ids.  
                                               Must have n of them. */  
};  
</pre>

### XEN_SYSCTL_XSPLICE_ACTION (3)

Perform an operation on the payload structure referenced by the `id` field.
The operation request is asynchronous and the status should be retrieved
by using either **XEN_SYSCTL_XSPLICE_GET** or **XEN_SYSCTL_XSPLICE_LIST** hypercall.
If the operation fails more details on the operation can be retrieved via
**XEN_SYSCTL_XSPLICE_INFO** hypercall.

The caller provides:

 * A 'struct xen_xsplice_id` `id` containing the unique id.
 * `cmd` the command requested:
  * *XSPLICE_ACTION_CHECK* (1) check that the payload will apply properly.
    This also verfies the payload - which may require SecureBoot firmware
    calls.
  * *XSPLICE_ACTION_UNLOAD* (2) unload the payload.
   Any further hypercalls against the `id` will result in failure unless
   **XEN_SYSCTL_XSPLICE_UPLOAD** hypercall is perfomed with same `id`.
  * *XSPLICE_ACTION_REVERT* (3) revert the payload. If the operation takes
  more time than the upper bound of time the `status` will XEN_EBUSY.
  * *XSPLICE_ACTION_APPLY* (4) apply the payload. If the operation takes
  more time than the upper bound of time the `status` will be XEN_EBUSY.
  * *XSPLICE_ACTION_REPLACE* (5) revert all applied payloads and apply this
  payload.
  * *XSPLICE_ACTION_LOADED* is an initial state and cannot be requested.
 * `time` the upper bound of time the cmd should take. Zero means infinite.
   If within the time the operation does not succeed the operation would go in
   error state.
 * `_pad` - *MUST* be zero.

The return value will be zero unless the provided fields are incorrect.

The structure is as follow:

<pre>
#define XSPLICE_ACTION_CHECK   1  
#define XSPLICE_ACTION_UNLOAD  2  
#define XSPLICE_ACTION_REVERT  3  
#define XSPLICE_ACTION_APPLY   4  
#define XSPLICE_ACTION_REPLACE 5  
struct xen_sysctl_xsplice_action {  
    xen_xsplice_id_t id;                    /* IN, name of the patch. */  
    uint32_t cmd;                           /* IN: XSPLICE_ACTION_* */  
    uint32_t _pad;                          /* IN: MUST be zero. */  
    uint64_t time;                          /* IN: Zero if no timeout. */ 
                                            /* Or upper bound of time (ms) */   
                                            /* for operation to take. */  
};  

</pre>

## State diagrams of XSPLICE_ACTION values.

There is a strict ordering state of what the commands can be.
The XSPLICE_ACTION prefix has been dropped to easy reading:

<pre>
              /->\
              \  /
 UNLOAD <--- CHECK ---> REPLACE|APPLY --> REVERT --\
                \                                  |
                 \-------------------<-------------/

</pre>
Or an state transition table of valid states:

<pre>

+-------+-------+--------+--------+--------+---------+-------+------------------+  
| CHECK | APPLY | REPLACE| REVERT | UNLOAD | Current | Next  | Result           |  
+-------+-------+--------+--------+--------+---------+-------+------------------+  
|   x   |       |        |        |        | CHECK   | CHECK | Check payload.   |  
+-------+-------+--------+--------+--------+---------+-------+------------------+  
|   x   |       |        |        |        | LOADED  | CHECK | Check payload.   |  
+-------+-------+--------+--------+--------+---------+-------+------------------+  
|       |       |        |        |   x    | CHECK   | UNLOAD| Unload payload.  |  
+-------+-------+--------+--------+--------+---------+-------+------------------+  
|       |   x   |        |        |        | CHECK   | APPLY | Apply payload.   |  
+-------+-------+--------+--------+--------+---------+-------+------------------+  
|       |       |   x    |        |        | CHECK   | APPLY | Apply payload..  |  
+-------+-------+--------+--------+--------+---------+-------+------------------+  
|       |       |        |    x   |        | REVERT  | CHECK | Revert payload.  |  
+-------+-------+--------+--------+--------+---------+-------+------------------+  
</pre>
All the other state transitions are invalid.

## Sequence of events.

The normal sequence of events is to:

 1. *XEN_SYSCTL_XSPLICE_UPLOAD* to upload the payload. If there are errors *STOP* here.
 2. *XEN_SYSCTL_XSPLICE_GET* to check the `->rc`. If *XEN_EAGAIN* spin. If zero go to next step.
 3. *XEN_SYSCTL_XSPLICE_ACTION* with *XSPLICE_ACTION_CHECK* command to verify that the payload can be succesfully applied.
 4. *XEN_SYSCTL_XSPLICE_GET* to check the `->rc`. If *XEN_EAGAIN* spin. If zero go to next step.
 5. *XEN_SYSCTL_XSPLICE_ACTION* with *XSPLICE_ACTION_APPLY* to apply the patch.
 6. *XEN_SYSCTL_XSPLICE_GET* to check the `->rc`. If in *XEN_EAGAIN* spin. If zero exit with success.

 
## Addendum

Implementation quirks should not be discussed in a design document.

However these observations can provide aid when developing against this
document.


### Alternative assembler

Alternative assembler is a mechanism to use different instructions depending
on what the CPU supports. This is done by providing multiple streams of code
that can be patched in - or if the CPU does not support it - padded with
`nop` operations. The alternative assembler macros cause the compiler to
expand the code to place a most generic code in place - emit a special
ELF .section header to tag this location. During run-time the hypervisor
can leave the areas alone or patch them with an better suited opcodes.


### When to patch

During the discussion on the design two candidates bubbled where
the call stack for each CPU would be deterministic. This would
minimize the chance of the patch not being applied due to safety
checks failing.

#### Rendezvous code instead of stop_machine for patching

The hypervisor's time rendezvous code runs synchronously across all CPUs
every second. Using the stop_machine to patch can stall the time rendezvous
code and result in NMI. As such having the patching be done at the tail
of rendezvous code should avoid this problem.

However the entrance point for that code is
do_softirq->timer_softirq_action->time_calibration
which ends up calling on_selected_cpus on remote CPUs.

The remote CPUs receive CALL_FUNCTION_VECTOR IPI and execute the
desired function.

#### Before entering the guest code.

Before we call VMXResume we check whether any soft IRQs need to be executed.
This is a good spot because all Xen stacks are effectively empty at
that point.

To randezvous all the CPUs an barrier with an maximum timeout (which
could be adjusted), combined with forcing all other CPUs through the
hypervisor with IPIs, can be utilized to have all the CPUs be lockstep.

The approach is similar in concept to stop_machine and the time rendezvous
but is time-bound. However the local CPU stack is much shorter and
a lot more deterministic.

### Compiling the hypervisor code

Hotpatch generation often requires support for compiling the target
with -ffunction-sections / -fdata-sections.  Changes would have to
be done to the linker scripts to support this.


### Generation of xSplice ELF payloads

The design of that is not discussed in this design.

The author of this design envisions objdump and objcopy along
with special GCC parameters (see above) to create .o.xsplice files
which can be used to splice an ELF with the new payload.

The ksplice or kpatching code can provide inspiration.

### Exception tables and symbol tables growth

We may need support for adapting or augmenting exception tables if
patching such code.  Hotpatches may need to bring their own small
exception tables (similar to how Linux modules support this).

If supporting hotpatches that introduce additional exception-locations
is not important, one could also change the exception table in-place
and reorder it afterwards.

### Security

Only the privileged domain should be allowed to do this operation.


# v2: Not Yet Done


## Goals

The v2 design must also have a mechanism for:

 *  An dependency mechanism for the payloads. To use that information to load:
    - The appropiate payload. To verify that payload is built against the
      hypervisor. This can be done via the `build-id` (see later sections),
      or via providing an copy of the old code - so that the hypervisor can
       verify it against the code in memory.
    - To construct an appropiate order of payloads to load in case they
      depend on each other.
 * Be able to cope with symbol names in the ELF payload.
 * Be able to patch .rodata, .bss, and .data sections.
 * Further safety checks.

### Hypervisor ID (build-id)

The build-id can help with:

  * Prevent loading of wrong hotpatches (intended for other builds)

  * Allow to identify suitable hotpatches on disk and help with runtime
    tooling (if laid out using build ID)

The build-id (aka hypervisor id) can be easily obtained by utilizing
the ld --build-id operatin which (copied from ld):

<pre>
--build-id  
    --build-id=style  
        Request creation of ".note.gnu.build-id" ELF note section.  The contents of the note are unique bits identifying this  
        linked file.  style can be "uuid" to use 128 random bits, "sha1" to use a 160-bit SHA1 hash on the normative parts of the  
        output contents, "md5" to use a 128-bit MD5 hash on the normative parts of the output contents, or "0xhexstring" to use a  
        chosen bit string specified as an even number of hexadecimal digits ("-" and ":" characters between digit pairs are  
        ignored).  If style is omitted, "sha1" is used.  

        The "md5" and "sha1" styles produces an identifier that is always the same in an identical output file, but will be  
        unique among all nonidentical output files.  It is not intended to be compared as a checksum for the file's contents.  A  
        linked file may be changed later by other tools, but the build ID bit string identifying the original linked file does  
        not change.  

        Passing "none" for style disables the setting from any "--build-id" options earlier on the command line.  

</pre>


### xSplice interdependencies

xSplice patches interdependencies are tricky.

There are the ways this can be addressed:
 * A single large patch that subsumes and replaces all previous ones.
   Over the life-time of patching the hypervisor this large patch
   grows to accumulate all the code changes.
 * Hotpatch stack - where an mechanism exists that loads the hotpatches
   in the same order they were built in. We would need an build-id
   of the hypevisor to make sure the hot-patches are build against the
   correct build.
 * Payload containing the old code to check against that. That allows
   the hotpatches to be loaded indepedently (if they don't overlap) - or
   if the old code also containst previously patched code - even if they
   overlap.

The disadvantage of the first large patch is that it can grow over
time and not provide an bisection mechanism to identify faulty patches.

The hot-patch stack puts stricts requirements on the order of the patches
being loaded and requires an hypervisor build-id to match against.

The old code allows much more flexibility and an additional guard,
but is more complex to implement.

### Symbol names


Xen as it is now, has a couple of non-unique symbol names which will
make runtime symbol identification hard.  Sometimes, static symbols
simply have the same name in C files, sometimes such symbols get
included via header files, and some C files are also compiled
multiple times and linked under different names (guest_walk.c).

As such we need to modify the linker to make sure that the symbol
table qualifies also symbols by their source file name.

For the awkward situations in which C-files are compiled multiple
times patches we would need to some modification in the Xen code.


The convention for file-type symbols (that would allow to map many
symbols to their compilation unit) says that only the basename (i.e.,
without directories) is embedded.  This creates another layer of
confusion for duplicate file names in the build tree.

That would have to be resolved.

<pre>
> find . -name \*.c -print0 | xargs -0 -n1 basename | sort | uniq -c | sort -n | tail -n10
      3 shutdown.c
      3 sysctl.c
      3 time.c
      3 xenoprof.c
      4 gdbstub.c
      4 irq.c
      5 domain.c
      5 mm.c
      5 pci.c
      5 traps.c
</pre>

### Handle inlined __LINE__


This problem is related to hotpatch construction
and potentially has influence on the design of the hotpatching
infrastructure in Xen.

For example:

We have file1.c with functions f1 and f2 (in that order).  f2 contains a
BUG() (or WARN()) macro and at that point embeds the source line number
into the generated code for f2.

Now we want to hotpatch f1 and the hotpatch source-code patch adds 2
lines to f1 and as a consequence shifts out f2 by two lines.  The newly
constructed file1.o will now contain differences in both binary
functions f1 (because we actually changed it with the applied patch) and
f2 (because the contained BUG macro embeds the new line number).

Without additional information, an algorithm comparing file1.o before
and after hotpatch application will determine both functions to be
changed and will have to include both into the binary hotpatch.

Options:

1. Transform source code patches for hotpatches to be line-neutral for
   each chunk.  This can be done in almost all cases with either
   reformatting of the source code or by introducing artificial
   preprocessor "#line n" directives to adjust for the introduced
   differences.

   This approach is low-tech and simple.  Potentially generated
   backtraces and existing debug information refers to the original
   build and does not reflect hotpatching state except for actually
   hotpatched functions but should be mostly correct.

2. Ignoring the problem and living with artificially large hotpatches
   that unnecessarily patch many functions.

   This approach might lead to some very large hotpatches depending on
   content of specific source file.  It may also trigger pulling in
   functions into the hotpatch that cannot reasonable be hotpatched due
   to limitations of a hotpatching framework (init-sections, parts of
   the hotpatching framework itself, ...) and may thereby prevent us
   from patching a specific problem.

   The decision between 1. and 2. can be made on a patch--by-patch
   basis.

3. Introducing an indirection table for storing line numbers and
   treating that specially for binary diffing. Linux may follow
   this approach.

   We might either use this indirection table for runtime use and patch
   that with each hotpatch (similarly to exception tables) or we might
   purely use it when building hotpatches to ignore functions that only
   differ at exactly the location where a line-number is embedded.

Similar considerations are true to a lesser extent for __FILE__, but it
could be argued that file renaming should be done outside of hotpatches.

## Signature checking requirements.

The signature checking requires that the layout of the data in memory
**MUST** be same for signature to be verified. This means that the payload
data layout in ELF format **MUST** match what the hypervisor would be
expecting such that it can properly do signature verification.

The signature is based on the all of the payloads continuously laid out
in memory. The signature is to be appended at the end of the ELF payload
prefixed with the string '~Module signature appended~\n', followed by
an signature header then followed by the signature, key identifier, and signers
name.

Specifically the signature header would be:

<pre>
#define PKEY_ALGO_DSA       0  
#define PKEY_ALGO_RSA       1  

#define PKEY_ID_PGP         0 /* OpenPGP generated key ID */  
#define PKEY_ID_X509        1 /* X.509 arbitrary subjectKeyIdentifier */  

#define HASH_ALGO_MD4          0  
#define HASH_ALGO_MD5          1  
#define HASH_ALGO_SHA1         2  
#define HASH_ALGO_RIPE_MD_160  3  
#define HASH_ALGO_SHA256       4  
#define HASH_ALGO_SHA384       5  
#define HASH_ALGO_SHA512       6  
#define HASH_ALGO_SHA224       7  
#define HASH_ALGO_RIPE_MD_128  8  
#define HASH_ALGO_RIPE_MD_256  9  
#define HASH_ALGO_RIPE_MD_320 10  
#define HASH_ALGO_WP_256      11  
#define HASH_ALGO_WP_384      12  
#define HASH_ALGO_WP_512      13  
#define HASH_ALGO_TGR_128     14  
#define HASH_ALGO_TGR_160     15  
#define HASH_ALGO_TGR_192     16  


struct elf_payload_signature {  
	u8	algo;		/* Public-key crypto algorithm PKEY_ALGO_*. */  
	u8	hash;		/* Digest algorithm: HASH_ALGO_*. */  
	u8	id_type;	/* Key identifier type PKEY_ID*. */  
	u8	signer_len;	/* Length of signer's name */  
	u8	key_id_len;	/* Length of key identifier */  
	u8	__pad[3];  
	__be32	sig_len;	/* Length of signature data */  
};

</pre>
(Note that this has been borrowed from Linux module signature code.).


### .rodata sections

The patching might require strings to be updated as well. As such we must be
also able to patch the strings as needed. This sounds simple - but the compiler
has a habit of coalescing strings that are the same - which means if we in-place
alter the strings - other users will be inadvertently affected as well.

This is also where pointers to functions live - and we may need to patch this
as well. And switch-style jump tables.

To guard against that we must be prepared to do patching similar to
trampoline patching or in-line depending on the flavour. If we can
do in-line patching we would need to:

 * alter `.rodata` to be writeable.
 * inline patch.
 * alter `.rodata` to be read-only.

If are doing trampoline patching we would need to:

 * allocate a new memory location for the string.
 * all locations which use this string will have to be updated to use the
   offset to the string.
 * mark the region RO when we are done.

### .bss and .data sections.

Patching writable data is not suitable as it is unclear what should be done
depending on the current state of data. As such it should not be attempted.


### Patching code which is in the stack.

We should not patch the code which is on the stack. That can lead
to corruption.

### Inline patching

The hypervisor should verify that the in-place patching would fit within
the code or data.

### Trampoline (e9 opcode)

The e9 opcode used for jmpq uses a 32-bit signed displacement. That means
we are limited to up to 2GB of virtual address to place the new code
from the old code. That should not be a problem since Xen hypervisor has
a very small footprint.

However if we need - we can always add two trampolines. One at the 2GB
limit that calls the next trampoline.

Please note there is a small limitation for trampolines in
function entries: The target function (+ trailing padding) must be able
to accomodate the trampoline. On x86 with +-2 GB relative jumps,
this means 5 bytes are  required.

Depending on compiler settings, there are several functions in Xen that
are smaller (without inter-function padding).

<pre> 
readelf -sW xen-syms | grep " FUNC " | \
    awk '{ if ($3 < 5) print $3, $4, $5, $8 }'

...
3 FUNC LOCAL wbinvd_ipi
3 FUNC LOCAL shadow_l1_index
...
</pre>
A compile-time check for, e.g., a minimum alignment of functions or a
runtime check that verifies symbol size (+ padding to next symbols) for
that in the hypervisor is advised.

