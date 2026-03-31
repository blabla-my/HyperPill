# Nested VMX Behavior: Guest KVM vs Guest VBox Under HyperPill

## Scope

This note describes the difference between:

- `L0 = HyperPill/Bochs`
- `L1 = guest KVM` or `L1 = guest VirtualBox`
- `L2 = the nested guest`

The goal is to explain why the same HyperPill-side edit of VMCS exit
fields can look "handled" by guest KVM but not by guest VBox.

## First invariant: a real L2 VM-exit always goes to L0 first

For both guest KVM and guest VBox:

`L2 -> L0 -> reflected/emulated for L1`

There is no real path of:

`L2 -> L1 -> L0`

because L1 itself is running under L0's VMX implementation.

So the core difference is not the direction of the real exit. The core
difference is how the L1 hypervisor models nested VMX state and when it
consumes that state.

## Where HyperPill stops execution

HyperPill stops at the pre-entry point, before the real nested
`VMLAUNCH/VMRESUME` body runs.

From `vendor/bochs/cpu/vmx.cc`:

```c++
void BX_CPP_AttrRegparmN(1) BX_CPU_C::VMLAUNCH(bxInstruction_c *i)
{
    if(fuzz_hook_vmlaunch(BX_CPU_ID)) {
        BX_NEXT_TRACE(i);
        return;
    }
```

From `feedback.cc`:

```c++
bool fuzz_hook_vmlaunch(unsigned cpu) {
	printf("Vmlaunch:%lx\n", BX_CPU(cpu)->vmcsptr);
	log_vmentry_event(cpu);
	if (drain_active())
		return false;
	if (vmcs_addr == BX_CPU(cpu)->vmcsptr) {
		pause_cpu();
		return true;
	}
```

This means:

1. L1 has already handled some previous real nested exit.
2. L1 is now about to enter L2 again.
3. HyperPill pauses before the actual nested entry happens.

So when `inject_write()` runs, it is not running "inside a pending
VM-exit handler". It runs in the gap between:

- the previous nested exit already finished
- the next nested entry has not happened yet

## What `inject_write()` really changes

From `fuzz.cc`:

```c++
bool inject_write(bx_address addr, int size, uint64_t val) {
	printf("Try to write instruction to %lx\n",
	       BX_CPU(0)->VMread64(VMCS_GUEST_RIP));
	BX_CPU(0)->VMwrite64(VMCS_64BIT_GUEST_PHYSICAL_ADDR, addr);
	uint32_t exit_reason =
		vmcs_translate_guest_physical_ept(addr, NULL, NULL);
	if (!exit_reason)
		return false;
	BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, exit_reason);

	if (exit_reason == VMX_VMEXIT_EPT_VIOLATION)
		BX_CPU(0)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, 2);

	BX_CPU(0)->set_reg64(BX_64BIT_REG_RDX, addr);
	BX_CPU(0)->set_reg64(BX_64BIT_REG_RAX, val);
```

This mixes two different things:

1. Exit metadata

- `VMCS_64BIT_GUEST_PHYSICAL_ADDR = addr`
- `VMCS_32BIT_VMEXIT_REASON = ...`
- `VMCS_VMEXIT_QUALIFICATION = ...`

2. Real guest instruction state

- `RDX = addr`
- later the patched instruction becomes a normal store such as
  `mov [rdx], eax` or `mov [rdx], rax`

Important consequence:

- the VMCS fields above do not queue a new VM-exit for L1 to handle
- they only describe what a nested exit should look like if or when a
  real nested run causes one later

## Guest KVM as L1

Guest KVM has a software nested-VMX model around `vmcs12`.

### KVM consumes nested state on `VMRESUME`

From Linux KVM `arch/x86/kvm/vmx/nested.c`:

```c
vmcs12 = get_vmcs12(vcpu);

if (CC(vmcs12->hdr.shadow_vmcs))
	return nested_vmx_failInvalid(vcpu);

if (evmptr_is_valid(vmx->nested.hv_evmcs_vmptr)) {
	copy_enlightened_to_vmcs12(vmx, vmx->nested.hv_evmcs->hv_clean_fields);
	vmcs12->launch_state = !launch;
} else if (enable_shadow_vmcs) {
	copy_shadow_to_vmcs12(vmx);
}

if (nested_vmx_check_controls(vcpu, vmcs12))
	return nested_vmx_fail(vcpu, VMXERR_ENTRY_INVALID_CONTROL_FIELD);

status = nested_vmx_enter_non_root_mode(vcpu, true);
```

This is the `nested_vmx_run()` path used by guest KVM's emulated
`VMLAUNCH/VMRESUME`.

The key point is that KVM consumes its software nested state before
entering L2.

### KVM reflects the exit back into `vmcs12`

Also from `nested.c`:

```c
if (likely(!vmx->fail)) {
	sync_vmcs02_to_vmcs12(vcpu, vmcs12);

	if (vm_exit_reason != -1)
		prepare_vmcs12(vcpu, vmcs12, vm_exit_reason,
			       exit_intr_info, exit_qualification);
}
```

So on a real L2 exit, KVM:

1. syncs state back from its internal VMCS to `vmcs12`
2. writes exit reason and qualification into `vmcs12`
3. returns to L1

### Why this tends to cooperate better with HyperPill

Guest KVM is software-heavy in its nested entry and exit path:

- it has an explicit `vmcs12`
- it consumes nested state on every nested entry
- it prepares reflected exit state in software on every nested exit

So if HyperPill edits nested state near guest KVM's `VMRESUME`, guest
KVM is more likely to observe something meaningful on the next nested
entry and exit cycle.

This does not mean KVM skips the real `L2 -> L0 -> L1` ordering. It
means guest KVM's `L1 VMRESUME` path is a software path that actively
consumes the nested VMX model.

## Guest VBox as L1

Guest VBox does not behave like guest KVM here.

### VBox's HM loop is "run, handle, immediately run again"

From `src/VBox/VMM/VMMR3/EMR3HM.cpp`:

```c++
/*
 * Spin till we get a forced action which returns anything but VINF_SUCCESS.
 */
for (;;)
{
    if (RT_LIKELY(emR3IsExecutionAllowed(pVM, pVCpu)))
        rc = VMMR3HmRunGC(pVM, pVCpu);

    VMCPU_FF_CLEAR_MASK(pVCpu, VMCPU_FF_RESUME_GUEST_MASK);
    if (VM_FF_IS_ANY_SET(pVM, VM_FF_HIGH_PRIORITY_POST_MASK)
        || VMCPU_FF_IS_ANY_SET(pVCpu, VMCPU_FF_HIGH_PRIORITY_POST_MASK))
        rc = VBOXSTRICTRC_TODO(emR3HighPriorityPostForcedActions(pVM, pVCpu, rc));

    if (rc >= VINF_EM_FIRST && rc <= VINF_EM_LAST)
        break;

    rc = emR3HmHandleRC(pVM, pVCpu, rc);
    if (rc != VINF_SUCCESS)
        break;
}
```

VBox's normal behavior is:

1. run guest
2. handle the result
3. if the result is fully handled, go back and run guest again

This is why VBox seems to "immediately VMRESUME again" after handling a
nested exit. That is just its normal HM inner loop.

### VBox rewrites raw VMCS guest RIP from cached guest state

From `src/VBox/VMM/VMMAll/VMXAllTemplate.cpp.h`:

```c++
static void vmxHCExportGuestRip(PVMCPUCC pVCpu)
{
    if (ASMAtomicUoReadU64(&VCPU_2_VMXSTATE(pVCpu).fCtxChanged) & HM_CHANGED_GUEST_RIP)
    {
        int rc = VMX_VMCS_WRITE_NW(pVCpu, VMX_VMCS_GUEST_RIP, pVCpu->cpum.GstCtx.rip);
        AssertRC(rc);
    }
}
```

So VBox does not treat the raw VMCS as the only source of truth. Before
entry it can export its cached `cpum.GstCtx.rip` back into the VMCS.

That explains why `VMCS_GUEST_RIP` can change from your injected
userspace RIP to a guest kernel RIP such as `asm_exc_page_fault`.

### VBox consumes `GUEST_PHYSICAL_ADDR` only after a real nested exit

From `src/VBox/VMM/VMMAll/VMXAllTemplate.cpp.h`:

```c++
vmxHCReadToTransient< ... | HMVMX_READ_GUEST_PHYSICAL_ADDR>(pVCpu, pVmxTransient);

int rc = vmxHCImportGuestState<IEM_CPUMCTX_EXTRN_MUST_MASK>(pVCpu, pVmcsInfo, __FUNCTION__);
AssertRCReturn(rc, rc);

RTGCPHYS const GCPhys    = pVmxTransient->uGuestPhysicalAddr;
uint64_t const uExitQual = pVmxTransient->uExitQual;
```

The important point is timing:

- VBox reads `GUEST_PHYSICAL_ADDR` in its nested EPT-violation handler
- that handler runs only after a real nested exit has been delivered to
  VBox

Therefore, writing `VMCS_64BIT_GUEST_PHYSICAL_ADDR` in HyperPill before
entry does not by itself cause VBox to handle an exit immediately.

## The concrete difference

### Guest KVM

Timeline:

1. Guest KVM executes `VMRESUME`
2. Guest KVM enters its software nested path `nested_vmx_run()`
3. KVM consumes `vmcs12`
4. L2 runs
5. L2 exits to L0
6. KVM reflects the exit back into `vmcs12`
7. guest KVM's `VMRESUME` returns to L1 code

### Guest VBox

Timeline:

1. Guest VBox already finished handling some previous nested exit
2. Guest VBox is about to execute `VMRESUME`
3. HyperPill stops at the pre-entry hook
4. `inject_write()` edits raw VMCS exit fields and patches the L2 code
5. HyperPill resumes execution
6. Guest VBox continues toward the next `VMRESUME`
7. Only after a real later nested run can there be a new nested exit
   for VBox to handle

So VBox is not saying "this synthetic exit was already handled". What is
already handled is the previous real exit. Your injection happens on the
way to the next entry.

## Why a guest page fault can happen before MMIO handling

The patched instruction still uses a guest linear address.

If the patched store is something like:

```asm
mov [rdx], eax
```

and `rdx = 0xf0806000`, then the CPU first performs guest virtual
translation for that linear address.

If the current guest page tables do not map that address correctly, the
result is:

1. guest `#PF`
2. guest RIP changes to the guest kernel page-fault handler
3. VBox later re-exports that RIP into `VMCS_GUEST_RIP`

This can happen before any nested EPT or MMIO exit is delivered to VBox.

## What to remember

1. The real exit direction is the same in both setups: `L2 -> L0 -> L1`.
2. The difference is the L1 implementation, not the exit direction.
3. Guest KVM has a software `vmcs12` model that is consumed on nested
   entry and updated on nested exit.
4. Guest VBox, at your current hook point, is still on the next-entry
   path. Editing raw VMCS exit fields there does not inject a
   "handle-now" nested exit.
5. Seeing `Vmlaunch:` in HyperPill logs only proves that L1 reached the
   next nested entry point. It does not prove that L2 actually ran.

## Short mental model

Use this simplified rule while debugging:

- If the L1 hypervisor has a software nested-VMX state machine
  (`vmcs12`-style), HyperPill edits near `VMRESUME` may be picked up by
  that software path.
- If the L1 hypervisor is still on a pre-entry path and also refreshes
  raw VMCS fields from its own cached guest context, then editing raw
  VMCS exit fields alone is usually not enough to force immediate nested
  exit handling.
