#include "bochs.h"
#include "config.h"
#include "cpu/cpu.h"
#include "fuzz.h"
#include "option.h"
#include "pc_system.h"
#include "sourcecov.h"
#include "syntax.h"
#include "task.h"
#include "gui/siminterface.h"
#include "param_names.h"
#include "vendor/libfuzzer-ng/FuzzerInternal.h"
#include "virtio.h"
#include <cstdint>
#include <memory>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <filesystem>
#include <vector>

namespace fuzzer {
	extern TracePC TPC;
	extern Fuzzer* F;
};

int in_timer_mode = 0;
uint64_t timer_mod[5] = {0};
bool hack_timer_mod = false;

bool master_fuzzer;
bool verbose = 1;

bool fuzz_unhealthy_input = false; /* We reached an execution timeout */
bool fuzz_do_not_continue = false; /* Don't inject new instructions. */
bool fuzz_should_abort = false;    /* We got a crash. */

bool fuzzing;
static bool executing_input;

static bool nocov = nocov_enabled();
static unsigned long int kDrainIcountBudget =
	nocov ? 5000000 * nocov_scale() : 5000000;
static constexpr size_t kDrainPredTickIntervalInitial = 1024;
static constexpr size_t kDrainPredTickIntervalMax = 100000;

static struct {
	bool active;
	drain_predicate_t pred;
	void* ctx;
	bool budget_hit;
	size_t pred_calls;
	size_t tickn_calls;
	size_t pred_tick_interval;
} drain_state = {};

void drain_begin(drain_predicate_t pred, void* ctx) {
	if (!virtio_core_enabled()) {
		drain_state.active = false;
		drain_state.pred = nullptr;
		drain_state.ctx = nullptr;
		drain_state.budget_hit = false;
		drain_state.pred_calls = 0;
		drain_state.tickn_calls = 0;
		drain_state.pred_tick_interval = 0;
		return;
	}
	drain_state.active = true;
	drain_state.pred = pred;
	drain_state.ctx = ctx;
	drain_state.budget_hit = false;
	drain_state.pred_calls = 0;
	drain_state.tickn_calls = 0;
	drain_state.pred_tick_interval = kDrainPredTickIntervalInitial;
}

DrainStats drain_end() {
	DrainStats stats = {
		.budget_hit = drain_state.budget_hit,
	};
	drain_state.active = false;
	drain_state.pred = nullptr;
	drain_state.ctx = nullptr;
	drain_state.pred_calls = 0;
	drain_state.tickn_calls = 0;
	drain_state.pred_tick_interval = 0;
	return stats;
}

bool drain_active() { return virtio_core_enabled() && drain_state.active; }

// Ensure pc_system (and its null timer) is constructed before the CPU/LAPIC.
BOCHSAPI bx_pc_system_c bx_pc_system;
#if BX_SUPPORT_SMP
BOCHSAPI BX_CPU_C **bx_cpu_array = nullptr;
BOCHSAPI Bit8u bx_cpu_count = 0;
static std::vector<BX_CPU_C> shadow_bx_cpus;
#else
BOCHSAPI BX_CPU_C bx_cpu = BX_CPU_C(0);
BOCHSAPI BX_CPU_C shadow_bx_cpu;
#endif
BOCHSAPI bx_pc_system_c shadow_bx_pc_system;
BOCHSAPI Bit64s shadow_tsc;

uint64_t vmcs_addr;
uint64_t guest_rip; /* Entrypoint. Reset after each op */

static bool log_writes;
static bool fuzzenum;

uint64_t icount_limit_floor = 200000;
uint64_t icount_limit = nocov ? 50000000 * nocov_scale() : 50000000;
uint64_t pio_icount_limit = icount_limit;

static unsigned long int icount, pio_icount;

static void dump_hex(const uint8_t *data, size_t len) {
	for (int i = 0; i < len; i++)
		printf("%02x ", data[i]);
	printf("\n");
}

static void dump_regs_cpu(unsigned cpu_id) {
	auto *cpu = BX_CPU(cpu_id);
	static const char *general_64bit_regname[17] = {
		"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8",
		"r9",  "r10", "r11", "r12", "r13", "r14", "r15", "rip"
	};
	for (int i = 0; i <= BX_GENERAL_REGISTERS; i++) {
		printf("REG%d (%s) = %016lx\n", i, general_64bit_regname[i],
		       cpu->gen_reg[i].rrx);
	}
	printf("FLAGS: %x\n", cpu->eflags);
	fflush(stdout);
	fflush(stderr);
}

void dump_regs() { dump_regs_cpu(0); }

static void dump_instr_cpu(unsigned cpu_id) {
	auto *cpu = BX_CPU(cpu_id);
	auto s = addr_to_sym(cpu->get_rip());
	printf("0x%lx<< %s %s\n", cpu->get_rip(), s.bin.c_str(),
	       s.symbol.c_str());
	cpu->debug_disasm_instruction(cpu->get_rip());
}

void dump_instr() { dump_instr_cpu(0); }

static void hp_init_cpus(unsigned int cpu_count) {
#if BX_SUPPORT_SMP
	if (bx_cpu_array)
		return;
	if (cpu_count == 0)
		cpu_count = 1;

	bx_cpu_count = static_cast<Bit8u>(cpu_count);
	bx_cpu_array = new BX_CPU_C*[cpu_count];
	for (unsigned int i = 0; i < bx_cpu_count; i++) {
		bx_cpu_array[i] = new BX_CPU_C(i);
	}
	shadow_bx_cpus.resize(cpu_count);
#else
	(void)cpu_count;
#endif
}

static void init_cpu(void) {
	for (unsigned int cpu = 0; cpu < bx_cpu_count; cpu++) {
		BX_CPU(cpu)->initialize();
		BX_CPU(cpu)->reset(BX_RESET_HARDWARE);
		BX_CPU(cpu)->sanity_checks();
	}
}

void start_cpu(bool enumerating) {
	if (fuzzing && (fuzz_unhealthy_input || fuzz_do_not_continue))
		return;

	srand(1); /* rdrand */
	if (!drain_state.active)
		BX_CPU(0)->gen_reg[BX_64BIT_REG_RIP].rrx = guest_rip;
	icount = 0;
	pio_icount = 0;
	clear_seen_dma();
	if (BX_CPU(0)->fuzztrace) {
		dump_regs();
	}
	reset_op_cov();

	for (unsigned int cpu = 0; cpu < bx_cpu_count; cpu++) {
		BX_CPU(cpu)->fuzz_executing_input = true;
	}
	if (BX_CPU(0)->fuzzdebug_gdb && !enumerating)
		hp_gdbstub_debug_loop();
	if (bx_cpu_count == 1) {
		while (BX_CPU(0)->fuzz_executing_input) {
			BX_CPU(0)->cpu_loop();
		}
	} else {
	#if BX_SUPPORT_SMP
		Bit32u executed = 0;
		Bit32u processor = 0;
		bool run = true;
		const Bit32u quantum = SIM->get_param_num(BXPN_SMP_QUANTUM)->get();

		for (unsigned int cpu = 0; cpu < bx_cpu_count; cpu++) {
			BX_CPU(cpu)->icount_last_sync = BX_CPU(cpu)->get_icount();
		}

		if (setjmp(BX_CPU_C::jmp_buf_env)) {
			BX_CPU(processor)->icount++;
			run = false;
		}

			auto smp_running = [&]() -> bool {
				for (unsigned int cpu = 0; cpu < bx_cpu_count; cpu++) {
					if (BX_CPU(cpu)->fuzz_executing_input)
						return true;
				}
				return false;
			};

		while (smp_running()) {
			if (drain_state.active) {
				if (icount > kDrainIcountBudget) {
					drain_state.budget_hit = true;
					fuzz_emu_stop_unhealthy();
					break;
				}
			}

			if (run)
				BX_CPU(processor)->cpu_run_trace();
			else
				run = true;

			Bit32u n = (Bit32u)(BX_CPU(processor)->get_icount() -
			                    BX_CPU(processor)->icount_last_sync);
			if (n == 0)
				n = quantum;
			executed += n;

			if (++processor == bx_cpu_count) {
				processor = 0;
				BX_TICKN(executed / bx_cpu_count);
				executed %= bx_cpu_count;
				if (drain_state.active) {
					drain_state.tickn_calls++;
					if (drain_state.pred &&
					    drain_state.tickn_calls %
						    drain_state.pred_tick_interval == 0) {
						drain_state.pred_calls++;
						if (drain_state.pred(drain_state.ctx))
							pause_cpu();
						if (drain_state.pred_tick_interval <
						    kDrainPredTickIntervalMax) {
							drain_state.pred_tick_interval *= 2;
							if (drain_state.pred_tick_interval >
							    kDrainPredTickIntervalMax) {
								drain_state.pred_tick_interval =
									kDrainPredTickIntervalMax;
							}
						}
					}
				}
			}

			BX_CPU(processor)->icount_last_sync =
				BX_CPU(processor)->get_icount();
		}
#else
		while (BX_CPU(0)->fuzz_executing_input) {
			BX_CPU(0)->cpu_loop();
		}
	#endif
		}
		pause_cpu();
		if (fuzz_unhealthy_input || fuzz_do_not_continue)
			return;
		if (drain_state.active)
			return;
		BX_CPU(0)->gen_reg[BX_64BIT_REG_RIP].rrx = guest_rip; // reset $RIP

	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(0)->VMread64(VMCS_GUEST_RIP), &phy);
	// assert(res == 1); // Guest page table should be guarded
	if (res != 1){
		fuzz_emu_stop_unhealthy();
	}
	if (phy > maxaddr || !res) {
		fuzz_do_not_continue = true;
	}
}

/*
 * There are multiple ways to break out of the emulator:
 * fuzz_emu_stop_normal :
 *      A healthy stop (after hypervisor re-enter into the VM).
 * fuzz_emu_stop_unhealthy :
 *      We reached some timeout or error condition. Do not attmept to inject
 *      more operations and do not save the input in our queue.
 * fuzz_emu_stop_crash :
 *      There was a crash. Potentially print some info. Do not attempt to inject
 *      more operations.
 */

static void fuzz_emu_stop() {
	for (unsigned int cpu = 0; cpu < bx_cpu_count; cpu++) {
		BX_CPU(cpu)->fuzz_executing_input = false;
	}
}

void pause_cpu() {
	fuzz_emu_stop();
}

void fuzz_emu_stop_normal(){
	pause_cpu();
}

void fuzz_emu_stop_unhealthy(){
	pause_cpu();
    fuzz_do_not_continue = 1;
    fuzz_unhealthy_input = 1;
}

void fuzz_emu_stop_polling() {
	pause_cpu();
	fuzz_do_not_continue = 1;
}

void fuzz_emu_stop_crash(unsigned cpu, const char *type){
	// judege whether the crash is from a hypervisor thread
	Task* task = task_manager.get_current_task(cpu);
	if (task) {
		printf("Task PID: %d, Kernel Thread: %d, Hypervisor Thread: %d, Comm: %s, CR3: %lx, PGD: %lx\n",
			task->pid, task->kernel_task, task->hypervisor_task, task->comm,
			task->cr3, task->pgd);
	} else {
		return;
	}
	fuzz_emu_stop_unhealthy();
	// fuzz_should_abort = 1;
	if (type) {
		printf(".crash %s\n", type);
	} else {
		printf(".crash\n");
	}
	auto hash = stacktrace_hash_get(cpu);
	if (not stacktrace_hash_seen(hash)) {
		printf("Stacktrace hash: %lx\n", hash);
		stacktrace_hash_add(hash);
		print_stacktrace(cpu);
		auto *vdev = get_vqueue_manager().get_fuzzed_dev();
		if (vdev) {
			if (auto *model = vdev->get_syntax_model()) {
				model->log_generated_request(cpu);
			}
		}
		dump_regs_cpu(cpu);
		dump_instr_cpu(cpu);
		// construct a string type-hash, hash is hexadecimal
		std::stringstream ss;
		ss << type << "-" << std::hex << hash;
		ic_dump_file(ss.str().c_str());
	}
	if (abort_on_err_enabled()) {
		fflush(stdout);
		fflush(stderr);
		_exit(0);
	}
}

void fuzz_hook_exception(unsigned cpu, unsigned vector, unsigned error_code) {
}

void fuzz_hook_hlt(unsigned cpu) {
}

unsigned long int get_icount() {
	return icount;
}

unsigned long int get_pio_icount() {
	return pio_icount;
}

void reset_bx_vm() {
#if BX_SUPPORT_SMP
	for (unsigned int cpu = 0; cpu < bx_cpu_count; cpu++) {
		*BX_CPU(cpu) = shadow_bx_cpus[cpu];
	}
#else
	bx_cpu = shadow_bx_cpu;
#endif
	bx_pc_system = shadow_bx_pc_system;
	if (BX_CPU(0)->vmcs_map)
		BX_CPU(0)->vmcs_map->set_access_rights_format(VMCS_AR_OTHER);
	fuzz_reset_memory();
}

void fuzz_instr_interrupt(unsigned cpu, unsigned vector) {
	// if (vector == 3) {
    //     fuzz_emu_stop_crash(cpu, "debug-interrupt");
	// }
}

void fuzz_instr_after_execution(bxInstruction_c *i) {
	/* I don't think we need hacker_timer_mod. This prevent from configuring bochs to use -O2 optimization, just remove it */
	// if (hack_timer_mod && i->getIaOpcode() == 0x4b8 /*CALL_Jq*/) {
	// 	static uint64_t rdi, rsi; // context
	// 	uint64_t rip = BX_CPU(id)->gen_reg[BX_64BIT_REG_RIP].rrx;
	// 	if (rip == timer_mod[0] || rip == timer_mod[1] || rip == timer_mod[2] || rip == timer_mod[3]) {
	// 		if (in_timer_mode == 0) {
	// 			uint64_t anchor = BX_CPU(id)->pop_64() - 5; // assume CALL_Ja
	// 			rdi = BX_CPU(id)->gen_reg[BX_64BIT_REG_RDI].rrx;
	// 			rsi = BX_CPU(id)->gen_reg[BX_64BIT_REG_RSI].rrx;
	// 			// printf("call timer_mod(ts=0x%lx, expire_time=0x%lx), ", rdi, rsi);
	// 			BX_CPU(id)->set_reg64(BX_64BIT_REG_RDI, 1 /*CLOCK_VIRTUAL*/);
	// 			BX_CPU(id)->prev_rip = timer_mod[4];
	// 			BX_CPU(id)->gen_reg[BX_64BIT_REG_RIP].rrx = timer_mod[4];
	// 			BX_CPU(id)->push_64(anchor);
	// 			BX_CPU(id)->invalidate_prefetch_q();
	// 			in_timer_mode++;
	// 		} else if (in_timer_mode == 1) {
	// 			uint64_t current = BX_CPU(id)->get_reg64(BX_64BIT_REG_RAX);
	// 			// printf("while current=0x%lx\n", current);
	// 			BX_CPU(id)->set_reg64(BX_64BIT_REG_RSI, current);
	// 			BX_CPU(id)->set_reg64(BX_64BIT_REG_RDI, rdi);
	// 			BX_CPU(id)->prev_rip = rip;
	// 			BX_CPU(id)->gen_reg[BX_64BIT_REG_RIP].rrx = rip;
	// 			BX_CPU(id)->invalidate_prefetch_q();
	// 			in_timer_mode = 2;
	// 		}
	// 	}
	// }
}

void fuzz_instr_before_execution(unsigned cpu, bxInstruction_c *i) {
	handle_breakpoints(cpu, i);
	handle_syscall_hooks(cpu, i);
	if (!fuzzing && !fuzzenum)
		return;

	/* Check Icount limits */
	if (icount > icount_limit && fuzzing) {
		printf("icount abort %ld\n", icount);
	    fuzz_emu_stop_unhealthy();
	}
	if (pio_icount > pio_icount_limit && fuzzenum){
		printf("pio_icount abort %ld\n", pio_icount);
		fuzz_emu_stop_unhealthy();
	}
    icount++;
    pio_icount++;
}

static void usage() {
	printf("The following environment variables must be set:\n");
	printf("ICP_MEM_PATH\n");
	printf("ICP_REGS_PATH\n");
	printf("ICP_VMCS_LAYOUT_PATH\n");
	printf("ICP_VMCS_ADDR\n");
	exit(-1);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	static bool ic_test = fuzz_ic_test_enabled();
	static bool virtio_core = virtio_core_enabled();
	static int done;
	if (BX_CPU(0)->fuzztrace)
		printf("NEW INPUT\n");
	if (!done) {
		if (!log_writes)
			log_writes = log_writes_enabled();
		if (!nocov_enabled()) {
			auto qemu_source_cov = new UserSourceCov("qemu-system-x86_64");
			auto spdk_source_cov = new UserSourceCov("vhost");
			auto dpdk_source_cov = new UserSourceCov("dpdk-vhost_crypto");
			auto passt_source_cov = new UserSourceCov("passt.avx2");
			auto vhost_net_source_cov = new KernelSourceCov("vhost-net", "vhost/net.gcda", sym_to_addr("vmlinux", "gcov_info_head"));
			auto vhost_scsi_source_cov = new KernelSourceCov("vhost-scsi", "vhost/scsi.gcda", sym_to_addr("vmlinux", "gcov_info_head"));
			auto vhost_vsock_source_cov = new KernelSourceCov("vhost-vsock", "vhost/vsock.gcda", sym_to_addr("vmlinux", "gcov_info_head"));
			auto vhost_source_cov = new KernelSourceCov("vhost", "vhost/vhost.gcda", sym_to_addr("vmlinux", "gcov_info_head"));
			add_to_source_cov_set((SourceCov*)qemu_source_cov);
			add_to_source_cov_set((SourceCov*)spdk_source_cov);
			add_to_source_cov_set((SourceCov*)dpdk_source_cov);
			add_to_source_cov_set((SourceCov*)passt_source_cov);
			add_to_source_cov_set((SourceCov*)vhost_net_source_cov);
			add_to_source_cov_set((SourceCov*)vhost_scsi_source_cov);
			add_to_source_cov_set((SourceCov*)vhost_vsock_source_cov);
			add_to_source_cov_set((SourceCov*)vhost_source_cov);
		}
		setup_periodic_coverage();
	}

	check_write_coverage();

	/* Reset vars used to early abort input */
	fuzz_do_not_continue = false;
	fuzz_unhealthy_input = false;
	fuzz_should_abort = false;
	reset_cur_cov();
	/* this should be put before fuzz_run_input() since we will access it after LLVMFuzzerTestOneInput finishes */
	fuzzer::TPC.switch_values.clear();

	fuzzing = true;
	fuzz_run_input(Data, Size);
	fuzzing = false;

	size_t final_size;
	final_input_get(&final_size);

	if (fuzz_should_abort) abort();

	if (final_size == 0 || fuzz_unhealthy_input || !done) {
		verbose_printf("Skipping saving input (size: %ld, unhealthy: %d, done: %d)\n",
		       final_size, fuzz_unhealthy_input, done);
		fflush(stdout);
		uint8_t *dummy = (uint8_t *)"AAA";
		__fuzzer_set_output(dummy, 1);
		reset_bx_vm();
		get_vqueue_manager().reset_all_queue();
		get_vqueue_manager().reset_generated_desc();
		get_vqueue_manager().reset_seen_buffer();
		get_vqueue_manager().reset_indirect_tables();
		done = 1;
		return 0;
	}
	done = 1;

	reset_bx_vm();
	get_vqueue_manager().reset_all_queue();
	get_vqueue_manager().reset_generated_desc();
	get_vqueue_manager().reset_seen_buffer();
	get_vqueue_manager().reset_indirect_tables();

	/*
	 * The IC_TEST mode
	 */
	if (ic_test && !fuzz_unhealthy_input) {
		tsl::robin_set<bx_address> original_coverage = cur_input;
		size_t len, len2;
		uint8_t *output = ic_get_output(&len);
		uint8_t *newdata = (uint8_t *)malloc(len);
		memcpy(newdata, output, len);
		fuzz_unhealthy_input = false;
		reset_cur_cov();
		fuzzing = true;
		printf("Rerun:\n");
		fuzz_run_input(newdata, len);
		fuzzing = false;

		output = ic_get_output(&len2);
		
		if (len != len2 || memcmp(output, newdata, len)) {
			printf("Detected mismatch. Original Input %ld. IC Output1: %ld IC "
			       "Output2: %ld\n",
			       Size, len, len2);
			printf("Original Input: ");
			dump_hex(Data, Size);
			printf("IC Output 1     : ");
			dump_hex(newdata, len);
			printf("IC Output 2     : ");
			dump_hex(output, len2);
			fflush(stdout);
			fflush(stdout);
			exit(1);
		}
		if (original_coverage != cur_input) {
			printf("Detected Coverage mismatch\n");
			printf("Original Input: ");
			dump_hex(Data, Size);
			printf("IC Output     : ");
			dump_hex(newdata, len);
			fflush(stdout);
			exit(1);
		}
		free(newdata);
		reset_bx_vm();
	}
	return fuzz_unhealthy_input != 0;
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
	option_init();
	/* Path to VM Snapshot */
	const char *mem_path = icp_mem_path();
	const char *regs_path = icp_regs_path();
	const char *icp_db_path_str = icp_db_path();
	verbose = verbose_enabled();

	/* The Layout of the VMCS is specific to the CPU where the snapshot was
	 * collected, so we also need to load a mapping of VMCS encodings to
	 * offsets
	 */
	const char *vmcs_shadow_layout_path = icp_vmcs_layout_path();

	/*
	 * Location of VMCS is not contained in either the mem or regs, so
	 * speicify it manually. It can be obtained from the KVM state dump into
	 * syslog.
	 */
	const char *vmcs_addr_str = icp_vmcs_addr_env();

	if (!(mem_path && regs_path && vmcs_shadow_layout_path &&
	      vmcs_addr_str))
		usage();

	vmcs_addr = strtoll(vmcs_addr_str, NULL, 16);

	auto guess_cpu_count = [&](const char *base) -> unsigned int {
		const char *env = icp_ncpus_env();
		if (env) {
			long n = strtol(env, nullptr, 10);
			if (n > 0)
				return static_cast<unsigned int>(n);
		}
		std::error_code ec;
		if (std::filesystem::exists(base, ec))
			return 1;
		for (unsigned int cpu = 0;; cpu++) {
			std::string path = std::string(base) + std::to_string(cpu);
			if (!std::filesystem::exists(path, ec))
				return cpu ? cpu : 1;
		}
	};
	unsigned int cpu_count = guess_cpu_count(regs_path);

	/* Bochs-specific initialization. (e.g. CPU version/features). */
	icp_init_params();
	hp_init_cpus(cpu_count);
#if BX_SUPPORT_SMP
	SIM->get_param_num(BXPN_CPU_NPROCESSORS)->set(1);
	SIM->get_param_num(BXPN_CPU_NCORES)->set(cpu_count);
	SIM->get_param_num(BXPN_CPU_NTHREADS)->set(1);
#endif
	init_cpu();
	bx_init_pc_system();

	for (unsigned int cpu = 0; cpu < bx_cpu_count; cpu++) {
		BX_CPU(cpu)->fuzzdebug_gdb = gdb_enabled();
		BX_CPU(cpu)->fuzztrace = fuzz_debug_disasm_enabled();
	}

	/* Load the snapshot */
	printf(".loading memory snapshot from %s\n", mem_path);
	icp_init_mem(mem_path);
	fuzz_watch_memory_inc();

	icp_init_shadow_vmcs_layout(vmcs_shadow_layout_path);
	printf(".loading register snapshot from %s\n", regs_path);
		{
			std::error_code ec;
			for (unsigned int cpu = 0; cpu < bx_cpu_count; cpu++) {
				std::string path;
			if (std::filesystem::exists(regs_path, ec)) {
				if (cpu != 0)
					break;
				path = regs_path;
			} else {
				path = std::string(regs_path) + std::to_string(cpu);
			}
				icp_init_regs_cpu(path.c_str(), cpu);
			}
		}

		/* The current VMCS address is part of the CPU-state, but it is not part
		 * of the memory or register snapshot. As such, we load it (and adjacent
		 * internal Bochs pointers) separately.
	 */
	printf(".vmcs addr set  to %lx\n", vmcs_addr);
	icp_set_vmcs(vmcs_addr);

	/* Dump disassembly and CMP hooks? */

	fuzz_walk_ept();

	/* WIP: Tweak the VMCS/L2 state. E.g. set up our own page-tables for L2
	 * and ensure that the hypervisor thinks L2 is running privileged
	 * code/ring0 code.
	 */
	vmcs_fixup();
	/* fuzz_walk_cr3(); */

	/*
	 * Previously, we identified all of L2's pages. However, we want to
	 * avoid overwriting the L2's page-tables, as this might cause us to end
	 * up with crashes that are impossible to achieve in practice. So let's
	 * identify L2's page-tables and remove them from the list of hooked L2
	 * pages.
	 *
	 * Example: We inject a MMIO read into HV
	 *
	 * HV needs to disassemble the current L2 instruction to figure out
	 * where to place the result of the MMIO read.
	 *
	 * To do that it needs to take L2's RIP and convert it from a virtual
	 * address to a physical address.
	 *
	 * To do that it needs to walk L2's page tables. If we let
	 * the fuzzer hook reads from the page-table it might cause HV to crash
	 * but it's not clear whether it would be possible to actually cause the
	 * crash in practice (if the page-table was corrupted by the fuzzer, the
	 * MMIO exit wouldn't have happened in the first place
	 */
	ept_mark_page_table();

	/* Translate the guest's RIP in the VMCS to a physical-address */
	ept_locate_pc();

	/* Save guest RIP so that we can restore it after each fuzzer input */
	guest_rip = BX_CPU(0)->get_rip();
	
	/* Load symbols from files */
	if (kallsyms_path() and maps_path()) {
		/* only in infer stage, these two should be set */
		/* Load the kallsyms file */
		load_symbol_map_from_kallsyms(kallsyms_path());
		// load_symbol_map_from_maps(maps_path());
		// walk snapshot dir, find all file names that end with '.maps'
		for (const auto &entry :
		     std::filesystem::directory_iterator(snapshot_base())) {
			if (entry.path().extension() == ".maps") {
				printf("Loading symbol map from %s\n", entry.path().string().c_str());
				load_symbol_map_from_maps(entry.path().string().c_str());
			}
		}

		/* Since we are in infer stage, after doing this, we write sym back to the db, then exit*/
		store_sym_back_to_db(icp_db_path_str);
		exit(0);
	}


	/* For symbol - > addr (for breakpoints)*/
	if (symbol_mapping_path()) {
		// load_symbol_map(symbol_mapping_path());
		load_symbol_map_from_db(icp_db_path_str);
		if (hack_timer_mod_enabled()) {
			timer_mod[0] = sym_to_addr("qemu-system", "timer_mod");
			timer_mod[1] = sym_to_addr("qemu-system", "timer_mod_anticipate");
			timer_mod[2] = sym_to_addr("qemu-system", "timer_mod_ns");
			timer_mod[3] = sym_to_addr("qemu-system", "timer_mod_anticipate_ns");
			timer_mod[4] = sym_to_addr("qemu-system", "qemu_clock_get_ns");
			hack_timer_mod = true;
		}
	}

	for (unsigned int cpu = 0; cpu < bx_cpu_count; cpu++)
		BX_CPU(cpu)->TLB_flush();
	fuzz_walk_ept();
	vmcs_fixup();
	ept_mark_page_table();
	// init_register_feedback();

	if (link_map_path() && link_obj_regex())
		load_link_map(const_cast<char *>(link_map_path()),
			      const_cast<char *>(link_obj_regex()),
			      strtoll(link_obj_base_env(), NULL, 16));

	uint32_t pciid = 0;
	if (pci_id_env()) {
		pciid = strtol(pci_id_env(), NULL, 16);
		for (int i = 0; i < 32; i++)
			for (int j = 0; j < 8; j++) {
				uint32_t id = inject_pci_read(i, j, 0x0);
				if ((((id & 0xFFFF) << 16) | (id >> 16)) ==
				    pciid) {
					printf("Identified DEVICE %x FUNCTION %x : %04x:%04x\n",
					       i, j, id & 0xFFFF, id >> 16);
					set_pci_device(i, j);
				}
			}
	}
	if (kvm_enabled()) {
		if (kernel_dma_enabled())
			add_pc_range(0x0, 0xffffffffffffffff);
		else
			add_pc_range(0, 0x5fffffffffff);
		apply_breakpoints_linux();
    }
	/*
	 * make a copy of the bochs CPU state, which we use to reset the CPU
	 * state after each fuzzer input
	 */
#if BX_SUPPORT_SMP
	for (unsigned int cpu = 0; cpu < bx_cpu_count; cpu++) {
		shadow_bx_cpus[cpu] = *BX_CPU(cpu);
	}
#else
	shadow_bx_cpu = bx_cpu;
#endif
	shadow_bx_pc_system = bx_pc_system;

	/* Start tracking accesses to the memory so we can roll-back changes
	 * after each fuzzer input */
	fuzz_watch_memory_inc();
	reset_bx_vm();

	/* Enumerate or Load the cached list of PIO and MMIO Regions */
	/* Also, enumerate virtio queues */
	/* Since virtio queue enumeration would inject MMIOs, reset bx vm. */
	fuzzenum = true;
	init_regions(icp_db_path_str);
	fuzzenum = false;
	reset_bx_vm();

	/* iterate task list to find hypervisor-related tasks */
	bx_address init_task = sym_to_addr("vmlinux", "init_task");
	iterate_tasks(init_task);

	/* Init a signal handler for SIGUSR1 */
	signal(SIGUSR1, signal_handler);

	/* write seen edges at exit */
	// std::atexit(dump_seen_edges_to_file);

	return 0;
}
