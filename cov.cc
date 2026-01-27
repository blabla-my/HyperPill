#include "bochs.h"
#include "config.h"
#include "cpu/cpu.h"
#include "fuzz.h"
#include "task.h"
#include "time.h"
#include "conveyor.h"
#include "cov.h"
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <tsl/robin_map.h>
#include <tsl/robin_set.h> 
#include <unistd.h> 
#include <asm/ptrace.h>

tsl::robin_set<bx_address> seen_edges;
tsl::robin_map<bx_address, uint64_t> all_edges;
tsl::robin_map<bx_address, uint64_t> edge_to_idx;

tsl::robin_set<bx_address> cur_input;

std::vector<std::pair<size_t, size_t>> pc_ranges;

extern TaskManager task_manager;

struct calltrace_t {
    bx_address caller;
    bx_address callee;
    bx_address CR3;
};
std::vector<std::vector<calltrace_t>> our_stacktrace;
tsl::robin_set<uint64_t> seen_stacktraces;

#define EDGE_COUNTER_SIZE (32 << 12)
#define VIRTIO_REQ_COUNTER_SIZE (256)
#define TOTAL_COUNTER_SIZE (EDGE_COUNTER_SIZE + VIRTIO_REQ_COUNTER_SIZE)

__attribute__((section(
    "__libfuzzer_extra_counters"))) unsigned char libfuzzer_coverage[TOTAL_COUNTER_SIZE] = {0};

/* forward declaration so functions below can call it before its definition */
uint64_t edge_hash(uint64_t a, uint64_t b);
uint64_t pivot_hash(uint64_t hash);

uint64_t update_edge_counter(uint64_t prev_rip, uint64_t new_rip) {
    uint64_t hash = edge_hash(prev_rip, new_rip);
    libfuzzer_coverage[hash % EDGE_COUNTER_SIZE]++;
    return hash;
}

void update_virtio_req_counter(size_t queue_id, size_t desc_idx, bool is_out) {
    uint64_t hash = queue_id;
    hash = pivot_hash(hash);
    hash ^= desc_idx;
    hash = pivot_hash(hash);
    hash ^= (is_out ? 0x13ULL : 0x9eULL);
    hash = pivot_hash(hash);
    size_t idx = EDGE_COUNTER_SIZE + (hash % VIRTIO_REQ_COUNTER_SIZE);
    libfuzzer_coverage[idx]++;
}

uint32_t status = 0;

static std::vector<calltrace_t>& stacktrace_for_cpu(unsigned cpu) {
    if (cpu >= our_stacktrace.size())
        our_stacktrace.resize(cpu + 1);
    return our_stacktrace[cpu];
}

void add_pc_range(size_t base, size_t len) {
    printf("Will treat: %lx +%lx as coverage\n", base, len);
    pc_ranges.push_back(std::make_pair(base, len));
}

bool ignore_pc(unsigned cpu, bx_address pc) {
    static char* pc_filter = getenv("PC_FILTER");
    if (pc_filter){
        return task_filter(cpu);
    }
    
    if (pc_ranges.size() == 0) // No ranges = fuzz everthing
        return false;
    bool ignore = true;
    for (auto &r : pc_ranges) {
        if (pc >= r.first && pc <= r.first + r.second) {
            ignore = false;
            break;
        }
    }
    return ignore;
}

bool task_filter(unsigned cpu, bool user_only) {
    (void)user_only;
    if (!fuzzing) return false;
    Task* cur_task = task_manager.get_current_task(cpu);
    if (cur_task == NULL) {
        return true;
    }
    return !cur_task->is_hypervisor_task();
}

static size_t last_new = 0;

void print_stacktrace(unsigned cpu){
    auto &trace = stacktrace_for_cpu(cpu);
    printf("#stacktrace\n");
    if (trace.empty()) {
        printf("#end_stacktrace\n");
        fflush(stdout);
        fflush(stderr);
        return;
    }

    auto print_frame = [](bx_address addr, const sym_name_t &sym) {
        const char *symbol = sym.symbol.empty() ? "??" : sym.symbol.c_str();
        const char *bin = sym.bin.empty() ? "??" : sym.bin.c_str();
        printf("0x%lx %s (%s)\n", addr, symbol, bin);
    };

    const calltrace_t &last = trace.back();
    int pid = task_manager.get_pid(last.CR3);
    print_frame(last.callee, addr_to_sym(last.callee, pid));

    for (auto r = trace.rbegin(); r != trace.rend(); ++r) {
        pid = task_manager.get_pid(r->CR3);
        print_frame(r->caller, addr_to_sym(r->caller, pid));
    }

    printf("#end_stacktrace\n");
    fflush(stdout);
    fflush(stderr);
}

std::string stacktrace_to_string(unsigned cpu){
    auto &trace = stacktrace_for_cpu(cpu);
    std::stringstream ss;
    for (auto r = trace.rbegin(); r != trace.rend() ; ++r )
    {
        auto CR3 = r->CR3;
        auto pid = task_manager.get_pid(CR3);
        auto from_sym = addr_to_sym(r->caller, pid);
        auto to_sym = addr_to_sym(r->callee, pid);
        ss << r->caller<< " -> " << r->callee<< ","
           << " [" << from_sym.bin<< "] " << from_sym.symbol<< " -> "
           << " [" << to_sym.bin << "] " << to_sym.symbol<< "\n";
    }
    return ss.str();
}

inline uint64_t pivot_hash(uint64_t hash){
    hash ^= hash >> 30;
    hash *= 0xbf58476d1ce4e5b9U;
    hash ^= hash >> 27;
    hash *= 0x94d049bb133111ebU;
    hash ^= hash >> 31;
    return hash;
}

uint64_t edge_hash(uint64_t a, uint64_t b){
    uint64_t hash = a;
    hash = pivot_hash(hash);
    hash ^= b;
    hash = pivot_hash(hash);
    return hash;
}

uint64_t stacktrace_hash_get(unsigned cpu) {
    auto &trace = stacktrace_for_cpu(cpu);
    uint64_t hash = 0;
    int cnt = 0;
    for (auto r = trace.rbegin(); r != trace.rend() && cnt<15 ; ++r,++cnt )
    {
        hash ^= r->callee;
        hash = pivot_hash(hash);
        hash ^= r->caller;
        hash = pivot_hash(hash);
    }
    return hash;
}

bool stacktrace_hash_seen(uint64_t hash) {
    if (seen_stacktraces.find(hash) == seen_stacktraces.end()) {
        return false;
    }
    return true;
}

void stacktrace_hash_add(uint64_t hash) {
    seen_stacktraces.insert(hash);
}

void add_edge_not_taken(unsigned cpu, bx_address prev_rip) {
    bx_address new_rip = BX_CPU(cpu)->gen_reg[BX_64BIT_REG_RIP].rrx;
    add_edge(cpu, prev_rip, new_rip);
}

void add_edge(unsigned cpu, bx_address prev_rip, bx_address new_rip) {
    static char* NEW_PC_QEMU_ONLY=getenv("NEW_PC_QEMU_ONLY");
    if(ignore_pc(cpu, new_rip))
        // goto out;
        return ;
    
    time_t t;

    if(fuzzing) {
        if(cur_input.emplace(new_rip).second)
            last_new = 0;
        if(last_new++ > 3000000 && !master_fuzzer ){
            printf("No new edges for over %lu..\n", last_new);
            fuzz_emu_stop_unhealthy();
        }
        if(last_new > 3000000 && master_fuzzer ){
            printf("No new edges for over %lu..\n", last_new);
            fuzz_stacktrace(cpu);
            fuzz_emu_stop_unhealthy();
        }
    }
    uint64_t hash = update_edge_counter(prev_rip, new_rip);

out:
    if (log_ops) {
        if (seen_edges.emplace(hash).second) {
            time(&t);
            auto s = addr_to_sym(new_rip);
            printf("[%lu] NEW_PC: %lx %s (%s)\n", t, new_rip, s.symbol.c_str(), s.bin.c_str());
            status |= (1 << 1); // new pc
        }
    }
}

void reset_op_cov() {
    last_new = 0;
}
void reset_cur_cov() {
    our_stacktrace.clear();
    cur_input.clear();
    last_new = 0;
    libfuzzer_coverage[0] = 1;
}

void fuzz_instr_cnear_branch_taken(unsigned cpu, bx_address branch_rip, bx_address new_rip) {
    add_edge(cpu, branch_rip, new_rip);
}

void fuzz_instr_cnear_branch_not_taken(unsigned cpu, bx_address branch_rip) {
    add_edge_not_taken(cpu, branch_rip);
}

uint32_t get_sysret_status() { return status; }

void reset_sysret_status() { status = 0; }


void fuzz_stacktrace(unsigned cpu){
    /* if(master_fuzzer) */
    if(fuzzing)
        ic_dump();
    static void *log_crashes = getenv("LOG_CRASHES");
    if(!log_crashes)
        return;
    print_stacktrace(cpu);

}

void print_page_fault_pt_regs(){
    bx_address pt_regs_addr = BX_CPU(0)->gen_reg[BX_64BIT_REG_RDI].rrx;
    printf("pt_regs_addr: %lx\n", pt_regs_addr);
    struct pt_regs regs;
    bx_kernel_read(0, pt_regs_addr, &regs, sizeof(struct pt_regs));
    // dump pt_regs with name
    printf("pt_regs:\n");
    printf("r15: %lx\n", regs.r15);
    printf("r14: %lx\n", regs.r14);
    printf("r13: %lx\n", regs.r13);
    printf("r12: %lx\n", regs.r12);
    printf("r11: %lx\n", regs.r11);
    printf("r10: %lx\n", regs.r10);
    printf("r9: %lx\n", regs.r9);
    printf("r8: %lx\n", regs.r8);
    printf("rbp: %lx\n", regs.rbp);
    printf("rdi: %lx\n", regs.rdi);
    printf("rsi: %lx\n", regs.rsi);
    printf("rdx: %lx\n", regs.rdx);
    printf("rax: %lx\n", regs.rax);
    printf("rcx: %lx\n", regs.rcx);
    printf("rbx: %lx\n", regs.rbx);
    printf("orig_rax: %lx\n", regs.orig_rax);
    printf("rip: %lx %s\n", regs.rip, addr_to_sym(regs.rip).symbol.c_str());
    printf("cs: %lx\n", regs.cs);
    printf("eflags: %lx\n", regs.eflags);
    printf("rsp: %lx\n", regs.rsp);
    printf("ss: %lx\n", regs.ss);
}

void fuzz_instr_ucnear_branch(unsigned cpu, unsigned what, bx_address branch_rip,
                              bx_address new_rip) {
    auto &trace = stacktrace_for_cpu(cpu);
    if (what == BX_INSTR_IS_SYSRET)
        status |= 1; // sysret
    if((what == BX_INSTR_IS_CALL || what == BX_INSTR_IS_CALL_INDIRECT)) {
        trace.push_back({branch_rip, new_rip, BX_CPU(cpu)->cr3});
        /* fuzz_stacktrace(); */
    } else if (what == BX_INSTR_IS_RET && !trace.empty()) {
        calltrace_t last_call = trace.back();
        trace.pop_back();
        handle_breakpoints_func_call(cpu, last_call.callee, new_rip);
        /* fuzz_stacktrace(); */
    }
    add_edge(cpu, branch_rip, new_rip);
}

void fuzz_instr_far_branch(unsigned cpu, unsigned what, Bit16u prev_cs, bx_address prev_rip,
                           Bit16u new_cs, bx_address new_rip) {
    auto &trace = stacktrace_for_cpu(cpu);
    if (what == BX_INSTR_IS_SYSRET)
        status |= 1; // sysret

    if((what == BX_INSTR_IS_CALL || what == BX_INSTR_IS_CALL_INDIRECT)) {
        trace.push_back({prev_rip, new_rip, BX_CPU(cpu)->cr3});
        /* fuzz_stacktrace(); */
    } else if (what == BX_INSTR_IS_RET && !trace.empty()) {
        calltrace_t last_call = trace.back();
        trace.pop_back();
        handle_breakpoints_func_call(cpu, last_call.callee, new_rip);
        /* fuzz_stacktrace(); */
    }

    // if (what == BX_INSTR_IS_IRET)
        add_edge(cpu, prev_rip, new_rip);
}

void serialize_bx_address_set(tsl::robin_set<bx_address> &set, const char *filename) {
    std::ofstream ostream(filename, std::ios::binary);  
    for (const auto &item : set) {
        ostream.write(reinterpret_cast<const char *>(&item), sizeof(bx_address));
    }
    ostream.close();
}

void dump_seen_edges_to_file() {
    char filename[64] = {0};
    // add time to filename
    time_t t = time(NULL);
    snprintf(filename, sizeof(filename), "seen_edges_%d_%lu", getpid(), t);
    serialize_bx_address_set(seen_edges, filename);
}

/* Add a signal handler to dump libfuzzer coverage */
void signal_handler(int signum) {
    if (signum == SIGUSR1){
        char linkpath[100];
        readlink("/proc/self/fd/1", linkpath, 100);
        if (strstr(linkpath, "fuzz-")){
            dump_seen_edges_to_file();
        }
    }
}
