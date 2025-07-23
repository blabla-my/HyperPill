#include "bochs.h"
#include "config.h"
#include "cpu/cpu.h"
#include "fuzz.h"
#include "task.h"
#include "time.h"
#include "conveyor.h"
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <tsl/robin_map.h>
#include <tsl/robin_set.h> 
#include <unistd.h> 
#include <asm/ptrace.h>

tsl::robin_map<bx_address, bool> ignore_edges;
tsl::robin_set<bx_address> seen_edges;
tsl::robin_map<bx_address, uint64_t> all_edges;
tsl::robin_map<bx_address, uint64_t> edge_to_idx;

tsl::robin_set<bx_address> cur_input;

std::vector<std::pair<size_t, size_t>> pc_ranges;
std::vector<std::pair<size_t, size_t>> our_stacktrace;
tsl::robin_set<uint64_t> seen_stacktraces;

__attribute__((section(
    "__libfuzzer_extra_counters"))) unsigned char libfuzzer_coverage[32 << 12];

uint32_t status = 0;

void add_pc_range(size_t base, size_t len) {
    printf("Will treat: %lx +%lx as coverage\n", base, len);
    pc_ranges.push_back(std::make_pair(base, len));
}

bool ignore_pc(bx_address pc) {
    static char* pc_filter = getenv("PC_FILTER");
    if (pc_filter){
        return task_filter();
    }
    
    if (pc_ranges.size() == 0) // No ranges = fuzz everthing
        return false;
    if (ignore_edges.find(pc) == ignore_edges.end()) {
        bool ignore = true;
        for (auto &r : pc_ranges) {
            if (pc >= r.first && pc <= r.first + r.second) {
                ignore = false;
                break;
            }
        }
        ignore_edges[pc] = ignore;
    }
    return ignore_edges[pc];
}

bool task_filter(bool user_only) {
    task* cur_task = task_manager.get_current_task();
    if(cur_task == NULL) {
        return true;
    }
    if (is_userspace_vmm_task(cur_task)){
        return BX_CPU(id)->get_cpl() == 0;
    }
    if (!user_only && is_hypervisor_task(cur_task)){
        return false;
    }
    return true;
}

static size_t last_new = 0;

void print_stacktrace(){
    printf("Stacktrace:\n");
    if(our_stacktrace.empty())
        return;
    for (auto r = our_stacktrace.rbegin(); r != our_stacktrace.rend() ; ++r )
    {
        auto from_sym = addr_to_sym(r->first);
        auto to_sym = addr_to_sym(r->second);
        printf("%016lx -> %016lx, [%s] %s -> [%s] %s\n", r->first, r->second, 
                from_sym.first.c_str(), from_sym.second.c_str(), 
                to_sym.first.c_str(), to_sym.second.c_str());
    }
    fflush(stdout);
    fflush(stderr);
}

std::string stacktrace_to_string(){
    std::stringstream ss;
    for (auto r = our_stacktrace.rbegin(); r != our_stacktrace.rend() ; ++r )
    {
        auto from_sym = addr_to_sym(r->first);
        auto to_sym = addr_to_sym(r->second);
        ss << r->first << " -> " << r->second << ","
           << " [" << from_sym.first << "] " << from_sym.second << " -> "
           << " [" << to_sym.first << "] " << to_sym.second << "\n";
    }
    return ss.str();
}

uint64_t stacktrace_hash_get() {
    uint64_t hash = 0;
    int cnt = 0;
    for (auto r = our_stacktrace.rbegin(); r != our_stacktrace.rend() && cnt<10 ; ++r,++cnt )
    {
        hash ^= r->first ^ r->second;
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

void add_edge_not_taken(bx_address prev_rip) {
    // printf("add_edge_not_taken: %lx -> %lx\n", prev_rip, BX_CPU(id)->gen_reg[BX_64BIT_REG_RIP].rrx);
    bx_address new_rip = BX_CPU(id)->gen_reg[BX_64BIT_REG_RIP].rrx;
    add_edge(prev_rip, new_rip);
}

void add_edge(bx_address prev_rip, bx_address new_rip) {
    static char* NEW_PC_QEMU_ONLY=getenv("NEW_PC_QEMU_ONLY");
    if(ignore_pc(new_rip))
        goto out;
    time_t t;

    if(fuzzing) {
        if(cur_input.emplace(new_rip).second)
            last_new = 0;
        if(last_new++ > 1000000 && !master_fuzzer ){
            printf("No new edges for over %d..\n", last_new);
            fuzz_emu_stop_unhealthy();
        }
        if(last_new > 3000000 && master_fuzzer ){
            printf("No new edges for over %d..\n", last_new);
            fuzz_stacktrace();
            fuzz_emu_stop_unhealthy();
        }
    }
    libfuzzer_coverage[new_rip % sizeof(libfuzzer_coverage)]++;

out:
    if (NEW_PC_QEMU_ONLY && task_filter(true))
        return;
    else if (!NEW_PC_QEMU_ONLY && task_filter())
        return;

    bx_address hash = prev_rip ^ (new_rip >> 1);
    if (seen_edges.emplace(hash).second) {
        time(&t);
        auto s = addr_to_sym(new_rip);
        printf("[%d] NEW_PC: %lx %s (%s)\n", t, new_rip, s.second.c_str(), s.first.c_str());
        status |= (1 << 1); // new pc
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

void fuzz_instr_cnear_branch_taken(bx_address branch_rip, bx_address new_rip) {
    add_edge(branch_rip, new_rip);
}

void fuzz_instr_cnear_branch_not_taken(bx_address branch_rip) {
    add_edge_not_taken(branch_rip);
}

uint32_t get_sysret_status() { return status; }

void reset_sysret_status() { status = 0; }


void fuzz_stacktrace(){
    /* if(master_fuzzer) */
    if(fuzzing)
        ic_dump();
    static void *log_crashes = getenv("LOG_CRASHES");
    if(!log_crashes)
        return;
    print_stacktrace();

}

void print_page_fault_pt_regs(){
    bx_address pt_regs_addr = BX_CPU(0)->gen_reg[BX_64BIT_REG_RDI].rrx;
    printf("pt_regs_addr: %lx\n", pt_regs_addr);
    struct pt_regs regs;
    BX_CPU(0)->access_read_linear(pt_regs_addr, sizeof(regs), 0, BX_READ, 0x0, &regs);
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
    printf("rip: %lx %s\n", regs.rip, addr_to_sym(regs.rip).second.c_str());
    printf("cs: %lx\n", regs.cs);
    printf("eflags: %lx\n", regs.eflags);
    printf("rsp: %lx\n", regs.rsp);
    printf("ss: %lx\n", regs.ss);
}

void fuzz_instr_ucnear_branch(unsigned what, bx_address branch_rip,
                              bx_address new_rip) {
    if (what == BX_INSTR_IS_SYSRET)
        status |= 1; // sysret
    if((what == BX_INSTR_IS_CALL || what == BX_INSTR_IS_CALL_INDIRECT)) {
        our_stacktrace.push_back(std::make_pair(branch_rip, new_rip));
        /* fuzz_stacktrace(); */
    } else if (what == BX_INSTR_IS_RET && !our_stacktrace.empty()) {
        our_stacktrace.pop_back();
        /* fuzz_stacktrace(); */
    }
    add_edge(branch_rip, new_rip);
}

void fuzz_instr_far_branch(unsigned what, Bit16u prev_cs, bx_address prev_rip,
                           Bit16u new_cs, bx_address new_rip) {
    if (what == BX_INSTR_IS_SYSRET)
        status |= 1; // sysret

    if((what == BX_INSTR_IS_CALL || what == BX_INSTR_IS_CALL_INDIRECT)) {
        our_stacktrace.push_back(std::make_pair(prev_rip, new_rip));
        /* fuzz_stacktrace(); */
    } else if (what == BX_INSTR_IS_RET && !our_stacktrace.empty()) {
        our_stacktrace.pop_back();
        /* fuzz_stacktrace(); */
    }

    // if (what == BX_INSTR_IS_IRET)
        add_edge(prev_rip, new_rip);
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