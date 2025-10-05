#include "bochs.h"
#include "fuzz.h"
#include "sourcecov.h"

#include "task.h"
#include <stdio.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include  <signal.h>
#include <string>
#include <sstream>
#include <fstream>
#include <iostream>
#include <regex>

static int coverage_dump_precision = 300;
static uint64_t last_coverage_dump;

static std::set<const SourceCov*> source_cov_set;

// The format of the header:
/* See: https://github.com/llvm/llvm-project/blob/36daf3532d91bb3e61d631edceea77ebb8417801/compiler-rt/include/profile/InstrProfData.inc#L126
INSTR_PROF_RAW_HEADER(uint64_t, Magic, __llvm_profile_get_magic())
INSTR_PROF_RAW_HEADER(uint64_t, Version, __llvm_profile_get_version())
INSTR_PROF_RAW_HEADER(uint64_t, BinaryIdsSize, __llvm_write_binary_ids(NULL))
INSTR_PROF_RAW_HEADER(uint64_t, DataSize, DataSize)
INSTR_PROF_RAW_HEADER(uint64_t, PaddingBytesBeforeCounters, PaddingBytesBeforeCounters)
INSTR_PROF_RAW_HEADER(uint64_t, CountersSize, CountersSize)
INSTR_PROF_RAW_HEADER(uint64_t, PaddingBytesAfterCounters, PaddingBytesAfterCounters)
INSTR_PROF_RAW_HEADER(uint64_t, NamesSize,  NamesSize)
INSTR_PROF_RAW_HEADER(uint64_t, CountersDelta,
                      (uintptr_t)CountersBegin - (uintptr_t)DataBegin)
INSTR_PROF_RAW_HEADER(uint64_t, NamesDelta, (uintptr_t)NamesBegin)
INSTR_PROF_RAW_HEADER(uint64_t, ValueKindLast, IPVK_Last)

Eg:
00000000: 8172 666f 7270 6cff 0800 0000 0000 0000  .rforpl.........
00000010: 2000 0000 0000 0000 0fb0 0000 0000 0000   ...............
00000020: 0000 0000 0000 0000 bb55 0300 0000 0000  .........U......
00000030: 0000 0000 0000 0000 ce76 6d00 0000 0000  .........vm.....
00000040: 2852 e5ff ffff ffff 8dd1 3959 5555 0000  (R........9YUU..
00000050: 0100 0000 0000 0000 1400 0000 0000 0000  ................

*/

static uint64_t base;

static uint64_t get_addr_of_symbol(const char* symbolname)
{
    FILE *fp;
    char addr[100];

    char cmd[500];
    snprintf(cmd, 500, "nm --defined-only -n %s | grep %s | cut -f1 -d ' '", getenv("LINK_OBJ_PATH"), symbolname);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        printf("Failed to run command %s\n", cmd);
        exit(1);
    }

    /* Read the output a line at a time - output it. */
    while (fgets(addr, sizeof(addr), fp) != NULL) {
        printf("%s: %s", symbolname, addr);
        return strtoll(addr, NULL, 16);
    }
    return 0;
}

int SourceCov::access_read_linear(bx_address laddr, unsigned len, unsigned curr_pl, unsigned xlate_rw, Bit32u ac_mask, void *data) const {
    auto old_cr3 = BX_CPU(0)->cr3;
    BX_CPU(0)->cr3 = cr3;
    int rc = BX_CPU(0)->access_read_linear(laddr, len, curr_pl, xlate_rw, ac_mask, data);
    BX_CPU(0)->cr3 = old_cr3;
    return rc;
}

void SourceCov::write_source_cov() const {
    // Write Header
	size_t len;
	size_t offset = 0;
    uint64_t header[11] = {0};
    if(!header[0]) {
        uint64_t value;

        // Magic
        memcpy(&header[0], "\x81\x72\x66\x6f\x72\x70\x6c\xff", sizeof(uint64_t));

        // Version
        value = 0x8;
        memcpy(&header[1], &value, sizeof(uint64_t));

        // BinaryIdsSize (just copied from default.profraw)
        value = 0x20;
        value = 0;
        memcpy(&header[2], &value, sizeof(uint64_t));

        // DataSize
        // __start___llvm_prf_data
        // __stop___llvm_prf_data
        // Divide by 8
        value = pdsize/(8*6); 
        memcpy(&header[3], &value, sizeof(uint64_t));

        // PaddingBytesBeforeCounters
        value = 0; 
        memcpy(&header[4], &value, sizeof(uint64_t));

        // CountersSize
        // __start___llvm_prf_cnts
        // __stop___llvm_prf_cnts
        // Divide by 8
        value = pcsize/8; 
        memcpy(&header[5], &value, sizeof(uint64_t));

        // PaddingBytesAfterCounters
        value = 0; 
        memcpy(&header[6], &value, sizeof(uint64_t));                                                   

        // NamesSize
        // __start___llvm_prf_names
        // __stop___llvm_prf_names
        value = pnsize; 
        memcpy(&header[7], &value, sizeof(uint64_t));

        // CountersDelta
        // Address of __start___llvm_prf_cnts
        // Address of __start___llvm_prf_data
        value = pcstart-pdstart; 
        memcpy(&header[8], &value, sizeof(uint64_t));

        // CountersDelta
        // Address of __start___llvm_prf_names
        value = pnstart; 
        memcpy(&header[9], &value, sizeof(uint64_t));

        // ValueKindLast
        value = 1; 
        memcpy(&header[10], &value, sizeof(uint64_t));


		len = pdsize;
		offset = 0;
		while (len) {
			/* printf("Reading pd %lx\n", pd+offset); */
			if(len> 0x1000) {
				this->access_read_linear(pdstart+offset, 0x1000, 0, BX_READ, 0x0, pd + offset);
				len -= 0x1000;
				offset += 0x1000;
			} else {
				this->access_read_linear(pdstart+offset, len, 0, BX_READ, 0x0, pd + offset);
				len = 0;
			}
		}
		len = pnsize;
		offset = 0;
		while (len) {
			/* printf("Reading pn %lx\n", pn+offset); */
			if(len> 0x1000) {
				this->access_read_linear(pnstart+offset, 0x1000, 0, BX_READ, 0x0, pn + offset);
				len -= 0x1000;
				offset += 0x1000;
			} else {
				this->access_read_linear(pnstart+offset, len, 0, BX_READ, 0x0, pn + offset);
				len = 0;
			}
		}
    }

	len = pcsize;
	offset = 0;

    while (len) {
        /* printf("Reading pc %lx\n", pc+offset); */
        if(len> 0x1000) {
            this->access_read_linear(pcstart+offset, 0x1000, 0, BX_READ, 0x0, pc + offset);
            len -= 0x1000;
            offset += 0x1000;
        } else {
            this->access_read_linear(pcstart+offset, len, 0, BX_READ, 0x0, pc + offset);
            len = 0;
        }
    }

    uint8_t padding[10] = {};
    struct iovec iov[] = {
        {header, sizeof(header)},
        {pd, pdsize},
        {pc, pcsize},
        {pn, pnsize},
        {padding, 8-((sizeof(header)+pdsize+pcsize+pnsize)%8)}
    };
    char filename[100];
    sprintf(filename, "%s-%d-%ld.profraw", bin.c_str(), getpid(), time(NULL));
    int fd = open(filename, O_CREAT|O_RDWR, 0666);
    writev(fd, iov, sizeof(iov)/sizeof(struct iovec));
    close(fd);
}

void TERMhandler(int sig){
    for (auto source_cov : source_cov_set){
        source_cov->write_source_cov();
    }
    _exit(0);
}

void check_write_coverage(){
    if(!master_fuzzer || !last_coverage_dump)
        return;
    uint64_t t = time(NULL);
    if(t - last_coverage_dump < coverage_dump_precision)
        return;
    last_coverage_dump=t;
    // following dump
    static char* no_cov = getenv("NOCOV");
    if (!no_cov){
        for (auto source_cov : source_cov_set){
            source_cov->write_source_cov();
        }
    }

    static char* dump_seen_edges = getenv("SEEN_EDGES");
    if (dump_seen_edges)
        dump_seen_edges_to_file();
}

static void sig_handler(int signum) {
    uint64_t t = time(NULL);
    switch (signum) {
    case SIGALRM:
        if(t - last_coverage_dump < coverage_dump_precision)
            return;

        last_coverage_dump=t;
        // following dump
        for (auto source_cov : source_cov_set){
            source_cov->write_source_cov();
        }
        dump_seen_edges_to_file();
        alarm(coverage_dump_precision);
        break;
    }
}

SourceCov::SourceCov(const std::string& binary, bool reserve_init_cov) {
    __inited = false;
    bin = std::string("");
    pdstart = pdstop = pdsize = 0;
    pcstart = pcstop = pcsize = 0;
    pnstart = pnstop = pnsize = 0;
    pd = pc = pn = NULL;
    cr3 = 0;
    reserve_init_cov = reserve_init_cov;

    // we have already loaded all symbol addresses in the main.cc
    pdstart = sym_to_addr(binary.c_str(), "__start___llvm_prf_data");
    pdstop = sym_to_addr(binary.c_str(), "__stop___llvm_prf_data");
    pcstart = sym_to_addr(binary.c_str(), "__start___llvm_prf_cnts");
    pcstop = sym_to_addr(binary.c_str(), "__stop___llvm_prf_cnts");
    pnstart = sym_to_addr(binary.c_str(), "__start___llvm_prf_names");
    pnstop = sym_to_addr(binary.c_str(), "__stop___llvm_prf_names");
    
    if (!pdstart && !pdstop) {
        __inited = false;
        return;
    }

    const char* binpath = get_bin_full_path(binary);
    assert(binpath != NULL);

    auto pids = select_pid(binpath);
    assert(pids.size() == 1);
    auto pid = pids[0];
    
    printf("init sourcecov for %s, %d: pdstart: %lx, pdstop: %lx, pcstart: %lx, pcstop: %lx, pnstart: %lx, pnstop: %lx\n",
           binary.c_str(), pid, pdstart, pdstop, pcstart, pcstop, pnstart, pnstop);
    fflush(stdout);

    pdsize = pdstop-pdstart;
    pcsize = pcstop-pcstart;
    pnsize = pnstop-pnstart;

    pd = (uint8_t*)malloc(pdsize);
    pc = (uint8_t*)malloc(pcsize);
    pn = (uint8_t*)malloc(pnsize);

    memset(pc, 0, pcsize);
    for(size_t page = (pcstart >> 12) << 12;  page < pcstop;  page += 0x1000){
        size_t start, len;
        if(pcstart - page < 0x1000)
            start = pcstart;
        else 
            start = page;

        len = 0x1000 - (start & 0xFFF);

        if(pcstop - page < 0x1000)
            len = pcstop - page;

        Bit32u lpf_mask = 0xfff; // 4K pages
        Bit32u pkey = 0;
        /* switch cr3 to the task, then tranlsate */
        /* otherwise, page fault will occur */
        cr3 = task_manager.get_cr3(pid);
        assert(cr3 != 0);
        auto old_cr3 = BX_CPU(0)->cr3;
        BX_CPU(0)->cr3 = cr3;
        bx_phy_address phystart = 
            BX_CPU(0)->translate_linear_long_mode(start, lpf_mask, pkey, 0, BX_READ);
        if (!reserve_init_cov)
            BX_CPU(0)->access_write_linear(start, len, 0, BX_WRITE, 0x0, pc);
        /* resume cr3 */
        BX_CPU(0)->cr3 = old_cr3;

        phystart = (phystart & ~((Bit64u) lpf_mask)) | (start & lpf_mask);
        add_persistent_memory_range(phystart, len);
    }
    
    __inited = true;
    bin = binary;
}
extern uint64_t icount_limit_floor;
extern uint64_t icount_limit;

void add_to_source_cov_set(const SourceCov* source_cov) {
    if (!source_cov)
        return;
    if (source_cov->inited()) {
        source_cov_set.insert(source_cov);
    } else {
        printf("failed to add %s to source_cov_set, inited = %d\n", source_cov->get_bin().c_str(), source_cov->inited());
    }
}

void setup_periodic_coverage(){
    char linkpath[128];
    readlink("/proc/self/fd/1", linkpath, 128);
    linkpath[127] = 0;
    if(strstr(linkpath, "fuzz-0.log")){
        if(!getenv("NOCOV")) {
            last_coverage_dump=time(NULL);
            for (auto source_cov : source_cov_set) {
                source_cov->write_source_cov();
            }
        }
        if(getenv("SEEN_EDGES")) {
            last_coverage_dump=time(NULL);
            dump_seen_edges_to_file();
        }
        master_fuzzer = true;
    } else if(strstr(linkpath, "fuzz-") && getenv("PROGRESSIVE_TIMEOUT")){
        std::stringstream ss;
        std::regex log_regex("fuzz-(.*).log");
        std::smatch match;
        std::string s = linkpath;
        std::regex_search(s, match, log_regex);
        assert(match.size() > 1);
        ss << std::dec << match[1].str();
        int val;
        ss >> val;
        unsigned long max = strtol(getenv("NSLOTS"), NULL, 10);
        assert(val < max);
        if(max != LONG_MIN){
            icount_limit = icount_limit_floor + ((icount_limit-icount_limit_floor)/(max))*(val-1);
            printf("SET ICOUNT LIMIT: %lu\n", icount_limit);
        }
    }
}
