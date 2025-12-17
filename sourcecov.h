#ifndef SOURCECOV_H
#define SOURCECOV_H

#include "fuzz.h"
#include "gcov.h"
#include <stdint.h>
#include <string>
#include <set>

class SourceCov {
public:
    SourceCov(bool reserve_init_cov = false) : reserve_init_cov(reserve_init_cov) {
        __inited = false;
    }
    virtual void write_source_cov() const = 0;
    bool inited() const {return __inited;}
    virtual const std::string get_name() const = 0;
    
protected:
    bool __inited;
    bool reserve_init_cov;
};

class UserSourceCov : SourceCov {
public:
    UserSourceCov(const std::string& binary, bool reserve_init_cov = false);
    virtual void write_source_cov() const override;
    const std::string get_name() const override {return bin;}
    
private:
    std::string bin;
    uint64_t pdstart, pdstop, pdsize;
    uint64_t pcstart, pcstop, pcsize;
    uint64_t pnstart, pnstop, pnsize;
    uint8_t *pd, *pc, *pn;
    unsigned long cr3;
    
    /* when accessing llvm prf sections, it is possible that we are not in the virtual memory space of corresponding process.  */
    /* as a result, we need to switch to the process of target binary, then read/write */
    /* this is done by switching CR3 value */
    int access_read_linear(bx_address laddr, unsigned len, unsigned curr_pl, unsigned xlate_rw, Bit32u ac_mask, void *data) const;
};

void iterate_gcov_info_chain(uint64_t gcov_info_head_addr);

class KernelSourceCov : SourceCov {
public:
    KernelSourceCov(const std::string& module_name, const std::string& source_file, const uint64_t gcov_info_head_addr, bool reserve_init_cov = false);
    virtual void write_source_cov() const override;
    const std::string get_name() const override {return module_name;}
private:
    std::string module_name;
    std::string source_file;
    uint64_t gcov_info_head_addr;
    uint64_t gcov_info_addr;
    std::map<void*, uint64_t> addr_map;
    struct gcov_info ginfo;
    char ginfo_filename[0x40];
    size_t active_ctrs;
    size_t gcda_size;
    uint8_t *gcda_data;
    void fetch_latest_gcov_info() const;
    void write_back_gcov_info() const;
    void add_addr_map(void* addr, uint64_t bx_addr) {
        addr_map[addr] = bx_addr;
    }
    uint64_t get_bx_addr(void* addr) const {
        if (addr_map.find(addr) != addr_map.end()) {
            return addr_map.at(addr);
        }
        return 0;
    }
};

void add_to_source_cov_set(const SourceCov*);
void setup_periodic_coverage();
void check_write_coverage();

#endif