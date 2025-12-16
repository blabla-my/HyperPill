#ifndef SOURCECOV_H
#define SOURCECOV_H

#include "fuzz.h"
#include <stdint.h>
#include <string>
#include <set>

class SourceCov {
public:
    SourceCov(const std::string& binary, bool reserve_init_cov = false);
    virtual void write_source_cov() const;
    virtual bool inited() const {return __inited;}
    virtual const std::string get_bin() const {return bin;}
    
private:
    bool __inited;
    bool reserve_init_cov;
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

class KernelSourceCov : public SourceCov {
public:
    KernelSourceCov(const std::string& source_file, const uint64_t gcov_info_head_addr, bool reserve_init_cov = false);
    virtual void write_source_cov() const override;
private:
    std::string source_file;
    uint64_t gcov_info_head_addr;
    uint64_t gcov_info_addr;
};

void add_to_source_cov_set(const SourceCov*);
void setup_periodic_coverage();
void check_write_coverage();

#endif