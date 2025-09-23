#ifndef SOURCECOV_H
#define SOURCECOV_H

#include "fuzz.h"
#include <stdint.h>
#include <string>
#include <set>
class SourceCov {
public:
    SourceCov(const std::string& binary);
    void write_source_cov() const;
    bool inited() const {return __inited;}
    const std::string get_bin() const {return bin;}
    
private:
    bool __inited;
    std::string bin;
    uint64_t pdstart, pdstop, pdsize;
    uint64_t pcstart, pcstop, pcsize;
    uint64_t pnstart, pnstop, pnsize;
    uint8_t *pd, *pc, *pn;
    unsigned long cr3;
    
    int access_read_linear(bx_address laddr, unsigned len, unsigned curr_pl, unsigned xlate_rw, Bit32u ac_mask, void *data) const;
};

void add_to_source_cov_set(const SourceCov*);
void setup_periodic_coverage();
void check_write_coverage();

#endif