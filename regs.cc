#include <sstream>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <algorithm>
#include <array>
#include <cstring>
#include <map>
#include <regex>

#include "bochs.h"
#include "cpu/cpu.h"
#include "cpu/vmx.h"
#include "pc_system.h"
#include "hp_cpu.h"


//std::cout << "  submatch " << i << ": " << piece << '\n';
#define GETREG32(REG) \
({\
    uint32_t val;\
    std::stringstream ss; \
    std::regex reg_regex(#REG "\\s*=(\\w+)"); \
    std::smatch match; \
    std::regex_search(s, match, reg_regex);\
    assert(match.size() > 1);\
    for (size_t i = 0; i < match.size(); ++i) \
    { \
        std::string piece = match[i].str(); \
    } \
    ss << std::hex << match[1].str(); \
    ss >> val;\
    printf(".info " #REG ": %s %x\n", match[1].str().c_str(), val); \
    val;\
})

#define GETREG64(REG) \
({\
    uint64_t val;\
    std::stringstream ss; \
    std::regex reg_regex("\\b"#REG "\\s*=\\s*(\\w+)"); \
    std::smatch match; \
    std::regex_search(s, match, reg_regex);\
    assert(match.size() > 1);\
    for (size_t i = 0; i < match.size(); ++i) \
    { \
        std::string piece = match[i].str(); \
    } \
    ss << std::hex << match[1].str(); \
    ss >> val;\
    printf(".info " #REG ": %s %lx\n", match[1].str().c_str(), val); \
    val;\
})

static bool parse_hex_u64(const std::string &hex, uint64_t *out)
{
    char *end = NULL;
    unsigned long long val = strtoull(hex.c_str(), &end, 16);
    if (end == hex.c_str()) {
        return false;
    }
    *out = (uint64_t) val;
    return true;
}

static bool parse_fpu_header(const std::string &s, uint16_t *fcw,
                             uint16_t *fsw, uint8_t *ftw, uint32_t *mxcsr)
{
    std::regex re("FCW=([0-9A-Fa-f]+) FSW=([0-9A-Fa-f]+) \\[ST=([0-9]+)\\] FTW=([0-9A-Fa-f]+) MXCSR=([0-9A-Fa-f]+)");
    std::smatch match;
    if (!std::regex_search(s, match, re) || match.size() < 6) {
        return false;
    }

    uint64_t tmp = 0;
    if (!parse_hex_u64(match[1].str(), &tmp)) {
        return false;
    }
    *fcw = (uint16_t) tmp;
    if (!parse_hex_u64(match[2].str(), &tmp)) {
        return false;
    }
    *fsw = (uint16_t) tmp;
    if (!parse_hex_u64(match[4].str(), &tmp)) {
        return false;
    }
    *ftw = (uint8_t) tmp;
    if (!parse_hex_u64(match[5].str(), &tmp)) {
        return false;
    }
    *mxcsr = (uint32_t) tmp;
    return true;
}

static void parse_fpu_state(const std::string &s, unsigned cpu)
{
#if BX_SUPPORT_FPU
    hp::cpu(cpu)->the_i387.init();
    hp::cpu(cpu)->mxcsr.mxcsr = MXCSR_RESET;

    uint16_t fcw = 0x037f;
    uint16_t fsw = 0;
    uint8_t ftw = 0xff;
    uint32_t mxcsr = MXCSR_RESET;

    if (parse_fpu_header(s, &fcw, &fsw, &ftw, &mxcsr)) {
        hp::cpu(cpu)->the_i387.cwd = fcw;
        hp::cpu(cpu)->the_i387.swd = fsw & ~0x3800;
        hp::cpu(cpu)->the_i387.tos = (fsw >> 11) & 0x7;

        uint16_t twd = 0;
        for (int i = 0; i < 8; i++) {
            uint16_t tag = (ftw & (1u << i)) ? 0 : 3;
            twd |= (tag << (i * 2));
        }
        hp::cpu(cpu)->the_i387.twd = twd;

        hp::cpu(cpu)->mxcsr.mxcsr = mxcsr;
    }

    std::regex fpu_ptr_re("FPUIP=([0-9A-Fa-f]+) FPUDP=([0-9A-Fa-f]+) FPUCS=([0-9A-Fa-f]+) FPUDS=([0-9A-Fa-f]+) FPUOP=([0-9A-Fa-f]+)");
    std::smatch ptr_match;
    if (std::regex_search(s, ptr_match, fpu_ptr_re) && ptr_match.size() >= 6) {
        uint64_t tmp = 0;
        if (parse_hex_u64(ptr_match[1].str(), &tmp)) {
            hp::cpu(cpu)->the_i387.fip = (bx_address) tmp;
        }
        if (parse_hex_u64(ptr_match[2].str(), &tmp)) {
            hp::cpu(cpu)->the_i387.fdp = (bx_address) tmp;
        }
        if (parse_hex_u64(ptr_match[3].str(), &tmp)) {
            hp::cpu(cpu)->the_i387.fcs = (uint16_t) tmp;
        }
        if (parse_hex_u64(ptr_match[4].str(), &tmp)) {
            hp::cpu(cpu)->the_i387.fds = (uint16_t) tmp;
        }
        if (parse_hex_u64(ptr_match[5].str(), &tmp)) {
            hp::cpu(cpu)->the_i387.foo = (uint16_t) tmp;
        }
    }

    std::regex fpr_re("FPR(\\d)=([0-9A-Fa-f]{16})\\s+([0-9A-Fa-f]{4})");
    for (std::sregex_iterator it(s.begin(), s.end(), fpr_re), end; it != end; ++it) {
        int reg = std::stoi((*it)[1].str());
        if (reg < 0 || reg >= 8) {
            continue;
        }
        uint64_t lower = 0;
        uint64_t upper = 0;
        if (!parse_hex_u64((*it)[2].str(), &lower) ||
            !parse_hex_u64((*it)[3].str(), &upper)) {
            continue;
        }
        hp::cpu(cpu)->the_i387.st_space[reg].fraction = lower;
        hp::cpu(cpu)->the_i387.st_space[reg].exp = (uint16_t) upper;
    }
#endif
}

static void set_vmm_from_qwords(unsigned cpu, unsigned reg, const uint64_t *qwords,
                                size_t count)
{
    if (reg >= BX_XMM_REGISTERS) {
        return;
    }

    uint8_t buf[64] = {0};
    size_t bytes = std::min(sizeof(buf), count * sizeof(uint64_t));
    for (size_t i = 0; i < count && (i * 8 + 8) <= sizeof(buf); i++) {
        memcpy(buf + i * 8, &qwords[i], 8);
    }

#if BX_SUPPORT_EVEX
    uint8_t *dst = hp::cpu(cpu)->vmm[reg].zmm_ubyte;
    size_t dst_len = 64;
#elif BX_SUPPORT_AVX
    uint8_t *dst = hp::cpu(cpu)->vmm[reg].ymm_ubyte;
    size_t dst_len = 32;
#else
    uint8_t *dst = hp::cpu(cpu)->vmm[reg].xmm_ubyte;
    size_t dst_len = 16;
#endif

    memset(dst, 0, dst_len);
    memcpy(dst, buf, std::min(bytes, dst_len));
}

static bool parse_zmm_regs(const std::string &s, unsigned cpu)
{
    bool found = false;
    std::regex zmm_re("ZMM(\\d\\d)=([0-9A-Fa-f]{16})\\s+([0-9A-Fa-f]{16})\\s+([0-9A-Fa-f]{16})\\s+([0-9A-Fa-f]{16})\\s+([0-9A-Fa-f]{16})\\s+([0-9A-Fa-f]{16})\\s+([0-9A-Fa-f]{16})\\s+([0-9A-Fa-f]{16})");
    for (std::sregex_iterator it(s.begin(), s.end(), zmm_re), end; it != end; ++it) {
        int reg = std::stoi((*it)[1].str());
        uint64_t q[8] = {};
        for (int i = 0; i < 8; i++) {
            uint64_t val = 0;
            if (!parse_hex_u64((*it)[2 + i].str(), &val)) {
                val = 0;
            }
            q[7 - i] = val;
        }
        set_vmm_from_qwords(cpu, (unsigned) reg, q, 8);
        found = true;
    }
    return found;
}

static bool parse_ymm_regs(const std::string &s, unsigned cpu)
{
    bool found = false;
    std::regex ymm_re("YMM(\\d\\d)=([0-9A-Fa-f]{16})\\s+([0-9A-Fa-f]{16})\\s+([0-9A-Fa-f]{16})\\s+([0-9A-Fa-f]{16})");
    for (std::sregex_iterator it(s.begin(), s.end(), ymm_re), end; it != end; ++it) {
        int reg = std::stoi((*it)[1].str());
        uint64_t q[4] = {};
        for (int i = 0; i < 4; i++) {
            uint64_t val = 0;
            if (!parse_hex_u64((*it)[2 + i].str(), &val)) {
                val = 0;
            }
            q[3 - i] = val;
        }
        set_vmm_from_qwords(cpu, (unsigned) reg, q, 4);
        found = true;
    }
    return found;
}

static void parse_xmm_regs(const std::string &s, unsigned cpu)
{
    std::regex xmm_re("XMM(\\d\\d)=([0-9A-Fa-f]{16})\\s+([0-9A-Fa-f]{16})");
    for (std::sregex_iterator it(s.begin(), s.end(), xmm_re), end; it != end; ++it) {
        int reg = std::stoi((*it)[1].str());
        uint64_t q[2] = {};
        uint64_t val = 0;
        if (parse_hex_u64((*it)[2].str(), &val)) {
            q[1] = val;
        }
        if (parse_hex_u64((*it)[3].str(), &val)) {
            q[0] = val;
        }
        set_vmm_from_qwords(cpu, (unsigned) reg, q, 2);
    }
}

static void parse_opmask_regs(const std::string &s, unsigned cpu)
{
#if BX_SUPPORT_EVEX
    std::regex opmask_re("Opmask(\\d\\d)=([0-9A-Fa-f]{16})");
    for (std::sregex_iterator it(s.begin(), s.end(), opmask_re), end; it != end; ++it) {
        int reg = std::stoi((*it)[1].str());
        if (reg < 0 || reg >= 8) {
            continue;
        }
        uint64_t val = 0;
        if (parse_hex_u64((*it)[2].str(), &val)) {
            hp::cpu(cpu)->set_opmask((unsigned) reg, val);
        }
    }
#else
    (void) s;
#endif
}

static bool parse_apic_regs(const std::string &s, std::map<uint32_t, uint32_t> *regs)
{
    std::regex reg_re("APIC_REG\\s+0x([0-9A-Fa-f]+)\\s+0x([0-9A-Fa-f]+)");
    for (std::sregex_iterator it(s.begin(), s.end(), reg_re), end; it != end; ++it) {
        uint64_t off = 0;
        uint64_t val = 0;
        if (!parse_hex_u64((*it)[1].str(), &off) ||
            !parse_hex_u64((*it)[2].str(), &val)) {
            continue;
        }
        (*regs)[(uint32_t) off] = (uint32_t) val;
    }
    return !regs->empty();
}

static void apply_lapic_regs(unsigned cpu, const std::map<uint32_t, uint32_t> &regs)
{
#if BX_SUPPORT_APIC
    auto set_reg = [&](uint32_t reg, uint32_t value) {
        hp::cpu(cpu)->lapic.write_aligned(reg, value);
    };

    auto it = regs.find(BX_LAPIC_TPR);
    if (it != regs.end()) set_reg(BX_LAPIC_TPR, it->second);
    it = regs.find(BX_LAPIC_LDR);
    if (it != regs.end()) set_reg(BX_LAPIC_LDR, it->second);
    it = regs.find(BX_LAPIC_DESTINATION_FORMAT);
    if (it != regs.end()) set_reg(BX_LAPIC_DESTINATION_FORMAT, it->second);
    it = regs.find(BX_LAPIC_SPURIOUS_VECTOR);
    if (it != regs.end()) set_reg(BX_LAPIC_SPURIOUS_VECTOR, it->second);

    it = regs.find(BX_LAPIC_ICR_HI);
    if (it != regs.end()) set_reg(BX_LAPIC_ICR_HI, it->second);

    it = regs.find(BX_LAPIC_LVT_TIMER);
    if (it != regs.end()) set_reg(BX_LAPIC_LVT_TIMER, it->second);
    it = regs.find(BX_LAPIC_LVT_THERMAL);
    if (it != regs.end()) set_reg(BX_LAPIC_LVT_THERMAL, it->second);
    it = regs.find(BX_LAPIC_LVT_PERFMON);
    if (it != regs.end()) set_reg(BX_LAPIC_LVT_PERFMON, it->second);
    it = regs.find(BX_LAPIC_LVT_LINT0);
    if (it != regs.end()) set_reg(BX_LAPIC_LVT_LINT0, it->second);
    it = regs.find(BX_LAPIC_LVT_LINT1);
    if (it != regs.end()) set_reg(BX_LAPIC_LVT_LINT1, it->second);
    it = regs.find(BX_LAPIC_LVT_ERROR);
    if (it != regs.end()) set_reg(BX_LAPIC_LVT_ERROR, it->second);
    it = regs.find(BX_LAPIC_LVT_CMCI);
    if (it != regs.end()) set_reg(BX_LAPIC_LVT_CMCI, it->second);

    it = regs.find(BX_LAPIC_TIMER_INITIAL_COUNT);
    if (it != regs.end()) set_reg(BX_LAPIC_TIMER_INITIAL_COUNT, it->second);
    it = regs.find(BX_LAPIC_TIMER_DIVIDE_CFG);
    if (it != regs.end()) set_reg(BX_LAPIC_TIMER_DIVIDE_CFG, it->second);
#endif
}

static void restore_lapic_pending_irqs(unsigned cpu,
                                       const std::map<uint32_t, uint32_t> &regs)
{
#if BX_SUPPORT_APIC
    uint32_t irr[8] = {};
    uint32_t tmr[8] = {};

    for (int i = 0; i < 8; i++) {
        auto it = regs.find(BX_LAPIC_IRR1 + i * 0x10);
        if (it != regs.end()) {
            irr[i] = it->second;
        }
        it = regs.find(BX_LAPIC_TMR1 + i * 0x10);
        if (it != regs.end()) {
            tmr[i] = it->second;
        }
    }

    for (int vec = 0; vec < 256; vec++) {
        int idx = vec >> 5;
        uint32_t mask = 1u << (vec & 0x1f);
        if (irr[idx] & mask) {
            unsigned trig = (tmr[idx] & mask) ? APIC_LEVEL_TRIGGERED : APIC_EDGE_TRIGGERED;
            hp::cpu(cpu)->lapic.trigger_irq((Bit8u) vec, trig, 1);
        }
    }
#endif
}


#define LOADREG(NREG, REG ) \
{\
    uint64_t val;\
    std::stringstream ss; \
    std::regex reg_regex(#REG "\\s*=(\\w+)"); \
    std::smatch match; \
    std::regex_search(s, match, reg_regex);\
    assert(match.size() > 1);\
    for (size_t i = 0; i < match.size(); ++i) \
    { \
        std::string piece = match[i].str(); \
    } \
    ss << std::hex << match[1].str(); \
    ss >> val;\
    printf(".info " #REG ": %s %lx\n", match[1].str().c_str(), val); \
    hp::cpu(cpu)->set_reg64(NREG, val); \
};

#define LOADSEG(NREG, REG ) \
{\
    uint16_t raw_selector;\
    uint64_t base;\
    uint32_t limit_scaled;\
    uint32_t ar_data;\
    bool present =1;\
    std::stringstream ss; \
    std::regex reg_regex(#REG "\\s*=(\\w+)\\s+(\\w+)\\s+(\\w+)\\s+(\\w+)\\s+DPL.*"); \
    std::smatch match; \
    std::regex_search(s, match, reg_regex);\
    if(match.size() < 1){\
        std::regex reg_regex2(#REG "\\s*=(\\w+)\\s+(\\w+)\\s+(\\w+)\\s+(\\w+)"); \
        std::regex_search(s, match, reg_regex2);\
        present = 0;\
    }\
    assert(match.size() > 1);\
    for (size_t i = 0; i < match.size(); ++i) \
    { \
        std::string piece = match[i].str(); \
    } \
    ss << std::hex << match[1].str(); \
    ss >> raw_selector;\
    ss.clear();\
    ss << std::hex << match[2].str(); \
    ss >> base;\
    ss.clear();\
    ss << std::hex << match[3].str(); \
    ss >> limit_scaled;\
    ss.clear();\
    ss << std::hex << match[4].str(); \
    ss >> ar_data;\
    ar_data = (ar_data >> 8);\
    ss.clear();\
    printf(".info " #REG ": present=%d %x %lx %x %x\n", present, raw_selector, base, limit_scaled, ar_data); \
    hp::cpu(cpu)->set_segment_ar_data(NREG , \
            present, raw_selector, base, limit_scaled, ar_data);\
};
    /* BX_CPU(id)->set_segment_ar_data(NREG , \ */
    /*         (ar_data >> 8) & 1, raw_selector, base, limit_scaled, ar_data);\ */

#define LOADDT(NREG, REG ) \
{\
    uint64_t base;\
    uint16_t limit;\
    std::stringstream ss; \
    std::regex reg_regex(#REG "=\\s*(\\w+)\\s+(\\w+)"); \
    std::smatch match; \
    std::regex_search(s, match, reg_regex);\
    assert(match.size() > 1);\
    for (size_t i = 0; i < match.size(); ++i) \
    { \
        std::string piece = match[i].str(); \
    } \
    ss << std::hex << match[1].str(); \
    ss >> base;\
    ss.clear();\
    ss << std::hex << match[2].str(); \
    ss >> limit;\
    ss.clear();\
    printf(".info " #REG ": %lx %x\n", base, limit); \
    NREG.base = base;\
    NREG.limit = limit;\
};

void icp_init_regs_cpu(const char* filename, unsigned cpu) {
    std::ifstream t(filename);
    std::stringstream buffer;
    buffer << t.rdbuf();

    hp::set_current_cpu(cpu);
    printf(".loading registers from %s (cpu %u)\n", filename, cpu);
    std::string s = buffer.str();

    uint64_t val = GETREG64(RIP);
    hp::cpu(cpu)->gen_reg[BX_64BIT_REG_RIP].rrx = val;
    hp::cpu(cpu)->prev_rip = val;
    

    val = GETREG64(RSP);
    hp::cpu(cpu)->gen_reg[BX_64BIT_REG_RSP].rrx = val;
    hp::cpu(cpu)->prev_rsp = val;

    LOADREG(0, RAX);
    LOADREG(1, RCX);
    LOADREG(2, RDX);
    LOADREG(3, RBX);
    LOADREG(5, RBP);
    LOADREG(6, RSI);
    LOADREG(7, RDI);
    LOADREG(8, R8);
    LOADREG(9, R9);
    LOADREG(10, R10);
    LOADREG(11, R11);
    LOADREG(12, R12);
    LOADREG(13, R13);
    LOADREG(14, R14);
    LOADREG(15, R15);

    hp::cpu(cpu)->setEFlags(GETREG64(RFL));

    LOADSEG(&hp::cpu(cpu)->sregs[0], ES );
    LOADSEG(&hp::cpu(cpu)->sregs[1], CS );
    LOADSEG(&hp::cpu(cpu)->sregs[2], SS );
    LOADSEG(&hp::cpu(cpu)->sregs[3], DS );
    LOADSEG(&hp::cpu(cpu)->sregs[4], FS );
    LOADSEG(&hp::cpu(cpu)->sregs[5], GS );

    LOADSEG(&hp::cpu(cpu)->ldtr, LDT );
    LOADSEG(&hp::cpu(cpu)->tr, TR );
    
    LOADDT(hp::cpu(cpu)->gdtr, GDT );
    LOADDT(hp::cpu(cpu)->idtr, IDT );

    hp::cpu(cpu)->dr[0] = GETREG64(DR0);
    hp::cpu(cpu)->dr[1] = GETREG64(DR1);
    hp::cpu(cpu)->dr[2] = GETREG64(DR2);
    hp::cpu(cpu)->dr[3] = GETREG64(DR3);
    hp::cpu(cpu)->dr6.set32(GETREG32(DR6));
    hp::cpu(cpu)->dr7.set32(GETREG32(DR7));
    
    hp::cpu(cpu)->cr0.set32(GETREG32(CR0));
    hp::cpu(cpu)->cr2 = GETREG64(CR2);
    hp::cpu(cpu)->cr3 = GETREG64(CR3);
    hp::cpu(cpu)->cr4.set32(GETREG32(CR4));
    if (!getenv("NOCOV")) {
        hp::cpu(cpu)->cr4.set_SMAP(false);
    }
    
    hp::cpu(cpu)->xcr0.set32((Bit32u) GETREG64(xcr0));

    hp::cpu(cpu)->msr.kernelgsbase = GETREG64(kernelgsbase);
    hp::cpu(cpu)->msr.sysenter_cs_msr = GETREG64(sysenter_cs);
    hp::cpu(cpu)->msr.sysenter_esp_msr = GETREG64(sysenter_esp);
    hp::cpu(cpu)->msr.sysenter_eip_msr = GETREG64(sysenter_eip);
    hp::cpu(cpu)->efer.set32(GETREG32(EFER));
    hp::cpu(cpu)->msr.star = GETREG64(star); // Check it
    hp::cpu(cpu)->msr.lstar = GETREG64(lstar);
    hp::cpu(cpu)->msr.cstar = GETREG64(cstar);
    hp::cpu(cpu)->msr.fmask = GETREG64(fmask);
    
    uint64_t tsc = GETREG64(tsc);
    int64_t tsc_adjust = (int64_t) GETREG64(tsc_adjust);
    uint64_t tsc_factor = 1;
    const char *tsc_factor_env = getenv("TSC_FACTOR");
    if (tsc_factor_env) {
        tsc_factor = strtoull(tsc_factor_env, NULL, 10);
        if (tsc_factor == 0) {
            tsc_factor = 1;
        }
    }
    int64_t ticks = (int64_t) (tsc / tsc_factor) - tsc_adjust;
    if (ticks < 0) {
        ticks = 0;
    }
    if (cpu == 0) {
        bx_pc_system.set_time_ticks((Bit64u) ticks);
    }
    hp::cpu(cpu)->tsc_adjust = (Bit64s) tsc_adjust;
    hp::cpu(cpu)->msr.tsc_aux = GETREG64(tsc_aux);
    
    hp::cpu(cpu)->msr.pat._u64 = GETREG64(pat);
    hp::cpu(cpu)->msr.apicbase = GETREG64(apicbase);
    

    hp::cpu(cpu)->TLB_flush();
#if BX_CPU_LEVEL >= 4
    hp::cpu(cpu)->handleAlignmentCheck(/* CR0.AC reloaded */);
#endif

    hp::cpu(cpu)->handleCpuModeChange();

#if BX_SUPPORT_X86_64
    if (hp::cpu(cpu)->efer.get_LMA()) {
        Bit64u gs_base = hp::cpu(cpu)->sregs[BX_SEG_REG_GS].cache.u.segment.base;
        Bit64u kgs_base = hp::cpu(cpu)->msr.kernelgsbase;
        Bit8u cpl = hp::cpu(cpu)->sregs[BX_SEG_REG_CS].selector.rpl;
        bool gs_kernel = (gs_base >> 47) & 1;
        bool kgs_kernel = (kgs_base >> 47) & 1;

        if ((cpl == 0 && !gs_kernel && kgs_kernel) ||
            (cpl == 3 && gs_kernel && !kgs_kernel)) {
            hp::cpu(cpu)->sregs[BX_SEG_REG_GS].cache.u.segment.base = kgs_base;
            hp::cpu(cpu)->msr.kernelgsbase = gs_base;
        }
    }
#endif

#if BX_CPU_LEVEL >= 6
    hp::cpu(cpu)->handleSseModeChange();
    hp::cpu(cpu)->handleAvxModeChange();
#endif

    parse_fpu_state(s, cpu);
    bool have_zmm = parse_zmm_regs(s, cpu);
    bool have_ymm = false;
    if (!have_zmm) {
        have_ymm = parse_ymm_regs(s, cpu);
    }
    if (!have_zmm && !have_ymm) {
        parse_xmm_regs(s, cpu);
    }
    parse_opmask_regs(s, cpu);

#if BX_SUPPORT_APIC
    hp::cpu(cpu)->lapic.set_base(hp::cpu(cpu)->msr.apicbase);
    std::map<uint32_t, uint32_t> apic_regs;
    bool have_apic_regs = parse_apic_regs(s, &apic_regs);
    if (have_apic_regs) {
        apply_lapic_regs(cpu, apic_regs);
        restore_lapic_pending_irqs(cpu, apic_regs);
    } else {
        Bit32u spiv = hp::cpu(cpu)->lapic.read_aligned(BX_LAPIC_SPURIOUS_VECTOR);
        hp::cpu(cpu)->lapic.write_aligned(BX_LAPIC_SPURIOUS_VECTOR, spiv | 0x100);
        hp::cpu(cpu)->lapic.set_lvt_entry(BX_LAPIC_LVT_TIMER, 0x000400ec);
    }
    Bit32u lvt_timer = hp::cpu(cpu)->lapic.read_aligned(BX_LAPIC_LVT_TIMER);
    if (lvt_timer & 0x40000) {
        hp::cpu(cpu)->lapic.set_tsc_deadline(GETREG64(tsc_deadline));
    }
#endif

#if BX_SUPPORT_SMP
    // Bochs resets application processors (APs) into WAIT_FOR_SIPI. When we
    // restore a running snapshot, ensure we don't keep CPUs parked there.
    if (hp::num_cpus() > 1 &&
        hp::cpu(cpu)->activity_state == BX_CPU_C::BX_ACTIVITY_STATE_WAIT_FOR_SIPI) {
        hp::cpu(cpu)->activity_state = BX_CPU_C::BX_ACTIVITY_STATE_ACTIVE;
        hp::cpu(cpu)->unmask_event(BX_EVENT_INIT | BX_EVENT_SMI | BX_EVENT_NMI);
    }
#endif

}

void icp_set_vmcs(uint64_t vmcs) {
    /* BX_CPU(id)->vmcshostptr = BX_CPU(id)->getHostMemAddr(vmcs, BX_WRITE); */
    for(int i=0; i<0x10000; i+=0x1000)
        hp::vcpu()->getHostMemAddr(vmcs+i, BX_WRITE);
    hp::vcpu()->vmcsptr = vmcs;
    hp::vcpu()->vmxonptr = 0xdeadbeef;
    hp::vcpu()->in_vmx = true;
    hp::vcpu()->vmcs.eptptr = (bx_phy_address) hp::vcpu()->VMread64(VMCS_64BIT_CONTROL_EPTPTR);
    hp::vcpu()->VMwrite32(VMCS_LAUNCH_STATE_FIELD_ENCODING, VMCS_STATE_LAUNCHED);
    hp::vcpu()->vmcs_map->set_access_rights_format(VMCS_AR_OTHER);
}


void fuzz_reset_registers() {
}
