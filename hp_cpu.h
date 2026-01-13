#pragma once

#include "bochs.h"
#include "cpu/cpu.h"

// Legacy globals used throughout HyperPill (e.g., `BX_CPU(id)`).
// Updated by `hp::set_current_cpu()`; prefer `hp::cur_cpu()` / `hp::vcpu()` in new code.
extern thread_local unsigned int id;
extern thread_local unsigned int x;

namespace hp {

unsigned current_cpu();
void set_current_cpu(unsigned cpu);

inline BX_CPU_C *cpu(unsigned cpu) { return BX_CPU(cpu); }
inline BX_CPU_C *vcpu() { return BX_CPU(0); }
inline BX_CPU_C *cur_cpu() { return BX_CPU(current_cpu()); }

inline unsigned num_cpus() {
#if BX_SUPPORT_SMP
	return BX_SMP_PROCESSORS;
#else
	return 1;
#endif
}

} // namespace hp
