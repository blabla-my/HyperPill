#pragma once

#include "bochs.h"
#include "cpu/cpu.h"

namespace hp {

inline BX_CPU_C *cpu(unsigned cpu) { return BX_CPU(cpu); }
inline BX_CPU_C *vcpu() { return BX_CPU(0); }

inline unsigned num_cpus() {
#if BX_SUPPORT_SMP
	return BX_SMP_PROCESSORS;
#else
	return 1;
#endif
}

} // namespace hp
