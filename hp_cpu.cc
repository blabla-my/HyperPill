#include "hp_cpu.h"

thread_local unsigned int id = 0;
thread_local unsigned int x = 0;

namespace hp {
static thread_local unsigned tls_current_cpu = 0;

unsigned current_cpu() { return tls_current_cpu; }
void set_current_cpu(unsigned cpu) {
	tls_current_cpu = cpu;
	::id = cpu;
	::x = cpu;
}
} // namespace hp
