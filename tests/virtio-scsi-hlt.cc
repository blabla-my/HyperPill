#include "tests.h"

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv);

int main(int argc, char **argv) {
    LLVMFuzzerInitialize(&argc, &argv);

test_mem_write(0x130433000UL + 0x40UL, 0x1UL, (void*)"\x00");
test_mem_write(0x130433000UL + 0x88UL, 0x4UL, (void*)"\x00\x00\x00\x00");
test_mem_write(0x13eb97000UL + 0x2UL, 0x2UL, (void*)"\x6d\x00");
test_mem_write(0x13eb97000UL + 0x1deUL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x13eb97000UL + 0x1e0UL, 0x2UL, (void*)"\x03\x05");
test_mem_write(0x13eb97000UL + 0x2UL, 0x2UL, (void*)"\x6d\x00");
test_mem_write(0x13eb96000UL + 0x0UL, 0x10UL, (void*)"\x25\x00\x5b\x00\x00\x00\x00\x00\x58\x00\x00\x00\x01\x01\xf7\x00");
test_mem_write(0x13eb96000UL + 0xf70UL, 0x10UL, (void*)"\x00\x00\xd7\x00\x00\x00\x00\x00\x00\xc6\xc5\x3f\x01\x01\x07\x00");
test_mem_write(0x13eb96000UL + 0x70UL, 0x10UL, (void*)"\x00\x00\xd7\x20\x00\x00\x00\x00\xc0\x75\x5b\x79\x96\x00\x63\x20");
test_mem_write(0x11cdb0000UL + 0x25UL, 0x20UL, (void*)"\x01\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x40\xef\x00\x00\x32\x00\x00\xef\x46\x55\xba\x2e\xa5\xa5\xa5\xfe\xfd\x03");
test_mem_write(0x11cdb0000UL + 0x38UL, 0x20UL, (void*)"\x00\x00\xef\x46\x55\xba\x2e\xa5\xa5\xa5\xfe\xfd\x03\x2e\x00\x00\x00\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x46\x55\x5a\x00\x5a\x01\xff\x40");
test_mmio_read(0xfebf3000UL + 0x8UL, 0x0UL);
test_mmio_write(0xfebf0000UL + 0x11UL, 0x3UL, 0xffff7e0000000034);


    return 0;
}