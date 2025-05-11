#include "tests.h"

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv);

int main(int argc, char **argv) {
    LLVMFuzzerInitialize(&argc, &argv);

    // test_mem_write_up_to_8(0x1828f5242, 1, 0xde);
    // test_mem_write_up_to_8(0x1828f5242, 1, 0xad);
    // test_mem_write_up_to_8(0x1828f7242, 1, 0xbe);
    // test_mem_write_up_to_8(0x1828f7242, 1, 0xef);

    // test_mmio_read(0xfebfcf45, 0);
    // test_mmio_read(0xfebfc179, 3);
    // test_mmio_write(0xfebfc013, 3, 0x4065a5a554600);
    // test_mmio_write(0xfebfc013, 3, 0xad3d3d3d3d3);
    // test_mmio_write(0xfebfc013, 3, 0xb04065a5a554600);

    test_mem_write_up_to_8(0, 8, 0x0045000000000000);
    test_out(0xc099, 1, 0x7a);
    test_mmio_read(0x2fff, 1);
    test_clock_step(); 
}