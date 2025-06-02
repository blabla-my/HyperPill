#include "tests.h"

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv);

int main(int argc, char **argv) {
    LLVMFuzzerInitialize(&argc, &argv);

test_mem_write(0x182522000UL + 0x802UL, 0x1UL, (void*)"\xbf");
test_mem_write(0x182522000UL + 0x802UL, 0x2UL, (void*)"\x01\x00");
test_mem_write(0x182522000UL + 0x804UL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x804UL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x0UL, 0x10UL, (void*)"\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00");
test_mem_write(0x182522000UL + 0x806UL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x806UL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x904UL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x904UL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x808UL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x808UL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x80aUL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x80aUL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x80cUL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x80cUL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x80eUL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x80eUL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x810UL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x810UL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x812UL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x812UL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x814UL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x814UL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x816UL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x816UL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x818UL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x818UL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x81aUL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x81aUL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x81cUL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x81cUL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x81eUL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x81eUL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x820UL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x820UL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x822UL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x822UL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x824UL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x824UL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x826UL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x826UL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x828UL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x828UL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x82aUL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x82aUL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x82cUL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x82cUL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x182522000UL + 0x82eUL, 0x1UL, (void*)"\x00");
test_mem_write(0x182522000UL + 0x82eUL, 0x2UL, (void*)"\x00\x00");
test_mem_write(0x11f999000UL + 0x0UL, 0x8UL, (void*)"\x00\x00\x00\x00\x00\x00\x00\x00");
test_mmio_write(0xfebfb000UL + 0x0UL, 0x0UL, 0xe3);


    return 0;
}