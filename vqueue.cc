#include "vqueue.h"
#include "bochs.h"
#include "config.h"
#include "cpu/vmx.h"
#include "fuzz.h"
#include <cstddef>

unsigned ConfigSpace::readw(size_t offset) {
	bx_address addr = address + offset;
	inject_read(addr, 2);
    start_cpu();
	printf("ConfigSpace::readw: start_cpu done\n");
    
    unsigned value = BX_CPU(id)->gen_reg[BX_64BIT_REG_RAX].rrx;
    return value;
}

bx_address ConfigSpace::avail_ring_addr() {
	unsigned avail_lo = readw(VIRTIO_PCI_COMMON_Q_AVAILLO);
	unsigned avail_hi = readw(VIRTIO_PCI_COMMON_Q_AVAILHI);
	return (bx_address)(((bx_address)avail_hi << 32) | avail_lo);	
}

bx_address ConfigSpace::used_ring_addr() {
	unsigned used_lo = readw(VIRTIO_PCI_COMMON_Q_USEDLO);
	unsigned used_hi = readw(VIRTIO_PCI_COMMON_Q_USEDHI);
	return (bx_address)(((bx_address)used_hi << 32) | used_lo);	
}

bx_address ConfigSpace::desc_ring_addr() {
	unsigned desc_lo = readw(VIRTIO_PCI_COMMON_Q_DESCLO);
	unsigned desc_hi = readw(VIRTIO_PCI_COMMON_Q_DESCHI);
	return (bx_address)(((bx_address)desc_hi << 32) | desc_lo);	
}

size_t ConfigSpace::queue_size() {
	unsigned size = readw(VIRTIO_PCI_COMMON_Q_SIZE);
	if (size > VIRTIO_QUEUE_MAX) {
		printf("Queue size %u exceeds maximum %u, clamping to max.\n", size, VIRTIO_QUEUE_MAX);
		size = VIRTIO_QUEUE_MAX;
	}
	return size;
}

bool ConfigSpace::writew(size_t offset, unsigned value) {
    // Implement writing to the config space at the given offset
    // This is a placeholder implementation
    return true;
}