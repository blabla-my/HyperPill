#include "vqueue.h"
#include "bochs.h"
#include "config.h"
#include "cpu/vmx.h"
#include "fuzz.h"
#include <cstddef>
#include <cstdint>

/* VQueue */

/* ConfigSpace */
unsigned long ConfigSpace::read(size_t offset, size_t size) const {
	bx_address addr = address + offset;
	switch (size) {
	case sizeof(uint8_t): 
		inject_read(addr, 0);
		break;
	case sizeof(uint16_t): 
		inject_read(addr, 1);
		break;
	case sizeof(uint32_t): 
		inject_read(addr, 2);
		break;
	case sizeof(uint64_t):
		inject_read(addr, 3);
		break;
	default:
		printf("Unsupported read size %zu in ConfigSpace::read\n", size);
		return 0;
	}
    start_cpu();
    
	unsigned long mask = (1ULL << (size * 8)) - 1;
    unsigned long value = BX_CPU(id)->gen_reg[BX_64BIT_REG_RAX].rrx & mask;
    return value;
}

bx_address ConfigSpace::get_avail_ring_addr() const {
	unsigned avail_lo = read(VIRTIO_PCI_COMMON_Q_AVAILLO, sizeof(unsigned));
	unsigned avail_hi = read(VIRTIO_PCI_COMMON_Q_AVAILHI, sizeof(unsigned));
	return (bx_address)(((bx_address)avail_hi << 32) | avail_lo);	
}

bx_address ConfigSpace::get_used_ring_addr() const {
	unsigned used_lo = read(VIRTIO_PCI_COMMON_Q_USEDLO, sizeof(unsigned));
	unsigned used_hi = read(VIRTIO_PCI_COMMON_Q_USEDHI, sizeof(unsigned));
	return (bx_address)(((bx_address)used_hi << 32) | used_lo);	
}

bx_address ConfigSpace::get_desc_ring_addr() const {
	unsigned desc_lo = read(VIRTIO_PCI_COMMON_Q_DESCLO, sizeof(unsigned));
	unsigned desc_hi = read(VIRTIO_PCI_COMMON_Q_DESCHI, sizeof(unsigned));
	return (bx_address)(((bx_address)desc_hi << 32) | desc_lo);	
}

size_t ConfigSpace::get_queue_size() const {
	uint16_t size = read(VIRTIO_PCI_COMMON_Q_SIZE, sizeof(uint16_t));
	if (size > VIRTIO_QUEUE_MAX) {
		printf("Queue size %u exceeds maximum %u, clamping to max.\n", size, VIRTIO_QUEUE_MAX);
		size = VIRTIO_QUEUE_MAX;
	}
	return (size_t)size;
}

size_t ConfigSpace::get_queue_num() const {
	uint16_t num = read(VIRTIO_PCI_COMMON_NUMQ, sizeof(uint16_t));
	return (size_t)num;
}

size_t ConfigSpace::get_queue_sel() const {
	uint16_t sel = read(VIRTIO_PCI_COMMON_Q_SELECT, sizeof(uint16_t));
	return (size_t)sel;
}

void ConfigSpace::set_queue_num(size_t num) const {
	if (num > VIRTIO_QUEUE_MAX) {
		printf("Queue number %zu exceeds maximum %u, clamping to max.\n", num, VIRTIO_QUEUE_MAX);
		num = VIRTIO_QUEUE_MAX;
	}
	write(VIRTIO_PCI_COMMON_NUMQ, sizeof(uint16_t), (unsigned long)num);
}

void ConfigSpace::set_queue_sel(size_t sel) const {
	if (sel > VIRTIO_QUEUE_MAX) {
		printf("Queue selection %zu exceeds maximum %u, clamping to max.\n", sel, VIRTIO_QUEUE_MAX);
		sel = VIRTIO_QUEUE_MAX;
	}
	write(VIRTIO_PCI_COMMON_Q_SELECT, sizeof(uint16_t), (uint16_t)sel);
}

bool ConfigSpace::write(size_t offset, size_t size, unsigned long value) const {
	bx_address addr = address + offset;
	bool inject_ok;
	switch (size) {
	case sizeof(uint8_t): 
		inject_ok = inject_write(addr, 0, value);
		break;
	case sizeof(uint16_t): 
		inject_ok = inject_write(addr, 1, value);
		break;
	case sizeof(uint32_t): 
		inject_ok = inject_write(addr, 2, value);
		break;
	case sizeof(uint64_t):
		inject_ok = inject_write(addr, 3, value);
		break;
	default:
		printf("Unsupported read size %zu in ConfigSpace::read\n", size);
		return 0;
	}
	if (!inject_ok) 
		return false;

    start_cpu();
    
    return true;
}

/* VirtioDev */
VirtioDev::VirtioDev() {
	memset(this, 0, sizeof(VirtioDev));
}

void VirtioDev::enumerate_queues_from_common_cfg() {
	if (common_cfg.type != ConfigSpace::COMMON) {
		printf("Common config space not set for device %s, cannot enumerate queues.\n", name);
		return;
	}
	size_t queue_num = common_cfg.get_queue_num();
	size_t old_queue_sel = common_cfg.get_queue_sel();
	if (queue_num > VIRTIO_QUEUE_MAX) {
		printf("Warning: Queue number %lx exceeds maximum %u, clamping to max.\n", queue_num, VIRTIO_QUEUE_MAX);
		queue_num = 1;
	}
	printf("VirtioDev %s: Found %lx queues in common config space, currently at %lx.\n", name, queue_num, old_queue_sel);


	for (size_t i = 0; i < queue_num; i++) {
		common_cfg.set_queue_sel(i);
		size_t queue_size = common_cfg.get_queue_size();
		bx_address avail_ring_addr = common_cfg.get_avail_ring_addr();	
		bx_address used_ring_addr = common_cfg.get_used_ring_addr();
		bx_address desc_ring_addr = common_cfg.get_desc_ring_addr();
		if (i < VIRTIO_QUEUE_MAX) {
			queues[i].desc = {queue_size, desc_ring_addr, VRing::VRING_DESC};
			queues[i].avail = {queue_size, avail_ring_addr, VRing::VRING_AVAIL};
			queues[i].used = {queue_size, used_ring_addr, VRing::VRING_USED};
			printf("#QUEUE_ENUM: {dev: \"%s\", queue_sel: %lx, size: %lx, desc: %lx, avail: %lx, used: %lx}\n", 
				   name, i, queue_size, desc_ring_addr, avail_ring_addr, used_ring_addr);
		} else {
			printf("Warning: Queue %lx exceeds maximum %u, skipping.\n", i, VIRTIO_QUEUE_MAX);
			break;
		}
	}

	// reset queue selection to the old value
	common_cfg.set_queue_sel(old_queue_sel);
}

/* VQueueManager */
tsl::robin_map<std::string, VirtioDev> VQueueManager::virtio_devs;

bool VQueueManager::create_virtio_device(const std::string& name) {
	if (virtio_devs.find(name) != virtio_devs.end()) {
		printf("Virtio device %s already exists.\n", name.c_str());
		return false;
	}
	virtio_devs[name] = VirtioDev();
	strcpy(virtio_devs[name].name, name.c_str());
	return true;
}

void VQueueManager::add_config_space(const std::string& name, enum ConfigSpace::ConfigSpaceType type,
									 unsigned long address, size_t size) {
	auto it = virtio_devs.find(name);
	if (it == virtio_devs.end()) {
		printf("Virtio device %s not found.\n", name.c_str());
		return;
	}
	VirtioDev &dev = virtio_devs[name];
	switch (type) {
		case ConfigSpace::COMMON:
			dev.common_cfg = {address, size, type};
			dev.enumerate_queues_from_common_cfg();
			break;
		case ConfigSpace::ISR:
			dev.isr_cfg = {address, size, type};
			break;
		case ConfigSpace::DEVICE:
			dev.device_cfg = {address, size, type};
			break;
		case ConfigSpace::NOTIFY:
			dev.notify_cfg = {address, size, type};
			break;
		default:
			printf("Unknown config space type %d for device %s.\n", type, name.c_str());
			return;
	}
}