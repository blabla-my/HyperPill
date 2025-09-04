#include "virtio.h"
#include "bochs.h"
#include "config.h"
#include "cpu/cpu.h"
#include "cpu/vmx.h"
#include "fuzz.h"
#include <bits/types/struct_iovec.h>
#include <cstddef>
#include <cstdint>
#include "conveyor.h"

/* global variables */

/* VRing */
VRing::VRing(size_t size, bx_address addr_gpa, VQueue* vqueue): size(size), addr_gpa(addr_gpa), 
										type(VRING_BASE), align(VRING_BASE_ALIGN) {
	addr_hpa = 0UL;
	vmcs_translate_guest_physical_ept(addr_gpa, &addr_hpa, NULL);
	queue = vqueue;
	printf("VRing: hpa %lx, size: %lx, vqueue: %p\n", addr_hpa, size, queue);
}

int VRing::ingest_idx(uint16_t *idx) const {
	// read last index
	if (!addr_hpa) return -2;
	uint16_t last_idx;
	BX_CPU(x)->access_read_physical(addr_hpa + sizeof(uint16_t), sizeof(last_idx), &last_idx);
	if(ic_ingest16(idx, last_idx, last_idx + 0x30) < 0) {
		printf("failed to inject vring index!\n");
		return -1;
	}
	printf("!virtio: inject vring %s index %.2x\n", type_str(), *idx);
	return 0;
}

/* AvailRing */
int AvailRing::ingest_elem(void* opaque) const {
	auto* avail_elem_ptr = (vring_avail_elem*)opaque;
	if(ic_ingest16(avail_elem_ptr, 0, size) < 0){
		return -1;
	}
	/* every time the avail ring is touched, reset desc chain fsm */
	queue->desc_chain_fsm.reset();
	queue->desc_chain_fsm.init(size);
	printf("!virtio: inject vring %s elem, size: %lx: ", type_str(), element_size());
	for (int i = 0; i < element_size(); i++){
		printf("%.2x", *((uint8_t*)opaque + i));
	}
	printf("\n");
	return 0;
}
VRing::FILED_TYPE AvailRing::filed_type(bx_address address) const {
	assert(address >= start() && address < end());
	bx_address offset = address - start();
	if (offset < sizeof(uint16_t)){
		return VRing::FILED_TYPE::FLAGS;
	}
	else if (offset < sizeof(uint16_t)*2) {
		return VRing::FILED_TYPE::INDEX;
	} else {
		return VRing::FILED_TYPE::VRING_ELEM;
	}
}

/* UsedRing */
int UsedRing::ingest_elem(void* opaque) const {
	auto* used_elem_ptr = (vring_used_elem*)opaque;
	if(ic_ingest64((uint64_t*)used_elem_ptr, 0, -1) < 0){
		return -1;
	}
	printf("!virtio: inject vring %s elem, size: %lx: ", type_str(), element_size());
	for (int i = 0; i < element_size(); i++){
		printf("%.2x", *((uint8_t*)opaque + i));
	}
	printf("\n");
	return 0;
}
VRing::FILED_TYPE UsedRing::filed_type(bx_address address) const {
	bx_address offset = address - start();
	if (offset < sizeof(uint16_t)){
		return VRing::FILED_TYPE::FLAGS;
	}
	else if (offset < sizeof(uint16_t)*2) {
		return VRing::FILED_TYPE::INDEX;
	} else {
		return VRing::FILED_TYPE::VRING_ELEM;
	}
}

/* DescRing */
int DescRing::ingest_elem(void* opaque) const {
	auto* desc_ptr = (vring_desc*)opaque;
	if (ic_ingest64(&desc_ptr->addr, 0x10000, GUEST_MEM_SIZE-1) < 0){
		return -1;	
	}
	// this upperbound and lowerbound are just for testing
	if (ic_ingest32(&desc_ptr->len, 0x10, 0x1000) < 0){
		return -1;	
	}
	/* TODO: flags should not be randomized(?) */
	if (ic_ingest16(&desc_ptr->flags, 0, -1) < 0){
		return -1;
	}
	while (true){
		if (ic_ingest16(&desc_ptr->next, 0, size-1) < 0){
			return -1;
		}
		if (!queue->desc_chain_fsm.has_used_index(desc_ptr->next)){
			queue->desc_chain_fsm.add_used_index(desc_ptr->next);
			break;
		}
	}
	// desc_ptr->addr should be page-aligned
	desc_ptr->addr = desc_ptr->addr & (~((1<<PAGE_SHIFT) - 1));
	// desc_ptr->addr = desc_ptr->addr & (~0xf);
	// desc_ptr->len should be 0x10-aligned
	desc_ptr->len = desc_ptr->len & (~0xf);
	// desc_ptr->flag should be set according to desc FSM
	desc_ptr->flags = 0;
	if (queue->desc_chain_fsm.is_done()){
		/* do not chaining */
		desc_ptr->flags &= ~VRING_DESC_F_NEXT;
		queue->desc_chain_fsm.reset();
	}
	else if (queue->desc_chain_fsm.is_inited()){
		DescChainFSM::SGType sg_type = queue->desc_chain_fsm.consume();
		switch (sg_type) {
			case DescChainFSM::SGType::OUT:
				printf("Setting desc as OUT\n");
				desc_ptr->flags |= VRING_DESC_F_NEXT;
				desc_ptr->flags &= ~VRING_DESC_F_WRITE;
				break;
			case DescChainFSM::SGType::IN:
				printf("Setting desc as IN\n");
				desc_ptr->flags |= (VRING_DESC_F_WRITE | VRING_DESC_F_NEXT);
				break;
			case DescChainFSM::SGType::TAIL:
				printf("Setting desc as TAIL\n");
				desc_ptr->flags |= VRING_DESC_F_WRITE;
				desc_ptr->flags &= ~VRING_DESC_F_NEXT;
				break;
			case DescChainFSM::SGType::NONE:
				break;
		}
	}
	printf("!virtio: inject vring %s elem, size: %lx, addr: %lx, len: %x, next: %x, flags: %x\n", 
		type_str(), element_size(),
		desc_ptr->addr, desc_ptr->len, desc_ptr->next, desc_ptr->flags);
	for (int i = 0; i < element_size(); i++){
		printf("%.2x", *((uint8_t*)opaque + i));
	}
	printf("\n");
	return 0;
}

/* VQueue */
void VQueue::reset(){
	desc_chain_fsm.reset();	
}

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
    start_cpu(true);
    
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

    start_cpu(true);
    
    return true;
}

/* VirtioDev */
VirtioDev::VirtioDev() {
	// memset(this, 0, sizeof(VirtioDev));
	memset(this, 0, sizeof(name));
}

void VirtioDev::enumerate_queues_from_common_cfg() {
	if (common_cfg.type != ConfigSpace::COMMON) {
		printf("Common config space not set for device %s, cannot enumerate queues.\n", name);
		return;
	}
	queue_num = common_cfg.get_queue_num();
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
			queues[i] = new VQueue{};
			queues[i]->desc_ring = new DescRing{queue_size, desc_ring_addr, queues[i]};
			queues[i]->avail_ring = new AvailRing{queue_size, avail_ring_addr, queues[i]};
			queues[i]->used_ring = new UsedRing{queue_size, used_ring_addr, queues[i]};
			printf("#QUEUE_ENUM dev: %s, queue sel: %lx, size: %lx, desc: %lx, avail: %lx, used: %lx\n", 
				   name, i, queues[i]->desc_ring->size, desc_ring_addr, avail_ring_addr, used_ring_addr);
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
tsl::robin_map<bx_address, VQueueManager::VRingSet> VQueueManager::rings_grouped_by_page;

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

void VQueueManager::group_vrings_by_page() {
	for (const auto& it : virtio_devs) {
		const auto& vdev = it.second;
		for (size_t i = 0; i < vdev.queue_num; i++ ) {
			const auto* queue = vdev.queues[i];
			group_vring_by_page(queue->avail_ring);
			group_vring_by_page(queue->used_ring);
			group_vring_by_page(queue->desc_ring);
		}
	}
}

void VQueueManager::group_vring_by_page(const VRing* vring) {
	for (auto pn = vring->start_pagenum(); pn <= vring->end_pagenum(); pn++){
		if (!pn) continue;
		if (!rings_grouped_by_page.contains(pn)) {
			rings_grouped_by_page[pn] = {};
		}
		printf("group vring: %lx -> (%lx, %lx)\n", pn, vring->start(), vring->end());
		rings_grouped_by_page[pn].insert(vring);
	}
}

const VRing* VQueueManager::get_belonging_vring(bx_address address){
	if (rings_grouped_by_page.contains(PAGE_NUM(address))) {
		for (const VRing* vring : rings_grouped_by_page[PAGE_NUM(address)]) {
			if (vring->in_ring(address)){
				return vring;
			}
		}	
	}
	return NULL;
}

void VQueueManager::reset_all_queue(){
	for (auto& it : virtio_devs) {
		auto& vdev = it.second;
		for (size_t i = 0; i < vdev.queue_num; i++ ) {
			auto* queue = vdev.queues[i];
			if (queue)
				queue->reset();
		}
	}
}

/* VirtQueueElement */
int read_virtqueue_element(bx_address elem_ptr_hva, VirtQueueElement* elem){
	if (elem_ptr_hva == 0 || elem == NULL) {
		return -1;
	}

	int r = BX_CPU(id)->access_read_linear(elem_ptr_hva, sizeof(VirtQueueElement), 3, BX_READ, 0, elem);
	if (r<0) 
		return -1;
	return 0;
}

size_t VirtQueueElement::in_sgl_size() {
	size_t total = 0;
	size_t cur;
	for(size_t i=0; i<in_num; i++){
		// total += in_sg[i].iov_len;
		BX_CPU(id)->access_read_linear((bx_address)&in_sg[i].iov_len, sizeof(size_t), 3, BX_READ, 0, &cur);
		total += cur;
	}
	return total;
}

size_t VirtQueueElement::out_sgl_size() {
	size_t total = 0;
	size_t cur;
	for(size_t i=0; i<out_num; i++){
		BX_CPU(id)->access_read_linear((bx_address)&in_sg[i].iov_len, sizeof(size_t), 3, BX_READ, 0, &cur);
		total += cur;
	}
	return total;
}

/* DescChainFSM */
void DescChainFSM::init(unsigned max_len) {
	/* ingest random number as the length of chaining desc */	
	if (state == DescChainFSM::State::WAIT){
		if (ic_ingest8(&sg_num_out, 1, max_len-1) < 0) {
			printf("failed to ingest desc chaining out length!\n");
			sg_num_out = 1;
		}
		if (ic_ingest8(&sg_num_in, 1, max_len-sg_num_out) < 0) {
			printf("failed to ingest desc chaining in length!\n");
			sg_num_in = 1;
		}
		state = DescChainFSM::State::INITED;
		printf("init desc chaining: out %u, in %u\n", sg_num_out, sg_num_in);
	}	
}

DescChainFSM::SGType DescChainFSM::consume() {
	/* 
	* consume one desc.
	* if sg_num_out > 0, consume one out desc
	* only when sg_num_out == 0, consume one in desc
	*/
	if (state == INITED){
		state = RUNNING;
	}
	if (state == RUNNING) {
		if (sg_num_out > 0) {
			sg_num_out--;
			return SGType::OUT;
		} else if (sg_num_in > 1) {
			sg_num_in--;
			return SGType::IN;
		} else if (sg_num_in == 1) {
			sg_num_in--;
			return SGType::TAIL;
		}
		else if (sg_num_out == 0 && sg_num_in == 0) {
			state = DONE;
			return SGType::NONE;
		}
	}
	return SGType::NONE;
}