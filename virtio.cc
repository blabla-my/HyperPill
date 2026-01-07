#include "virtio.h"
#include "vendor/libfuzzer-ng/FuzzerTracePC.h"
#include "bochs.h"
#include "iodev/iodev.h"
#include "config.h"
#include "cpu/cpu.h"
#include "cpu/apic.h"
#include "cpu/vmx.h"
#include "fuzz.h"
#include "task.h"
#include "pc_system.h"
#include <bits/types/struct_iovec.h>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include "conveyor.h"
#include <linux/virtio_config.h>
#include <sys/types.h>

#define DBG_PRINT if (BX_CPU(0)->fuzztrace || log_ops)

/* global variables */

/* VRing */
VRing::VRing(size_t size, bx_address addr_gpa, VQueue* vqueue): size(size), addr_gpa(addr_gpa), 
										type(VRING_BASE), align(VRING_BASE_ALIGN) {
	addr_hpa = 0UL;
	vmcs_translate_guest_physical_ept(addr_gpa, &addr_hpa, NULL);
	queue = vqueue;
	printf("VRing: hpa %lx, size: %lx, vqueue: %p\n", addr_hpa, size, queue);
}

void VRing::write_elem(int index, void* elem) const {
	if (!addr_hpa) return;
	if (index >= size) return;
	// BX_CPU(id)->access_write_physical(addr_hpa + ring_offset() + index * element_size() , element_size(), elem);
	BX_MEM(0)->writePhysicalPage(BX_CPU(id), addr_hpa + ring_offset() + index*element_size(), element_size(), elem);
}

void VRing::read_elem(int index, void* elem) const {
	if (!addr_hpa) return;
	if (index >= size) return;
	BX_MEM(0)->readPhysicalPage(BX_CPU(id), addr_hpa + ring_offset() + index*element_size(), element_size(), elem);
}

/* AvailRing */
int AvailRing::ingest_idx(uint16_t *idx) const {
	// read last index
	if (!addr_hpa) return -2;
	uint16_t last_idx;
	BX_CPU(x)->access_read_physical(addr_hpa + sizeof(uint16_t), sizeof(last_idx), &last_idx);
	if (last_generated_idx == UINT16_MAX) {
		*idx = last_idx + MAX_REQUEST_NUMBER;
		last_generated_idx = *idx;
	} else {
		*idx = last_idx;
	} 	
	if (queue->all_request_completed()) {
		return -2;
	}
	DBG_PRINT {
		printf("!virtio: inject vring %s index %.2x, last %.2x\n", type_str(), *idx, last_idx);
	}
	return 0;
}

int AvailRing::ingest_elem(void* opaque, int index) const {
	auto* avail_elem_ptr = (vring_avail_elem*)opaque;
	if(ic_ingest_uint(avail_elem_ptr, sizeof(uint16_t), 0, size) < 0){
		return -1;
	}
	/* every time the avail ring is touched, reset desc chain fsm */
	queue->desc_chain_fsm.reset();
	queue->desc_chain_fsm.init(size, queue->type);
	queue->submit_request(*avail_elem_ptr);
	
	DBG_PRINT {
		printf("!virtio: inject vring %s elem, size: %lx, index: %x, max: %lx\n", type_str(), element_size(), *avail_elem_ptr, size);
	}
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
	} else if (offset < ring_offset() + size*element_size()) {
		return VRing::FILED_TYPE::VRING_ELEM;
	} else {
		return VRing::FILED_TYPE::EVENT_INDEX;
	}
}

void VRing::set_flags(uint16_t flags) const {
	if (!addr_hpa) return;
	uint16_t flags_stack = flags;
	BX_MEM(0)->writePhysicalPage(BX_CPU(id), addr_hpa, sizeof(uint16_t), &flags_stack);
}

void VRing::set_idx(uint16_t idx) const {
	if (!addr_hpa) return;
	uint16_t idx_stack = idx;
	BX_MEM(0)->writePhysicalPage(BX_CPU(id), addr_hpa + sizeof(uint16_t), sizeof(uint16_t), &idx_stack);
}

void VRing::set_event(uint16_t event) const {
	if (!addr_hpa) return;
	uint16_t event_stack = event;
	BX_MEM(0)->writePhysicalPage(BX_CPU(id), addr_hpa + sizeof(uint16_t) + size * element_size(), sizeof(uint16_t), &event_stack);
}

/* UsedRing */
int UsedRing::ingest_elem(void* opaque, int index) const {
	auto* used_elem_ptr = (vring_used_elem*)opaque;
	if(ic_ingest64((uint64_t*)used_elem_ptr, 0, -1) < 0){
		return -1;
	}
	DBG_PRINT {
		printf("!virtio: inject vring %s elem, size: %lx: ", type_str(), element_size());
		for (int i = 0; i < element_size(); i++){
			printf("%.2x", *((uint8_t*)opaque + i));
		}
		printf("\n");
	}
	return 0;
}
VRing::FILED_TYPE UsedRing::filed_type(bx_address address) const {
	bx_address offset = address - start();
	if (offset < sizeof(uint16_t)){
		return VRing::FILED_TYPE::FLAGS;
	} else if (offset < sizeof(uint16_t)*2) {
		return VRing::FILED_TYPE::INDEX;
	} else if (offset < ring_offset() + size*element_size()) {
		return VRing::FILED_TYPE::VRING_ELEM;
	} else {
		return VRing::FILED_TYPE::EVENT_INDEX;
	}
}

/* DescRing */
int DescRing::ingest_elem(void* opaque, int index) const {
	/* firstly, we query desc chain fsm for genereted desc index */
	/* we assume here the desc chain fsm has been initialized */
	if (queue->desc_chain_fsm.has_used_index(index)){
		return 1;
	} 
	auto* desc_ptr = (vring_desc*)opaque;

	if (queue->desc_chain_fsm.is_done()){
		/* do not chaining */
		desc_ptr->flags &= ~VRING_DESC_F_NEXT;
	}
	else if (queue->desc_chain_fsm.is_inited()){
		DescChainFSM::SGType sg_type = queue->desc_chain_fsm.consume();

		auto addr_ptr = (uint64_t*)&desc_ptr->addr;
		desc_ptr->next = (index+1) % size;
		// desc_ptr->flags = 0;

		switch (sg_type) {
			case DescChainFSM::SGType::OUT_HEAD:
				desc_ptr->flags |= VRING_DESC_F_NEXT;
				desc_ptr->flags &= ~VRING_DESC_F_WRITE;
				break;
			case DescChainFSM::SGType::OUT:
				desc_ptr->flags |= VRING_DESC_F_NEXT;
				desc_ptr->flags &= ~VRING_DESC_F_WRITE;
				break;
			case DescChainFSM::SGType::IN_HEAD:
				desc_ptr->flags |= (VRING_DESC_F_WRITE | VRING_DESC_F_NEXT);
				break;
			case DescChainFSM::SGType::IN:
				desc_ptr->flags |= (VRING_DESC_F_WRITE | VRING_DESC_F_NEXT);
				break;
			case DescChainFSM::SGType::IN_HEAD_TAIL:
				desc_ptr->flags |= VRING_DESC_F_WRITE;
				desc_ptr->flags &= ~VRING_DESC_F_NEXT;
				break;
			case DescChainFSM::SGType::IN_TAIL:
				desc_ptr->flags |= VRING_DESC_F_WRITE;
				desc_ptr->flags &= ~VRING_DESC_F_NEXT;
				break;
			case DescChainFSM::SGType::NONE:
				break;
		}
		uint16_t queue_idx = queue->idx;
		bool is_out = !(desc_ptr->flags & VRING_DESC_F_WRITE);
		auto desc_seq = queue->desc_chain_fsm.desc_seq();
		fuzzer::DescInfo desc_info = {
			.queue_id = queue_idx,
			.desc_idx = desc_seq,
			.is_out = is_out
		};
		const fuzzer::vring_desc_with_info* desc_with_info = desc_pool_get()->ingest_desc(&desc_info, get_guest_ram_start(), get_guest_ram_size());
		if (!desc_with_info) { 
			return -2;
		}
		desc_ptr->addr = desc_with_info->desc.addr;
		desc_ptr->len = desc_with_info->desc.len;
		queue->desc_chain_fsm.add_used_index(index);
		queue->desc_chain_fsm.add_desc(desc_with_info);
		get_vqueue_manager().add_desc(desc_with_info);
		if (desc_ptr->len > 0x1000) { // record large desc size, having more chance to be identified by cmplog
			AddDescSize(queue_idx, desc_seq, is_out, desc_ptr->len);
		}
	}
	DBG_PRINT {
		printf("!virtio: inject vring %s elem, size: %lx, addr: %lx, len: %x, next: %x, flags: %x\n", 
			type_str(), element_size(),
			desc_ptr->addr, desc_ptr->len, desc_ptr->next, desc_ptr->flags);
		for (int i = 0; i < element_size(); i++){
			printf("%.2x", *((uint8_t*)opaque + i));
		}
		printf("\n");
	}
	return 0;
}

/* VQueue */
void VQueue::reset(){
	desc_chain_fsm.reset();	
	avail_ring->last_generated_idx = UINT16_MAX;
	polling_count = 0;
	request_cnt = 0;
	memset(request_status, 0, sizeof(request_status));
}

void VQueue::update_polling_count() {
	polling_count++;
}

void VQueue::add_desc(vring_desc *desc) {
	if (desc)
		generated_descs.push_back(*desc);
}

bool VQueue::inited() {
	return desc_ring->start() != 0;
}

void VQueue::submit_request(uint16_t head) {
	if (request_cnt < MAX_REQUEST_NUMBER) {
		auto req_status = &request_status[request_cnt];
		request_cnt++;
		req_status->status = RequestStatus::SUBMITTED;
		req_status->head = head;
		DBG_PRINT {
			printf("added request head %x\n", head);
		}
	}
}

void VQueue::complete_request(uint16_t head) {
	for (size_t i = 0; i < request_cnt; i++) {
		auto req_status = &request_status[i];
		if (req_status->head == head && req_status->status == RequestStatus::SUBMITTED) {
			req_status->status = RequestStatus::COMPLETED;
			DBG_PRINT {
				printf("finshed request head %x\n", head);
			}
			return;
		}
	}
}

bool VQueue::all_request_completed() {
	if (request_cnt < MAX_REQUEST_NUMBER) {
		return false;
	}
	for (size_t i = 0; i < request_cnt; i++) {
		auto req_status = &request_status[i];
		if (req_status->status == RequestStatus::SUBMITTED) {
			return false;
		}
	}
	return true;
}

const vring_desc* VQueue::get_belonging_desc(unsigned long addr, size_t size) {
	for (const vring_desc& d : generated_descs) {
		if (addr >= d.addr && addr + size < d.addr + d.len) {
			return &d;
		}
	}
	return NULL;
}


/* ConfigSpace */
unsigned long ConfigSpace::read(size_t offset, size_t sz) const {
	bx_address addr = address + offset;
	bool inject_ok;
	switch (sz) {
	case sizeof(uint8_t): 
		inject_ok = inject_read(addr, 0);
		break;
	case sizeof(uint16_t): 
		inject_ok = inject_read(addr, 1);
		break;
	case sizeof(uint32_t): 
		inject_ok = inject_read(addr, 2);
		break;
	case sizeof(uint64_t):
		inject_ok = inject_read(addr, 3);
		break;
	default:
		printf("Unsupported read size %zu in ConfigSpace::read\n", sz);
		return 0;
	}
	if (!inject_ok) {
		printf("Failed to inject read in ConfigSpace::read to %lx size %lx\n", addr+offset, sz);
		return 0;
	}
    start_cpu(true);
    
	unsigned long mask = (1ULL << (sz * 8)) - 1;
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

uint64_t ConfigSpace::get_features() const {
	if (type != ConfigSpace::COMMON) {
		printf("ConfigSpace::get_features called on non-common config space %d\n", type);
		return 0;
	}
	if (!write(VIRTIO_PCI_COMMON_DFSELECT, sizeof(uint32_t), 0)) {
		return 0;
	}
	uint64_t features_lo = read(VIRTIO_PCI_COMMON_DF, sizeof(uint32_t));
	if (!write(VIRTIO_PCI_COMMON_DFSELECT, sizeof(uint32_t), 1)) {
		return 0;
	}
	uint64_t features_hi = read(VIRTIO_PCI_COMMON_DF, sizeof(uint32_t));
	return (features_hi << 32) | features_lo;
}

bool ConfigSpace::set_avail_ring_addr(unsigned long addr) const {
	unsigned lo = addr & 0xFFFFFFFF;
	unsigned hi = (addr >> 32) & 0xFFFFFFFF;
	bool write_ok;
	write_ok = write(VIRTIO_PCI_COMMON_Q_AVAILLO, sizeof(unsigned), lo);
	if (!write_ok) {
		return false;
	}
	write_ok = write(VIRTIO_PCI_COMMON_Q_AVAILHI, sizeof(unsigned), hi);
	if (!write_ok) {
		return false;
	}
	return true;
}

bool ConfigSpace::set_used_ring_addr(unsigned long addr) const {
	unsigned lo = addr & 0xFFFFFFFF;
	unsigned hi = (addr >> 32) & 0xFFFFFFFF;
	bool write_ok;
	write_ok = write(VIRTIO_PCI_COMMON_Q_USEDLO, sizeof(unsigned), lo);
	if (!write_ok) {
		return false;
	}
	write_ok = write(VIRTIO_PCI_COMMON_Q_USEDHI, sizeof(unsigned), hi);
	if (!write_ok) {
		return false;
	}
	return true;
}

bool ConfigSpace::set_desc_ring_addr(unsigned long addr) const {
	unsigned lo = addr & 0xFFFFFFFF;
	unsigned hi = (addr >> 32) & 0xFFFFFFFF;
	bool write_ok;
	write_ok = write(VIRTIO_PCI_COMMON_Q_DESCLO, sizeof(unsigned), lo);
	if (!write_ok) {
		return false;
	}
	write_ok = write(VIRTIO_PCI_COMMON_Q_DESCHI, sizeof(unsigned), hi);
	if (!write_ok) {
		return false;
	}
	return true;
}

bool ConfigSpace::setup_queue() const {
	return false;
}

size_t ConfigSpace::get_queue_size() const {
	uint16_t sz = read(VIRTIO_PCI_COMMON_Q_SIZE, sizeof(uint16_t));
	if (sz > VIRTIO_QUEUE_MAX) {
		printf("Queue size %u exceeds maximum %u, clamping to max.\n", sz, VIRTIO_QUEUE_MAX);
		sz = VIRTIO_QUEUE_MAX;
	}
	return (size_t)sz;
}

size_t ConfigSpace::get_queue_num() const {
	uint16_t num = read(VIRTIO_PCI_COMMON_NUMQ, sizeof(uint16_t));
	return (size_t)num;
}

size_t ConfigSpace::get_queue_sel() const {
	uint16_t sel = read(VIRTIO_PCI_COMMON_Q_SELECT, sizeof(uint16_t));
	return (size_t)sel;
}

void ConfigSpace::set_queue_size(size_t sz) const {
	write(VIRTIO_PCI_COMMON_Q_SIZE, sizeof(uint16_t), (uint16_t)sz);
}

void ConfigSpace::set_queue_num(size_t num) const {
	if (num > VIRTIO_QUEUE_MAX) {
		printf("Queue number %zu exceeds maximum %u, clamping to max.\n", num, VIRTIO_QUEUE_MAX);
		num = VIRTIO_QUEUE_MAX;
	}
	write(VIRTIO_PCI_COMMON_NUMQ, sizeof(uint16_t), (unsigned long)num);
}

bool ConfigSpace::set_queue_sel(size_t sel) const {
	if (sel > VIRTIO_QUEUE_MAX) {
		printf("Queue selection %zu exceeds maximum %u, clamping to max.\n", sel, VIRTIO_QUEUE_MAX);
		sel = VIRTIO_QUEUE_MAX;
		return false;
	}
	return write(VIRTIO_PCI_COMMON_Q_SELECT, sizeof(uint16_t), (uint16_t)sel);
}

bool ConfigSpace::set_queue_enable(size_t sel) const {
	auto queue_idx = get_queue_sel();
	if (queue_idx == sel){
		return true;
	}
	if (!set_queue_sel(sel)){
		return false;
	}
	return write(VIRTIO_PCI_COMMON_Q_ENABLE, sizeof(uint16_t), 1);
}

bool ConfigSpace::write(size_t offset, size_t sz, unsigned long value) const {
	bx_address addr = address + offset;
	bool inject_ok;
	switch (sz) {
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
		printf("Unsupported read size %zu in ConfigSpace::read\n", sz);
		return false;
	}
	if (!inject_ok) {
		printf("Failed to inject write in ConfigSpace::write to %lx size %lx\n", addr+offset, sz);
		return false;
	}

    start_cpu(true);
    
    return true;
}

bool ConfigSpace::contains(unsigned long addr) const {
	return addr >= address and addr < address + size;
}

/* VirtioDev */
VirtioDev::VirtioDev() {
	memset(this, 0, sizeof(VirtioDev));
	this->multiplier = 4;
	this->to_fuzz = false;
}

void VirtioDev::set_status(uint8_t status) {
	common_cfg.write(VIRTIO_PCI_COMMON_STATUS, sizeof(uint8_t), status);
}

uint8_t VirtioDev::get_status() {
	return (uint8_t)common_cfg.read(VIRTIO_PCI_COMMON_STATUS, sizeof(uint8_t));
}

void VirtioDev::set_device_features(uint64_t features) {
	uint32_t features_lo = features & 0xffffffff;
	uint32_t features_hi = (features>>32) & 0xffffffff;
	common_cfg.write(VIRTIO_PCI_COMMON_DFSELECT, sizeof(uint32_t), 0);
	common_cfg.write(VIRTIO_PCI_COMMON_DF, sizeof(uint32_t), features_lo);
	common_cfg.write(VIRTIO_PCI_COMMON_DFSELECT, sizeof(uint32_t), 1);
	common_cfg.write(VIRTIO_PCI_COMMON_DF, sizeof(uint32_t), features_hi);
}

void VirtioDev::set_guest_features(uint64_t features) {
	uint32_t features_lo = features & 0xffffffff;
	uint32_t features_hi = (features>>32) & 0xffffffff;
	common_cfg.write(VIRTIO_PCI_COMMON_GFSELECT, sizeof(uint32_t), 0);
	common_cfg.write(VIRTIO_PCI_COMMON_GF, sizeof(uint32_t), features_lo);
	common_cfg.write(VIRTIO_PCI_COMMON_GFSELECT, sizeof(uint32_t), 1);
	common_cfg.write(VIRTIO_PCI_COMMON_GF, sizeof(uint32_t), features_hi);
}

uint64_t VirtioDev::get_device_features() {
	common_cfg.write(VIRTIO_PCI_COMMON_DFSELECT, sizeof(uint32_t), 0);
	uint64_t features_lo = common_cfg.read(VIRTIO_PCI_COMMON_DF, sizeof(uint32_t));

	common_cfg.write(VIRTIO_PCI_COMMON_DFSELECT, sizeof(uint32_t), 1);
	uint64_t features_hi = common_cfg.read(VIRTIO_PCI_COMMON_DF, sizeof(uint32_t));
	return (features_hi << 32) | features_lo; 
}

uint64_t VirtioDev::get_guest_features() {
	common_cfg.write(VIRTIO_PCI_COMMON_GFSELECT, sizeof(uint32_t), 0);
	uint64_t features_lo = common_cfg.read(VIRTIO_PCI_COMMON_GF, sizeof(uint32_t));

	common_cfg.write(VIRTIO_PCI_COMMON_GFSELECT, sizeof(uint32_t), 1);
	uint64_t features_hi = common_cfg.read(VIRTIO_PCI_COMMON_GF, sizeof(uint32_t));
	return (features_hi << 32) | features_lo; 
}

bool VirtioDev::renegotiate_features(uint64_t new_guest_features) {
	if (common_cfg.type != ConfigSpace::COMMON) {
		printf("VirtioDev %s: Common config not set, cannot re-negotiate features.\n", name);
		return false;
	}

	get_vqueue_manager().disable_hook();

	bx_address desc_before[VIRTIO_QUEUE_MAX] = {0};
	bx_address avail_before[VIRTIO_QUEUE_MAX] = {0};
	bx_address used_before[VIRTIO_QUEUE_MAX] = {0};
	size_t old_sel = common_cfg.get_queue_sel();

	// for (size_t i = 0; i < queue_num && i < VIRTIO_QUEUE_MAX; ++i) {
	// 	if (!queues[i]) continue;
	// 	common_cfg.set_queue_sel(i);
	// 	/* Disable queue before reset per renegotiation */
	// 	common_cfg.write(VIRTIO_PCI_COMMON_Q_ENABLE, sizeof(uint16_t), 0);
	// }
	// common_cfg.set_queue_sel(old_sel);

	for (size_t i = 0; i < queue_num && i < VIRTIO_QUEUE_MAX; ++i) {
		if (!queues[i]) continue;
		desc_before[i] = queues[i]->desc_ring ? queues[i]->desc_ring->addr_gpa : 0;
		avail_before[i] = queues[i]->avail_ring ? queues[i]->avail_ring->addr_gpa : 0;
		used_before[i] = queues[i]->used_ring ? queues[i]->used_ring->addr_gpa : 0;
	}

	uint8_t prev_status = get_status();

	/* Reset and re-do feature negotiation */
	set_status(0);
	set_status(VIRTIO_CONFIG_S_ACKNOWLEDGE);
	set_status(VIRTIO_CONFIG_S_DRIVER | get_status());

	uint64_t device_features = get_device_features();
	uint64_t negotiated = new_guest_features & device_features;
	set_guest_features(negotiated);
	set_status(VIRTIO_CONFIG_S_FEATURES_OK | get_status());

	if (prev_status & VIRTIO_CONFIG_S_DRIVER_OK) {
		set_status(VIRTIO_CONFIG_S_DRIVER_OK | get_status());
	}

	for (size_t i = 0; i < queue_num && i < VIRTIO_QUEUE_MAX; ++i) {
		if (!queues[i]) continue;
		common_cfg.set_queue_sel(i);
		if (desc_before[i]) common_cfg.set_desc_ring_addr(desc_before[i]);
		if (avail_before[i]) common_cfg.set_avail_ring_addr(avail_before[i]);
		if (used_before[i]) common_cfg.set_used_ring_addr(used_before[i]);

		bx_address desc_after = common_cfg.get_desc_ring_addr();
		bx_address avail_after = common_cfg.get_avail_ring_addr();
		bx_address used_after = common_cfg.get_used_ring_addr();
		printf("VirtioDev %s: queue %zu desc %lx -> %lx, avail %lx -> %lx, used %lx -> %lx\n",
		       name, i, desc_before[i], desc_after, avail_before[i], avail_after, used_before[i], used_after);
	}

	common_cfg.set_queue_sel(old_sel);

	printf("VirtioDev %s: re-negotiated features to %lx.\n", name, negotiated);
	get_vqueue_manager().enable_hook();
	return true;
}

bool VirtioDev::disable_packed_queue() {
	uint64_t device_features = get_device_features();
	uint64_t guest_features = get_guest_features();
	uint64_t packed_bit = (1ULL << VIRTIO_F_RING_PACKED);
	bool packed_enabled = (device_features & packed_bit) && (guest_features & packed_bit);
	if (!packed_enabled) {
		return false;
	}

	uint64_t new_guest_features = guest_features & ~packed_bit;
	bool ok = renegotiate_features(new_guest_features);
	printf("VirtioDev %s: Packed ring disabled, guest features %lx -> %lx (renegotiate %s)\n",
	       name, guest_features, new_guest_features, ok ? "ok" : "failed");
	return ok;
}

void VirtioDev::enumerate_queues_from_common_cfg() {
	if (common_cfg.type != ConfigSpace::COMMON) {
		printf("Common config space not set for device %s, cannot enumerate queues.\n", name);
		return;
	}
	uint64_t device_features = get_device_features();
	uint64_t guest_features = get_guest_features();
	printf("VirtioDev %s: Device features: %lx\n", name, device_features);
	// packed bit
	printf("VirtioDev %s: Packed ring feature %s\n", name, 
		   (device_features & (1ul<<VIRTIO_F_RING_PACKED)) ? "supported" : "not supported");
	printf("VirtioDev %s: Guest features: %lx\n", name, guest_features);
	// packed bit
	printf("VirtioDev %s: Packed ring feature %s\n", name, 
		   (guest_features & (1ul<<VIRTIO_F_RING_PACKED)) ? "enabled" : "disabled");
	queue_num = common_cfg.get_queue_num();
	if (queue_num > VIRTIO_QUEUE_MAX) {
		// a workaround, if we write to config space than read, it will be normal
		common_cfg.set_queue_sel(0);
		// queue_num = 1;
		queue_num = common_cfg.get_queue_num();
		assert (queue_num <= VIRTIO_QUEUE_MAX);
	}
	size_t old_queue_sel = common_cfg.get_queue_sel();
	if (old_queue_sel > VIRTIO_QUEUE_MAX) {
		common_cfg.set_queue_sel(0);
		old_queue_sel = common_cfg.get_queue_sel();
		assert(old_queue_sel <= VIRTIO_QUEUE_MAX);
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
			queues[i]->idx = get_vqueue_manager().get_queue_list_size();
			get_vqueue_manager().add_to_queue_list(queues[i]);
			queues[i]->desc_ring = new DescRing{queue_size, desc_ring_addr, queues[i]};
			queues[i]->avail_ring = new AvailRing{queue_size, avail_ring_addr, queues[i]};
			queues[i]->used_ring = new UsedRing{queue_size, used_ring_addr, queues[i]};
			queues[i]->vdev = this;
			queues[i]->queue_sel = i;
			queues[i]->type = VQueue::QUEUE_NORMAL;
			if (is_net) {
				if (i == queue_num - 1 && queue_num % 2 == 1) {
					queues[i]->type = VQueue::QUEUE_CTRL;
				} else if (i % 2 == 0) {
					queues[i]->type = VQueue::QUEUE_RX;
				} else {
					queues[i]->type = VQueue::QUEUE_TX;
				}
			}
			if (is_scsi) {
				if (i == 0) {
					queues[i]->type = VQueue::QUEUE_CTRL;
				} else if (i == 1) {
					queues[i]->type = VQueue::QUEUE_EVENT;
				} else {
					queues[i]->type = VQueue::QUEUE_NORMAL;
				}
			}
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

bool VirtioDev::inited() {
	for (int i = 0; i < queue_num; i++) {
		if (!queues[i]->inited()) {
			return false;
		}
	}
	return true;
}

/* VQueueManager */
static VQueueManager vqueue_manager;
VQueueManager& get_vqueue_manager() {
	return vqueue_manager;
}

VirtioDev* VQueueManager::get_vdev_by_name(const std::string& name) {
    auto it = virtio_devs.find(name);
    if (it == virtio_devs.end()) {
        return NULL;
    }
    return it->second;
}

VirtioDev* VQueueManager::get_fuzzed_dev() {
	if (fuzzed_dev_cache && fuzzed_dev_cache->to_fuzz) {
		return fuzzed_dev_cache;
	}

	fuzzed_dev_cache = nullptr;
	for (auto* dev : virtio_dev_list) {
		if (dev && dev->to_fuzz) {
			fuzzed_dev_cache = dev;
			break;
		}
	}
	return fuzzed_dev_cache;
}

bool VQueueManager::create_virtio_device(const std::string& name, bool to_fuzz) {
	if (virtio_devs.find(name) != virtio_devs.end()) {
		printf("Virtio device %s already exists.\n", name.c_str());
		virtio_devs[name]->to_fuzz = to_fuzz;
		if (to_fuzz) {
			fuzzed_dev_cache = virtio_devs[name];
		} else if (fuzzed_dev_cache == virtio_devs[name]) {
			fuzzed_dev_cache = nullptr;
		}
		return true;
	}
	virtio_devs[name] = new VirtioDev();
	VirtioDev* dev_ptr = virtio_devs[name];
	dev_ptr->to_fuzz = to_fuzz;
	if (to_fuzz) {
		fuzzed_dev_cache = dev_ptr;
	}
	strcpy(virtio_devs[name]->name, name.c_str());
	if (to_fuzz)
		virtio_dev_list.push_back(virtio_devs[name]);
	if (name == "virtio-net") {
		dev_ptr->is_net = true;		
	}
	if (name == "virtio-scsi") {
		dev_ptr->is_scsi = true;		
	}
	return true;
}

void VQueueManager::add_config_space(const std::string& name, enum ConfigSpace::ConfigSpaceType type,
									 unsigned long address, size_t size) {
	auto it = virtio_devs.find(name);
	if (it == virtio_devs.end()) {
		printf("Virtio device %s not found.\n", name.c_str());
		return;
	}
	VirtioDev *dev = virtio_devs[name];
	switch (type) {
		case ConfigSpace::COMMON:
			if (dev->common_cfg.address == address && dev->common_cfg.size == size) {
				break;
			}
			dev->common_cfg = {address, size, type};
			dev->enumerate_queues_from_common_cfg();
			break;
		case ConfigSpace::ISR:
			if (dev->isr_cfg.address == address && dev->isr_cfg.size == size) {
				break;
			}
			dev->isr_cfg = {address, size, type};
			break;
		case ConfigSpace::DEVICE:
			if (dev->device_cfg.address == address && dev->device_cfg.size == size) {
				break;
			}
			dev->device_cfg = {address, size, type};
			break;
		case ConfigSpace::NOTIFY:
			if (dev->notify_cfg.address == address && dev->notify_cfg.size == size) {
				break;
			}
			dev->notify_cfg = {address, size, type};
			break;
		default:
			printf("Unknown config space type %d for device %s.\n", type, name.c_str());
			return;
	}
}

void VQueueManager::group_vrings_by_page() {
	for (const auto& it : virtio_devs) {
		const auto& vdev = it.second;
		for (size_t i = 0; i < vdev->queue_num; i++ ) {
			const auto* queue = vdev->queues[i];
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
		for (size_t i = 0; i < vdev->queue_num; i++ ) {
			auto* queue = vdev->queues[i];
			if (queue && queue->vdev && queue->vdev->to_fuzz)
				queue->reset();
		}
	}
}

bool VQueueManager::init_queues_for_dev(VirtioDev *vdev) {
	if (vdev->inited())
		return true;

	vdev->set_status(VIRTIO_CONFIG_S_ACKNOWLEDGE | vdev->get_status());
	vdev->set_status(VIRTIO_CONFIG_S_DRIVER | vdev->get_status());

	/* set features */
	uint64_t features = vdev->get_device_features();
	assert(features & (1ULL << VIRTIO_F_VERSION_1));
	features &= ~((1ULL << VIRTIO_RING_F_EVENT_IDX) | (1ULL << VIRTIO_RING_F_INDIRECT_DESC));
	vdev->set_guest_features(features);
	vdev->get_guest_features();

	vdev->set_status(VIRTIO_CONFIG_S_FEATURES_OK | vdev->get_status());


	for (size_t i = 0; i < vdev->queue_num; i++) {
		VQueue* queue = vdev->queues[i];
		if (!queue) continue;
		if (queue->inited()) continue;

		size_t queue_size = queue->desc_ring->size;
		if (queue_size == 0) continue;

		size_t desc_size = queue_size * sizeof(vring_desc);
		size_t avail_size = sizeof(uint16_t) * 3 + queue_size * sizeof(vring_avail_elem);
		size_t padding = ((avail_size + 0x3f) & (~0x3f)) - avail_size; // padding to 64byte
		size_t used_size = sizeof(uint16_t) * 2 + queue_size * sizeof(vring_used_elem);

		size_t total_size = desc_size + avail_size + padding + used_size;
		size_t num_pages = (total_size + PAGE_SIZE - 1) / PAGE_SIZE;

		// bx_address gpa = GUEST_MEM_START; // + 0x4000000;
		bx_address gpa = 0x10a8b8000UL;
		while (gpa < GUEST_MEM_START + GUEST_MEM_SIZE) {
			bool found = true;
			for (size_t j = 0; j < num_pages; j++) {
				if (rings_grouped_by_page.contains(PAGE_NUM(gpa + j * PAGE_SIZE))) {
					found = false;
					gpa += (j + 1) * PAGE_SIZE;
					break;
				}
			}

			if (found) {
				bx_address desc_addr = gpa;
				bx_address avail_addr = desc_addr + desc_size;
				bx_address used_addr = avail_addr + avail_size + padding;
				printf("VQueueManager: init queue for %s, desc %lx, avail %lx, used %lx\n", vdev->name, desc_addr, avail_addr, used_addr);

				vdev->common_cfg.set_queue_sel(queue->queue_sel);
				vdev->common_cfg.set_desc_ring_addr(desc_addr);
				vdev->common_cfg.set_avail_ring_addr(avail_addr);
				vdev->common_cfg.set_used_ring_addr(used_addr);

				desc_addr = vdev->common_cfg.get_desc_ring_addr();
				avail_addr = vdev->common_cfg.get_avail_ring_addr();
				used_addr = vdev->common_cfg.get_used_ring_addr();

				delete queue->desc_ring;
				delete queue->avail_ring;
				delete queue->used_ring;

				queue->desc_ring = new DescRing(queue_size, desc_addr, queue);
				queue->avail_ring = new AvailRing(queue_size, avail_addr, queue);
				queue->used_ring = new UsedRing(queue_size, used_addr, queue);
				
				// Initialize descriptor table
				for (size_t j = 0; j < queue_size; ++j) {
					vring_desc desc_elem = {0}; // Initialize all fields to 0
					desc_elem.next = (j + 1) % queue_size;
					queue->desc_ring->write_elem(j, &desc_elem);
				}
				
				queue->avail_ring->set_flags(0);
				queue->avail_ring->set_idx(0);
				queue->avail_ring->set_event(0);
				queue->used_ring->set_flags(0);
				queue->used_ring->set_idx(0);
				queue->used_ring->set_event(0);				

				group_vring_by_page(queue->desc_ring);
				group_vring_by_page(queue->avail_ring);
				group_vring_by_page(queue->used_ring);
				break;
			}
		}
	}
	for (int i = 0; i < vdev->queue_num; i++) {
		vdev->common_cfg.set_queue_sel(vdev->queues[i]->queue_sel);
		vdev->common_cfg.set_queue_size(vdev->queues[i]->desc_ring->size);
		vdev->common_cfg.set_queue_enable(vdev->queues[i]->queue_sel);
	}
	// vdev->set_status(VIRTIO_CONFIG_S_DRIVER_OK | vdev->get_status());
	return true;
}

bool VQueueManager::init_queues() {
	for (auto vdev : virtio_dev_list) {
		if (!vdev->inited())
			init_queues_for_dev(vdev);
	}
	return true;
}

const fuzzer::vring_desc_with_info* VQueueManager::get_desc_by_gpa(uint64_t gpa) {
	for (const auto* desc : generated_descs) {
		if (gpa >= desc->desc.addr && gpa < desc->desc.addr + desc->desc.len) {
			return desc;
		}
	}
    return nullptr;
}

void VQueueManager::add_seen_buffer(uint64_t start, size_t size) {
	if (!seen_buffers.contains(start)) {
		seen_buffers[start] = size;
		return;
	}
	if (seen_buffers[start] >= size) {
	} else {
		seen_buffers[start] = size;
	}
}

uint64_t VQueueManager::overlapped_size(uint64_t start, uint64_t size) {
	if (!seen_buffers.contains(start)) {
		return 0;
	}
	if (seen_buffers[start] >= size) {
		return size;
	} else {
		return seen_buffers[start];
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
void DescChainFSM::init(unsigned max_len, int queue_type) {
	/* ingest random number as the length of chaining desc */	
	max_len = max_len < DESC_CHAIN_MAX_LEN? max_len : DESC_CHAIN_MAX_LEN;
	if (state == DescChainFSM::State::WAIT){
		unsigned out_max_len, in_max_len;	
		switch (queue_type) {
			case VQueue::QUEUE_RX:
				in_max_len = max_len < 1 ? 1 : max_len;
				if (ic_ingest_uint(&sg_num_in, sizeof(sg_num_in), 1, in_max_len) < 0){
					sg_num_in = 1;
				}
				sg_num_out = 0;
				break;
			case VQueue::QUEUE_TX:
				out_max_len = max_len < 1 ? 1 : max_len;
				if (ic_ingest_uint(&sg_num_out, sizeof(sg_num_out), 1, out_max_len)) {
					sg_num_out = 1;
				}
				sg_num_in = 0;
				break;
			case VQueue::QUEUE_CTRL:
			case VQueue::QUEUE_EVENT:
			case VQueue::QUEUE_NORMAL:
				out_max_len = max_len < 1 ? 1 : max_len;
				if (ic_ingest_uint(&sg_num_out, sizeof(sg_num_out), 1, out_max_len) < 0){
					sg_num_out = 1;
				}
				in_max_len = max_len - sg_num_out < 1 ? 1 : max_len - sg_num_out;
				if (ic_ingest_uint(&sg_num_in, sizeof(sg_num_in), 1, in_max_len) < 0){
					sg_num_in = 1;
				}
				break;
		}
		sg_num_out_remain = sg_num_out;
		sg_num_in_remain = sg_num_in;
		state = DescChainFSM::State::INITED;
		if(!generated_descs_size) {
			memset(generated_descs, 0, sizeof(vring_desc_with_info)*generated_descs_size);
		}
		generated_descs_size = 0;
		DBG_PRINT {
			printf("init desc chaining: out %u, in %u, queue_type: %u\n", sg_num_out, sg_num_in, queue_type);
		}
	}	
}

void DescChainFSM::add_desc(const fuzzer::vring_desc_with_info *desc_with_info) {
	if (generated_descs_size < DESC_CHAIN_MAX_LEN*2) {
		generated_descs[generated_descs_size++] = desc_with_info;
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
		if (sg_num_out_remain > 0 && sg_num_out_remain == sg_num_out) {
			sg_num_out_remain--;
			return SGType::OUT_HEAD;
		} else if (sg_num_out_remain > 0) {
			sg_num_out_remain--;
			return SGType::OUT;
		} else if (sg_num_in_remain > 0 && sg_num_in_remain == sg_num_in) {
			sg_num_in_remain--;
			if (sg_num_in == 1) {
				return SGType::IN_HEAD_TAIL;
			}
			return SGType::IN_HEAD;
		} else if (sg_num_in_remain > 1) {
			sg_num_in_remain--;
			return SGType::IN;
		} else if (sg_num_in_remain == 1) {
			sg_num_in_remain--;
			state = DONE;
			return SGType::IN_TAIL;
		} else if (sg_num_out_remain == 0 && sg_num_in_remain == 0) {
			state = DONE;
			return SGType::NONE;
		}
	}
	state = DONE;
	return SGType::NONE;
}

uint16_t DescChainFSM::desc_seq() {
	if (is_inited() == false) {
		return 0xffff;
	}
	
	if (sg_num_out == 0 || sg_num_in == 0) {
		return 0xffff;
	}
	
	if (sg_num_out_remain == sg_num_out)
		return 0xffff;
	
	if (sg_num_out_remain > 0)
		return sg_num_out - sg_num_out_remain - 1;
	if (sg_num_in_remain == sg_num_in)
		return sg_num_out - 1;
	if (sg_num_in_remain >= 0)
		return sg_num_in - sg_num_in_remain - 1;

	return 0xffff;
}

size_t DescChainFSM::get_request_offset(bx_address gpa) const {
	size_t offset = 0;
	for (size_t i = 0; i < generated_descs_size; i++) {
		const auto* d = generated_descs[i];
		if (gpa >= d->desc.addr && gpa < d->desc.addr + d->desc.len) {
			offset += (gpa - d->desc.addr);
			break;
		} else {
			offset += d->desc.len;
		}
	}
	return offset;
}

void AddDescSize(uint16_t queue_id, uint16_t desc_idx, bool is_out, uint32_t size) {
	static void* enabled = getenv("SGL_SIZE_INFER");
	if (enabled)
		__trace_pc_add_desc_size(queue_id, desc_idx, is_out, size);
}

const DescSize* GetDescSizeHints(uint16_t queue_id, uint16_t desc_idx, bool is_out) {
	static void* enabled = getenv("SGL_SIZE_INFER");
	if (enabled)
		return (DescSize*)__trace_pc_get_desc_size_hints(queue_id, desc_idx, is_out);
	return nullptr;
}