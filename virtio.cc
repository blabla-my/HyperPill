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
#include "cov.h"
#include <bits/types/struct_iovec.h>
#include <cassert>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "conveyor.h"
#include <linux/virtio_config.h>
#include <sys/types.h>

#define DBG_PRINT if (BX_CPU(0)->fuzztrace || log_ops)

/* global variables */

/* VRing */
VRing::VRing(size_t size, bx_address addr_gpa, VQueue* vqueue): size(size), addr_gpa(addr_gpa), 
										type(VRING_BASE), align(VRING_BASE_ALIGN) {
	addr_hpa = 0UL;
	if (addr_gpa)
		assert(vmcs_translate_guest_physical_ept(addr_gpa, &addr_hpa, NULL) == 0);
	queue = vqueue;
	printf("VRing: hpa %lx, gpa %lx, size: %lx, vqueue: %p\n", addr_hpa, addr_gpa, size, queue);
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
static bx_address alloc_indirect_table_gpa(const VQueue* queue, size_t table_bytes_len) {
	bx_address guest_start = get_guest_ram_start();
	bx_address guest_end = guest_start + get_guest_ram_size();

	if (!queue || table_bytes_len == 0 || guest_end <= guest_start) {
		return 0;
	}
	if (guest_end - guest_start < PAGE_SIZE) {
		return (guest_start + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	}

	/*
	 * Deterministic placement: base it on (queue idx, per-input request id) so
	 * the same fuzz input remains reproducible across runs.
	 */
	size_t request_id = queue->request_cnt ? (queue->request_cnt - 1) : 0;
	const bx_address base = guest_start + 0x0c000000UL;
	bx_address gpa = base + (bx_address)queue->idx * 0x10000UL + (bx_address)request_id * PAGE_SIZE;
	gpa = (gpa + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

	const bx_address aligned_guest_start = (guest_start + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	const bx_address max_start = guest_end - std::min<bx_address>((bx_address)table_bytes_len, PAGE_SIZE);
	if (gpa < aligned_guest_start || gpa > max_start) {
		bx_address span = max_start > aligned_guest_start ? (max_start - aligned_guest_start) : 0;
		if (span == 0) {
			gpa = aligned_guest_start;
		} else {
			bx_address offset = (gpa - aligned_guest_start) % span;
			gpa = aligned_guest_start + offset;
			gpa = (gpa + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
		}
	}

	for (size_t tries = 0; tries < 0x10000; tries++) {
		if (gpa > max_start) {
			gpa = aligned_guest_start;
		}
		if (vmcs_translate_guest_physical_ept(gpa, nullptr, nullptr) == 0 &&
			vmcs_translate_guest_physical_ept(gpa + table_bytes_len - 1, nullptr, nullptr) == 0 &&
			get_vqueue_manager().get_belonging_vring(gpa) == nullptr &&
			get_vqueue_manager().get_belonging_vring(gpa + table_bytes_len - 1) == nullptr &&
			get_vqueue_manager().find_indirect_table(gpa, nullptr) == nullptr &&
			get_vqueue_manager().find_indirect_table(gpa + table_bytes_len - 1, nullptr) == nullptr) {
			return gpa;
		}
		gpa += PAGE_SIZE;
	}
	return aligned_guest_start;
}

int DescRing::ingest_elem(void* opaque, int index) const {
	/* firstly, we query desc chain fsm for genereted desc index */
	/* we assume here the desc chain fsm has been initialized */
	if (queue->desc_chain_fsm.has_used_index(index)){
		return 1;
	} 
	uint64_t* addr_ptr = nullptr;
	uint32_t* len_ptr = nullptr;
	uint16_t* flags_ptr = nullptr;
	bool is_packed = queue && queue->vdev && queue->vdev->packed;
	vring_desc* split_desc = nullptr;
	vring_packed_desc* packed_desc = nullptr;
	if (is_packed) {
		packed_desc = (vring_packed_desc*)opaque;
		addr_ptr = &packed_desc->addr;
		len_ptr = &packed_desc->len;
		flags_ptr = &packed_desc->flags;
	} else {
		split_desc = (vring_desc*)opaque;
		addr_ptr = &split_desc->addr;
		len_ptr = &split_desc->len;
		flags_ptr = &split_desc->flags;
	}

	if (queue->desc_chain_fsm.is_done()){
		/* do not chaining */
		*flags_ptr = 0;
		if (is_packed) {
			bool wrap_phase = ((size_t)index / size) % 2 == 0;
			if (wrap_phase) {
				*flags_ptr |= VIRTQ_DESC_F_AVAIL;
			} else {
				*flags_ptr |= VIRTQ_DESC_F_USED;
			}
		}
	}
	else if (queue->desc_chain_fsm.is_inited()){
		DescChainFSM::SGType sg_type = queue->desc_chain_fsm.consume();
		bool indirect_enabled = queue && queue->vdev && queue->vdev->indirect_desc;
		bool is_head = sg_type == DescChainFSM::SGType::OUT_HEAD ||
		               sg_type == DescChainFSM::SGType::IN_HEAD ||
		               sg_type == DescChainFSM::SGType::IN_HEAD_TAIL;

		if (indirect_enabled && is_head) {
			if (is_packed) {
				packed_desc->id = index;
				*flags_ptr = 0;
				bool wrap_phase = ((size_t)index / size) % 2 == 0;
				if (wrap_phase) {
					*flags_ptr |= VIRTQ_DESC_F_AVAIL;
				} else {
					*flags_ptr |= VIRTQ_DESC_F_USED;
				}
			} else {
				*flags_ptr = 0;
				split_desc->next = 0;
			}

			struct TablePlan {
				DescChainFSM::SGType sg_type;
				uint16_t desc_seq;
				bool is_out;
			};
			std::vector<TablePlan> plans;
			plans.reserve(DESC_CHAIN_MAX_LEN * 2);
			auto push_plan = [&](DescChainFSM::SGType t) {
				bool out = (t == DescChainFSM::SGType::OUT_HEAD || t == DescChainFSM::SGType::OUT);
				plans.push_back({t, queue->desc_chain_fsm.desc_seq(), out});
			};
			push_plan(sg_type);
			while (!queue->desc_chain_fsm.is_done() && plans.size() < DESC_CHAIN_MAX_LEN * 2) {
				DescChainFSM::SGType t = queue->desc_chain_fsm.consume();
				if (t == DescChainFSM::SGType::NONE) {
					break;
				}
				push_plan(t);
			}

			size_t elem_sz = is_packed ? sizeof(vring_packed_desc) : sizeof(vring_desc);
			size_t table_elems = plans.size();
			size_t table_bytes_len = table_elems * elem_sz;
			if (table_elems == 0 || table_bytes_len == 0 || table_bytes_len > PAGE_SIZE) {
				return -2;
			}

			bx_address table_gpa = alloc_indirect_table_gpa(queue, table_bytes_len);
			if (table_gpa == 0) {
				return -2;
			}
			*addr_ptr = table_gpa;
			*len_ptr = (uint32_t)table_bytes_len;

			/*
			 * Optional deterministic noise for error-handling coverage:
			 * - 0: set VRING_DESC_F_INDIRECT inside the table
			 * - 1: break chaining (split: out-of-range next, packed: NEXT on last)
			 */
			uint8_t noise = 0xff;
			if (ic_ingest8(&noise, 0, 0xff, true) < 0) {
				noise = 0xff;
			}

			std::vector<uint8_t> table_bytes;
			table_bytes.resize(table_bytes_len);
			uint16_t queue_idx = queue->idx;
			for (size_t i = 0; i < table_elems; i++) {
				bool has_next = (i + 1) < table_elems;
				uint16_t entry_flags = 0;
				if (has_next) {
					entry_flags |= VRING_DESC_F_NEXT;
				}
				if (!plans[i].is_out) {
					entry_flags |= VRING_DESC_F_WRITE;
				}

				if (noise == 0 && i == 0) {
					entry_flags |= VRING_DESC_F_INDIRECT;
				}
				if (noise == 1 && is_packed && i + 1 == table_elems) {
					entry_flags |= VRING_DESC_F_NEXT;
				}

				fuzzer::DescInfo desc_info = {
					.queue_id = queue_idx,
					.desc_idx = plans[i].desc_seq,
					.is_out = plans[i].is_out,
				};
				auto* desc_with_info = desc_pool_get()->ingest_desc(&desc_info);
				if (!desc_with_info) {
					return -2;
				}
				vring_desc canonical = {};
				memcpy(&canonical, desc_with_info->desc, sizeof(canonical));
				queue->desc_chain_fsm.add_desc(desc_with_info);
				get_vqueue_manager().add_desc(desc_with_info);
				if (canonical.len > 0x1000) {
					AddDescSize(queue_idx, plans[i].desc_seq, plans[i].is_out, canonical.len);
				}

				if (is_packed) {
					vring_packed_desc entry = {0};
					entry.addr = canonical.addr;
					entry.len = canonical.len;
					entry.id = (uint16_t)i;
					entry.flags = entry_flags;
					memcpy(table_bytes.data() + i * elem_sz, &entry, elem_sz);
				} else {
					vring_desc entry = {0};
					entry.addr = canonical.addr;
					entry.len = canonical.len;
					entry.flags = entry_flags;
					entry.next = (uint16_t)(i + 1);
					if (!has_next) {
						entry.next = 0;
					}
					if (noise == 1 && i == 0 && has_next) {
						entry.next = (uint16_t)table_elems;
					}
					memcpy(table_bytes.data() + i * elem_sz, &entry, elem_sz);
				}
			}

			get_vqueue_manager().add_indirect_table(table_gpa, std::move(table_bytes));

			*flags_ptr |= VRING_DESC_F_INDIRECT;
			*flags_ptr &= ~(VRING_DESC_F_NEXT | VRING_DESC_F_WRITE);
			queue->desc_chain_fsm.add_used_index(index);
		} else {
			if (is_packed) {
				packed_desc->id = index;
				*flags_ptr = 0;
				bool wrap_phase = ((size_t)index / size) % 2 == 0;
				if (wrap_phase) {
					*flags_ptr |= VIRTQ_DESC_F_AVAIL;
				} else {
					*flags_ptr |= VIRTQ_DESC_F_USED;
				}
			} else {
				*flags_ptr = 0;
				split_desc->next = (index+1) % size;
			}
			// desc_ptr->flags = 0;

			switch (sg_type) {
				case DescChainFSM::SGType::OUT_HEAD:
					*flags_ptr |= VRING_DESC_F_NEXT;
					*flags_ptr &= ~VRING_DESC_F_WRITE;
					break;
				case DescChainFSM::SGType::OUT:
					*flags_ptr |= VRING_DESC_F_NEXT;
					*flags_ptr &= ~VRING_DESC_F_WRITE;
					break;
				case DescChainFSM::SGType::IN_HEAD:
					*flags_ptr |= (VRING_DESC_F_WRITE | VRING_DESC_F_NEXT);
					break;
				case DescChainFSM::SGType::IN:
					*flags_ptr |= (VRING_DESC_F_WRITE | VRING_DESC_F_NEXT);
					break;
				case DescChainFSM::SGType::IN_HEAD_TAIL:
					*flags_ptr |= VRING_DESC_F_WRITE;
					*flags_ptr &= ~VRING_DESC_F_NEXT;
					break;
				case DescChainFSM::SGType::IN_TAIL:
					*flags_ptr |= VRING_DESC_F_WRITE;
					*flags_ptr &= ~VRING_DESC_F_NEXT;
					break;
				case DescChainFSM::SGType::NONE:
					break;
			}
			uint16_t queue_idx = queue->idx;
			bool is_out = !(*flags_ptr & VRING_DESC_F_WRITE);
			auto desc_seq = queue->desc_chain_fsm.desc_seq();
			fuzzer::DescInfo desc_info = {
				.queue_id = queue_idx,
				.desc_idx = desc_seq,
				.is_out = is_out
			};
			auto* desc_with_info = desc_pool_get()->ingest_desc(&desc_info);
			if (!desc_with_info) { 
				return -2;
			}
			vring_desc canonical = {};
			memcpy(&canonical, desc_with_info->desc, sizeof(canonical));
			*addr_ptr = canonical.addr;
			*len_ptr = canonical.len;
			queue->desc_chain_fsm.add_used_index(index);
			queue->desc_chain_fsm.add_desc(desc_with_info);
			get_vqueue_manager().add_desc(desc_with_info);
			if (*len_ptr > 0x1000) { // record large desc size, having more chance to be identified by cmplog
				AddDescSize(queue_idx, desc_seq, is_out, *len_ptr);
			}
		}
	}
	DBG_PRINT {
		if (is_packed) {
			auto* desc_ptr = (vring_packed_desc*)opaque;
			printf("!virtio: inject vring %s elem, size: %lx, addr: %lx, len: %x, id: %x, flags: %x\n", 
				type_str(), element_size(),
				desc_ptr->addr, desc_ptr->len, desc_ptr->id, desc_ptr->flags);
		} else {
			auto* desc_ptr = (vring_desc*)opaque;
			printf("!virtio: inject vring %s elem, size: %lx, addr: %lx, len: %x, next: %x, flags: %x\n", 
				type_str(), element_size(),
				desc_ptr->addr, desc_ptr->len, desc_ptr->next, desc_ptr->flags);
		}
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
		printf("Failed to inject read in ConfigSpace::read to %lx size %lx\n", addr, sz);
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
		printf("Failed to inject write in ConfigSpace::write to %lx size %lx\n", addr, sz);
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
	this->packed = false;
	this->indirect_desc = false;
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

	uint64_t device_features = get_device_features();
	uint64_t negotiated = new_guest_features & device_features;
	uint8_t prev_status = get_status();
	uint8_t cleared_features_ok = prev_status & ~VIRTIO_CONFIG_S_FEATURES_OK;

	/*
	 * Avoid `status = 0` resets because they tear down ioeventfd/irqfd/MSI-X
	 * notifiers (e.g. `msix_unset_vector_notifiers`) and can hang snapshot
	 * replay. To allow updating guest features via common cfg, temporarily
	 * clear FEATURES_OK (while keeping DRIVER_OK unchanged).
	 */
	if (prev_status & VIRTIO_CONFIG_S_FEATURES_OK) {
		set_status(cleared_features_ok);
	}
	set_guest_features(negotiated);
	if (prev_status & VIRTIO_CONFIG_S_FEATURES_OK) {
		set_status(prev_status);
	}

	uint64_t packed_bit = (1ULL << VIRTIO_F_RING_PACKED);
	packed = (negotiated & packed_bit) != 0;
	uint64_t indirect_bit = (1ULL << VIRTIO_RING_F_INDIRECT_DESC);
	indirect_desc = (negotiated & indirect_bit) != 0;
	uint64_t guest_features = get_guest_features();

	if (guest_features != negotiated) {
		printf("VirtioDev %s: Guest features readback %lx does not match negotiated %lx.\n", name, guest_features, negotiated);
	}

	DBG_PRINT {
		printf("VirtioDev %s: updated guest features to %lx (packed=%d indirect=%d).\n",
		       name, negotiated, packed ? 1 : 0, indirect_desc ? 1 : 0);
	}
	get_vqueue_manager().enable_hook();
	return true;
}

bool VirtioDev::set_packed_queue(bool enable) {
	if (common_cfg.type != ConfigSpace::COMMON) {
		printf("VirtioDev %s: Common config not set, cannot set packed ring.\n", name);
		return false;
	}

	uint64_t device_features = get_device_features();
	uint64_t guest_features = get_guest_features();
	uint64_t packed_bit = (1ULL << VIRTIO_F_RING_PACKED);

	bool device_supports_packed = (device_features & packed_bit) != 0;
	bool current_packed = device_supports_packed && ((guest_features & packed_bit) != 0);
	bool desired_packed = enable && device_supports_packed;

	if (current_packed == desired_packed) {
		packed = current_packed;
		return true;
	}

	uint64_t new_guest_features = guest_features;
	if (desired_packed) {
		new_guest_features |= packed_bit;
	} else {
		new_guest_features &= ~packed_bit;
	}

	return renegotiate_features(new_guest_features);
}

bool VirtioDev::disable_packed_queue() {
	return set_packed_queue(false);
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
			{
				uint64_t dev_features = dev->get_device_features();
				uint64_t guest_features = dev->get_guest_features();
				uint64_t packed_bit = (1ULL << VIRTIO_F_RING_PACKED);
				dev->packed = (dev_features & packed_bit) && (guest_features & packed_bit);
				uint64_t indirect_bit = (1ULL << VIRTIO_RING_F_INDIRECT_DESC);
				dev->indirect_desc = (dev_features & indirect_bit) && (guest_features & indirect_bit);
			}
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

void VQueueManager::add_indirect_table(bx_address base_gpa, std::vector<uint8_t>&& bytes) {
	indirect_tables[base_gpa] = std::move(bytes);
}

const std::vector<uint8_t>* VQueueManager::find_indirect_table(bx_address gpa, bx_address* base_gpa_out) const {
	for (const auto& it : indirect_tables) {
		bx_address base = it.first;
		const auto& bytes = it.second;
		if (gpa >= base && gpa < base + bytes.size()) {
			if (base_gpa_out) {
				*base_gpa_out = base;
			}
			return &bytes;
		}
	}
	return nullptr;
}

bool VQueueManager::init_queues_for_dev(VirtioDev *vdev) {
	if (vdev->inited())
		return true;

	vdev->set_status(VIRTIO_CONFIG_S_ACKNOWLEDGE | vdev->get_status());
	vdev->set_status(VIRTIO_CONFIG_S_DRIVER | vdev->get_status());

	/* set features */
	uint64_t features = vdev->get_device_features();
	assert(features & (1ULL << VIRTIO_F_VERSION_1));
	features &= ~(1ULL << VIRTIO_RING_F_EVENT_IDX);
	vdev->set_guest_features(features);
	vdev->get_guest_features();
	vdev->indirect_desc = (features & (1ULL << VIRTIO_RING_F_INDIRECT_DESC)) != 0;

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
		vring_desc canonical = {};
		memcpy(&canonical, desc->desc, sizeof(canonical));
		if (gpa >= canonical.addr && gpa < canonical.addr + canonical.len) {
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
		vring_desc canonical = {};
		memcpy(&canonical, d->desc, sizeof(canonical));
		if (gpa >= canonical.addr && gpa < canonical.addr + canonical.len) {
			offset += (gpa - canonical.addr);
			break;
		} else {
			offset += canonical.len;
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

/*
 * Ingest DMA reads to descriptor-backed buffers (when addr doesn't belong to a VRing).
 *
 * returns:
 *  0: handled/no-op
 * -1: failed to ingest buffer
 */
static int ingest_vring_buffer(bx_address addr, bx_address gpa, size_t len, void* data) {
	static void* replay = getenv("REPLAY");
	static char* no_double_fetch = getenv("NO_DOUBLE_FETCH");

	/* get the corresponding desc */
	if (get_vqueue_manager().hooks_disabled()) {
		return 0;
	}
	auto desc_with_info = get_vqueue_manager().get_desc_by_gpa(gpa);
	if (!desc_with_info) { /* the DMA is not issued by fuzzer, do nothing */
		return 0;
	}

	auto overlapped_size = get_vqueue_manager().overlapped_size(gpa, len);
	auto* queue = get_vqueue_manager().get_queue_by_id(desc_with_info->desc_info.queue_id);
	assert(overlapped_size <= len);
			
	size_t offset = queue->desc_chain_fsm.get_request_offset(gpa);
	bool is_out = desc_with_info->desc_info.is_out;
	bool possible_switch = (offset == 0 && is_out && desc_with_info->desc_info.desc_idx == 0);
	possible_switch = false;
			
	if (offset > 0x100) 
		return 0;

	/* ingest random data */
	bool overwrite = (replay == NULL);
	uint8_t* buf = dma_data_get()->ingest_data(len, possible_switch, overwrite);
	if (!buf)
		return -1;
	/* fetch overlapped data */
	if (no_double_fetch && overlapped_size) 
		BX_MEM(0)->readPhysicalPage(BX_CPU(id), addr, overlapped_size, buf);
			
	if (queue->vdev->is_scsi && is_out) {
		const uint8_t valid_lun[8] = {1, 1, 0, 0, 0, 0, 0, 0};
		if (queue->type == VQueue::QUEUE_NORMAL) {
			if (offset == 0) {
				buf[0] = 1; // just fix lun[0] to 1
			}
		} else if (queue->type == VQueue::QUEUE_CTRL) {
			// lun should be [8, 16) or [4, 12)
			if (offset == 8)
				buf[0] = 1;
			else if (offset == 4)
				buf[0] = 1;	
		}
	}
			
	/* adjust addr = addr + len - remaining_len to avoid duplicated region */
	BX_MEM(0)->writePhysicalPage(BX_CPU(id), addr, len, (void *)buf);
	memcpy(data, buf, len);
	get_vqueue_manager().add_seen_buffer(gpa, len);
	update_virtio_req_counter(desc_with_info->desc_info.queue_id,
							  desc_with_info->desc_info.desc_idx,
							  is_out);
	return 0;
}

/* 
	returns:
	 0: handled/no-op
	-1: failed to ingest element
	-2: stop polling
	1: not a vring element
*/
static int ingest_vring_split(bx_address addr, size_t len, void* data) {
	auto gpa = lookup_gpa_by_hpa(addr);
	const VRing *vring = get_vqueue_manager().get_belonging_vring(gpa);
	int rc;
	bx_address off_in_elem = 0;
	if (!vring) {
		return 1;
	}

	if (vring->queue && vring->queue->vdev && !vring->queue->vdev->to_fuzz) {
		// device is not being fuzzed
		// just ignore
		return 0;
	}
	uint16_t vring_idx = 0;
	uint8_t vring_elem[16] = {0};
	switch (vring->filed_type(gpa)) {
	case VRing::FILED_TYPE::FLAGS:
		return 0;
	case VRing::FILED_TYPE::INDEX:
		if (get_vqueue_manager().hooks_disabled()) {
			return 0;
		}
		rc = vring->ingest_idx(&vring_idx);
		if (rc == -1) {  
			// -1, ingest error
			// -2, queue locates at page 0
			// if (rc == -1) // ingest error
			/* here we should not call fuzz_emu_stop_unhealthy */
			// fuzz_emu_stop_unhealthy();
			return rc;				
		}
		if (rc == -2) {
			fuzz_emu_stop_polling();
			return -2;
		}
		if (rc == 1) { // genereted index, already written
			// just mark the region, do nothing
			return 0;
		}
		BX_MEM(0)->writePhysicalPage(BX_CPU(id), addr, len, (void*)&vring_idx);
		memcpy(data, &vring_idx, len);
		return 0;
	case VRing::FILED_TYPE::VRING_ELEM:
		if (get_vqueue_manager().hooks_disabled()) {
			return 0;
		}
		rc = vring->ingest_elem((void*)vring_elem, vring->element_index(gpa));
		off_in_elem = gpa - (vring->start() + vring->ring_offset() + vring->element_index(gpa) * vring->element_size());
		if (rc == -1) {
			/* here we should not call fuzz_emu_stop_unhealthy */
			// fuzz_emu_stop_unhealthy();
			return -1;
		} else if (rc == -2) {
			fuzz_emu_stop_polling();
			return -2;
		} else if (rc == 0) {
			vring->write_elem(vring->element_index(gpa), vring_elem);
			memcpy(data, vring_elem + off_in_elem, len);
		} else if (rc == 1) { // genereted elem, already written
			// just mark the region, do nothing
		}
		return 0;
	case VRing::FILED_TYPE::EVENT_INDEX:
		return 0; // not a vring element
	default:
		assert(false);
		return -1;
	}
	return 1;
}

/* packed queue variant mirroring ingest_vring_split for packed ring support */
static int ingest_vring_packed(bx_address addr, size_t len, void* data) {
	static char* vring_log = getenv("VIRTIO_VRING_LOG");
	static tsl::robin_map<size_t, bool> logged_init;
	auto gpa = lookup_gpa_by_hpa(addr);
	const VRing *vring = get_vqueue_manager().get_belonging_vring(gpa);
	int rc;
	bx_address off_in_elem = 0;
	if (!vring) {
		return 1;
	}

	if (vring->queue && vring->queue->vdev && !vring->queue->vdev->to_fuzz) {
		// device is not being fuzzed
		// just ignore
		return 0;
	}
	if (get_vqueue_manager().hooks_disabled()) {
		return 0;
	}
	if (vring->filed_type(gpa) != VRing::FILED_TYPE::VRING_ELEM) {
		return 0;
	}
	uint8_t vring_elem[16] = {0};
	uint16_t desc_idx = vring->element_index(gpa);
	off_in_elem = gpa - (vring->start() + vring->ring_offset() + desc_idx * vring->element_size());
	auto* queue = vring->queue;
	if (queue) {
		bool verbose = vring_log && (vring_log[0] == '2' || vring_log[0] == 'v' || vring_log[0] == 'V');
		bool needs_init = queue->desc_chain_fsm.is_wait() || queue->desc_chain_fsm.is_done();
		bool same_desc_partial = queue->desc_chain_fsm.is_done() &&
			queue->desc_chain_fsm.has_used_index(desc_idx) && off_in_elem != 0;
		if (vring_log && vring_log[0] != '0' && verbose) {
			printf("!virtio: ingest_vring packed ring=%s dev=%s qid=%zu sel=%u idx=%u off=%lx len=%zx needs_init=%d same_desc_partial=%d\n",
				   vring->type_str(),
				   queue->vdev ? queue->vdev->name : "<null>",
				   queue->idx,
				   queue->queue_sel,
				   desc_idx,
				   off_in_elem,
				   len,
				   needs_init ? 1 : 0,
				   same_desc_partial ? 1 : 0);
		}
		if (needs_init && !same_desc_partial) {
			queue->desc_chain_fsm.reset();
			queue->desc_chain_fsm.init(vring->size, queue->type);
			queue->submit_request(desc_idx);
			bool log_enabled = vring_log && vring_log[0] != '0';
			bool should_log = log_enabled && verbose;
			if (log_enabled && !verbose) {
				auto it = logged_init.find(queue->idx);
				if (it == logged_init.end()) {
					logged_init[queue->idx] = true;
					should_log = true;
				}
			}
			if (should_log) {
				printf("!virtio: ingest_vring packed init dev=%s qid=%zu sel=%u head=%u size=%zu\n",
					   queue->vdev ? queue->vdev->name : "<null>",
					   queue->idx,
					   queue->queue_sel,
					   desc_idx,
					   vring->size);
			}
		}
	}
	rc = vring->ingest_elem((void*)vring_elem, desc_idx);
	if (rc == -1) {
		/* here we should not call fuzz_emu_stop_unhealthy */
		// fuzz_emu_stop_unhealthy();
		return -1;
	} else if (rc == -2) {
		fuzz_emu_stop_polling();
		return -2;
	} else if (rc == 0) {
		vring->write_elem(desc_idx, vring_elem);
		memcpy(data, vring_elem + off_in_elem, len);
	} else if (rc == 1) { // genereted elem, already written
		// just mark the region, do nothing
	}
	return 0;
}

int ingest_vring(bx_address addr, size_t len, void* data) {
	auto gpa = lookup_gpa_by_hpa(addr);
	if (const VRing* vring = get_vqueue_manager().get_belonging_vring(gpa)) {
		return 0;
	}
	return ingest_vring_buffer(addr, gpa, len, data);
}
