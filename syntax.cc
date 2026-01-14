#include "syntax.h"

#include "conveyor.h"
#include "fuzz.h"

#include "vendor/libfuzzer-ng/FuzzerCorpus.h"
#include "virtio.h"
#include <algorithm>
#include <cassert>
#include <cstring>
#include <cstdio>
#include <sys/types.h>

SyntaxModel::SyntaxModel(VirtioDev& vdev) : vdev_(vdev) {}

std::unique_ptr<SyntaxModel> SyntaxModel::Create(VirtioDev& vdev) {
	if (vdev.packed) {
		return std::make_unique<PackedRingModel>(vdev);
	}
	return std::make_unique<SplitRingModel>(vdev);
}

uint16_t SyntaxModel::queue_notify_off(uint16_t queue_sel) {
	auto it = notify_off_cache_.find(queue_sel);
	if (it != notify_off_cache_.end()) {
		return it->second;
	}
	if (vdev_.common_cfg.type != ConfigSpace::COMMON) {
		notify_off_cache_[queue_sel] = queue_sel;
		return queue_sel;
	}
	size_t old_sel = vdev_.common_cfg.get_queue_sel();
	vdev_.common_cfg.set_queue_sel(queue_sel);
	uint16_t noff = (uint16_t)vdev_.common_cfg.read(VIRTIO_PCI_COMMON_Q_NOFF, sizeof(uint16_t));
	vdev_.common_cfg.set_queue_sel(old_sel);
	notify_off_cache_[queue_sel] = noff;
	return noff;
}

uint16_t SyntaxModel::submit_request() {
	return submit_request(0);
}

uint16_t SyntaxModel::submit_request(uint16_t queue_sel) {
	if (queue_sel >= vdev_.queue_num) {
		return UINT16_MAX;
	}
	queue_sel_ = queue_sel;
	queue_ = vdev_.queues[queue_sel];
	if (!queue_ || !queue_->desc_ring) {
		return UINT16_MAX;
	}
	if (!queue_->desc_ring->addr_hpa || !queue_->desc_ring->addr_gpa) {
		return UINT16_MAX;
	}
	if (!vdev_.packed) {
		if (!queue_->avail_ring || !queue_->avail_ring->addr_hpa) {
			return UINT16_MAX;
		}
	}

	auto& fsm = queue_->desc_chain_fsm;
	fsm.reset();
	/* initialize the request meta information */
	fsm.init(queue_->desc_ring->size, queue_->type);
	/* allocate descriptors and chain them */
	uint16_t head = allocate_descriptors(fsm);
	if (head == UINT16_MAX) {
		return UINT16_MAX;
	}
	queue_->submit_request(head);
	notify(head);
	return head;
}

SplitRingModel::SplitRingModel(VirtioDev& vdev) : SyntaxModel(vdev) {}

uint16_t SplitRingModel::allocate_descriptors(DescChainFSM& fsm) {
	uint16_t head = 0;
	if (ic_ingest16(&head, 0, (uint16_t)(queue()->desc_ring->size - 1)) < 0) {
		return UINT16_MAX;
	}
	uint16_t total = (uint16_t)(fsm.sg_num_out + fsm.sg_num_in);
	for (uint16_t i = 0; i < total; i++) {
		fuzzer::DescInfo desc_info {
			.queue_id = (uint16_t)queue()->idx,
			.desc_idx = (uint16_t)i,
			.is_out = i < fsm.sg_num_out
		};
		auto desc_with_info = desc_pool_get()->ingest_desc(&desc_info);
		if (!desc_with_info) {
			return UINT16_MAX;
		}

		vring_desc desc = {};
		memcpy(&desc, desc_with_info->desc, sizeof(desc));
		uint64_t addr = desc.addr;
		conveyor_round(&addr, get_guest_ram_start(), get_guest_ram_start() + get_guest_ram_size());
		desc.addr = addr;
		desc.len %= 0x10000;
		desc.flags = (uint16_t)(desc_info.is_out ? 0 : VRING_DESC_F_WRITE);

		uint16_t index = (head + i) % (uint16_t)(queue()->desc_ring->size);
		if ((i + 1) < total) {
			desc.flags |= VRING_DESC_F_NEXT;
			desc.next = (head + i + 1) % (uint16_t)(queue()->desc_ring->size);
		} else {
			desc.next = 0;
		}

		memcpy(desc_with_info->desc, &desc, sizeof(desc));
		queue()->desc_ring->write_elem(0, index, desc_with_info->desc);

		get_vqueue_manager().add_desc(desc_with_info);
		fsm.add_desc(desc_with_info);
	}
	return head;
}

void SplitRingModel::notify(uint16_t head) {
	auto* q = queue();
	if (!q || !q->desc_ring || !q->avail_ring) {
		return;
	}

	uint16_t avail_idx = 0;
	if (q->avail_ring->addr_hpa) {
		BX_MEM(0)->readPhysicalPage(BX_CPU(0), q->avail_ring->addr_hpa + sizeof(uint16_t),
									sizeof(avail_idx), &avail_idx);
	}
	uint16_t avail_pos = (uint16_t)(avail_idx % q->avail_ring->size);
	vring_avail_elem elem = head;
	q->avail_ring->write_elem(0, avail_pos, &elem);
	q->avail_ring->set_idx(0, (uint16_t)(avail_idx + 1));

	vdev().common_cfg.set_queue_enable(q->queue_sel);
	bx_address addr = vdev().notify_cfg.address + vdev().multiplier * queue_notify_off(q->queue_sel);
	if (inject_write(addr, 2, q->queue_sel)) {
		start_cpu();
	}
}

PackedRingModel::PackedRingModel(VirtioDev& vdev) : SyntaxModel(vdev) {}

PackedRingModel::PackedQueueState& PackedRingModel::state_for_queue(uint16_t queue_sel) {
	auto& state = queue_state_[queue_sel];
	if (!state.inited) {
		state.inited = true;
		state.next_desc_idx = 0;
		state.wrap = true;
	}
	return state;
}

uint16_t PackedRingModel::allocate_descriptors(DescChainFSM& fsm) {
	auto* q = queue();
	if (!q || !q->desc_ring) {
		return UINT16_MAX;
	}

	static void* dbg_packed_desc = getenv("DBG_PACKED_DESC");
	auto& state = state_for_queue(q->queue_sel);
	uint16_t total = (uint16_t)(fsm.sg_num_out + fsm.sg_num_in);
	if (total == 0) {
		return UINT16_MAX;
	}

	uint16_t head = state.next_desc_idx;
	if (dbg_packed_desc) {
		printf("packed desc alloc: qsel=%u qid=%zu head=%u total=%u wrap=%u\n",
		       q->queue_sel, q->idx, head, total, state.wrap ? 1 : 0);
	}
	for (uint16_t i = 0; i < total; i++) {
		fuzzer::DescInfo desc_info {
			.queue_id = (uint16_t)q->idx,
			.desc_idx = (uint16_t)i,
			.is_out = i < fsm.sg_num_out
		};
		auto desc_with_info = desc_pool_get()->ingest_desc(&desc_info);
		if (!desc_with_info) {
			return UINT16_MAX;
		}

		vring_desc canonical = {};
		memcpy(&canonical, desc_with_info->desc, sizeof(canonical));
		uint64_t addr = canonical.addr;
		conveyor_round(&addr, get_guest_ram_start(), get_guest_ram_start() + get_guest_ram_size());
		canonical.addr = addr;
		canonical.len %= 0x10000;

		uint16_t index = state.next_desc_idx;
		vring_packed_desc desc{};
		desc.addr = canonical.addr;
		desc.len = canonical.len;
		desc.id = index;
		desc.flags = (uint16_t)(desc_info.is_out ? 0 : VRING_DESC_F_WRITE);
		if ((i + 1) < total) {
			desc.flags |= VRING_DESC_F_NEXT;
		}
		desc.flags |= state.wrap ? VIRTQ_DESC_F_AVAIL : VIRTQ_DESC_F_USED;
		q->desc_ring->write_elem(0, index, &desc);
		memcpy(desc_with_info->desc, &desc, sizeof(desc));
		// printf("packed desc: qid=%zu idx=%u id=%u addr=%lx len=%x flags=%x\n",
		// 		q->idx, index, desc.id, (unsigned long)desc.addr, desc.len,
		// 		desc.flags);

		if (index + 1 == q->desc_ring->size) {
			state.next_desc_idx = 0;
			state.wrap = !state.wrap;
		} else {
			state.next_desc_idx++;
		}

		get_vqueue_manager().add_desc(desc_with_info);
		fsm.add_desc(desc_with_info);
	}
	return head;
}

void PackedRingModel::notify(uint16_t head) {
	auto* q = queue();
	if (!q || !q->desc_ring) {
		return;
	}
	vdev().common_cfg.set_queue_enable(q->queue_sel);
	bx_address addr = vdev().notify_cfg.address + vdev().multiplier * queue_notify_off(q->queue_sel);
	if (inject_write(addr, 2, q->queue_sel)) {
		start_cpu();
	}
}
