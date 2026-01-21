#include "syntax.h"

#include "conveyor.h"
#include "fuzz.h"

#include "vendor/libfuzzer-ng/FuzzerCorpus.h"
#include "virtio.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sys/types.h>
#include <vector>

SyntaxModel::SyntaxModel(VirtioDev &vdev)
	: vdev_(vdev) {
}

SyntaxModel *SyntaxModel::CreateOrGet(VirtioDev &vdev) {
	return vdev.get_syntax_model();
}

void SyntaxModel::init() {
	assert(!inited_);
	reset_completion_tracking();
	model_features_inited_ = false;
	inited_ = true;
	init_impl();
	assert(model_features_inited_);
}

uint64_t SyntaxModel::model_features() const {
	assert(inited_);
	assert(model_features_inited_);
	return model_features_;
}

void SyntaxModel::set_model_features(uint64_t features) {
	assert(!model_features_inited_);
	model_features_ = features;
	model_features_inited_ = true;
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
	uint16_t noff = (uint16_t)vdev_.common_cfg.read(
		VIRTIO_PCI_COMMON_Q_NOFF, sizeof(uint16_t));
	vdev_.common_cfg.set_queue_sel(old_sel);
	notify_off_cache_[queue_sel] = noff;
	return noff;
}

uint16_t SyntaxModel::submit_request() {
	return submit_request(0);
}

void SyntaxModel::reset_completion_tracking() {
	pending_heads_.clear();
	completed_heads_.clear();
}

void SyntaxModel::mark_completed(uint16_t queue_sel, uint16_t head) {
	completed_heads_[queue_sel].insert(head);
}

bool SyntaxModel::has_completed(uint16_t queue_sel, uint16_t head) const {
	auto it = completed_heads_.find(queue_sel);
	if (it == completed_heads_.end()) {
		return false;
	}
	return it->second.find(head) != it->second.end();
}

uint16_t SyntaxModel::desc_seq(uint16_t i, uint16_t out_num,
			      uint16_t in_num) const {
	if (i < out_num) {
		return i;
	} else if (i < out_num + in_num) {
		return i - out_num;
	} else {
		return UINT16_MAX;
	}
}

void SyntaxModel::remember_pending(uint16_t queue_sel, uint16_t head) {
	pending_heads_[queue_sel].insert(head);
}

void SyntaxModel::clear_pending(uint16_t queue_sel, uint16_t head) {
	auto it = pending_heads_.find(queue_sel);
	if (it == pending_heads_.end()) {
		return;
	}
	it->second.erase(head);
	if (it->second.empty()) {
		pending_heads_.erase(it);
	}
}

bool SyntaxModel::select_queue(uint16_t queue_sel) {
	if (queue_sel >= vdev_.queue_num) {
		return false;
	}
	queue_sel_ = queue_sel;
	queue_ = vdev_.queues[queue_sel];
	if (!queue_ || !queue_->desc_ring) {
		return false;
	}
	if (!queue_->desc_ring->addr_hpa || !queue_->desc_ring->addr_gpa) {
		return false;
	}
	if (!vdev_.packed) {
		if (!queue_->avail_ring || !queue_->avail_ring->addr_hpa) {
			return false;
		}
	}
	return true;
}

bool SyntaxModel::all_completed() {
	for (auto it = pending_heads_.begin(); it != pending_heads_.end();) {
		uint16_t queue_sel = it->first;
		auto &heads = it->second;

		if (!select_queue(queue_sel)) {
			++it;
			continue;
		}

		for (auto head_it = heads.begin(); head_it != heads.end();) {
			uint16_t head = *head_it;
			if (completed(head)) {
				head_it = heads.erase(head_it);
			} else {
				++head_it;
			}
		}

		if (heads.empty()) {
			it = pending_heads_.erase(it);
		} else {
			++it;
		}
	}
	return pending_heads_.empty();
}

uint16_t SyntaxModel::submit_request(uint16_t queue_sel) {
	if (!select_queue(queue_sel)) {
		return UINT16_MAX;
	}

	auto &fsm = queue_->desc_chain_fsm;
	fsm.reset();
	/* initialize the request meta information */
	fsm.init(queue_->desc_ring->size, queue_->type);
	/* allocate descriptors and chain them */
	uint16_t head = allocate_descriptors(fsm);
	if (head == UINT16_MAX) {
		return UINT16_MAX;
	}
	queue_->submit_request(head);
	remember_pending(queue_sel, head);
	completed_heads_[queue_sel].erase(head);
	notify(head);
	return head;
}

SplitRingModel::SplitRingModel(VirtioDev &vdev)
	: SyntaxModel(vdev) {
}

SplitRingModel::SplitQueueState &
SplitRingModel::state_for_queue(uint16_t queue_sel) {
	auto &state = queue_state_[queue_sel];
	if (!state.inited) {
		auto it = shadow_queue_state_.find(queue_sel);
		if (it != shadow_queue_state_.end()) {
			state = it->second;
		}
		state.inited = true;
	}
	return state;
}

void SplitRingModel::init_impl() {
	set_model_features(0);
	shadow_queue_state_.clear();
	for (uint16_t i = 0; i < vdev().queue_num; i++) {
		auto *q = vdev().queues[i];
		if (!q || !q->used_ring) {
			continue;
		}
		if (!q->used_ring->addr_hpa) {
			continue;
		}
		uint16_t used_idx = 0;
		uint16_t avail_idx = 0;
		BX_MEM(0)->readPhysicalPage(
			nullptr, q->used_ring->addr_hpa + sizeof(uint16_t),
			sizeof(used_idx), &used_idx);
		BX_MEM(0)->readPhysicalPage(
			nullptr, q->avail_ring->addr_hpa + sizeof(uint16_t),
			sizeof(avail_idx), &avail_idx);
		auto &state = shadow_queue_state_[i];
		state.inited = true;
		state.used_idx = used_idx;
		state.avail_idx = avail_idx;
	}
}

bool SplitRingModel::matched(uint64_t features) const {
	return (features & (1ULL << VIRTIO_F_RING_PACKED)) == 0;
}

bool SplitRingModel::completed(uint16_t head) {
	auto *q = queue();
	if (!q || !q->used_ring || !q->used_ring->addr_hpa) {
		return false;
	}
	if (has_completed(queue_sel_, head)) {
		return true;
	}

	auto &state = state_for_queue(queue_sel_);
	uint16_t used_idx = 0;
	BX_MEM(0)->readPhysicalPage(nullptr,
				    q->used_ring->addr_hpa + sizeof(uint16_t),
				    sizeof(used_idx), &used_idx);

	while (state.used_idx != used_idx) {
		uint16_t pos =
			(uint16_t)(state.used_idx % q->used_ring->size);
		vring_used_elem elem = {};
		q->used_ring->read_elem(0, pos, &elem);
		mark_completed(queue_sel_, (uint16_t)elem.id);
		state.used_idx++;
	}

	return has_completed(queue_sel_, head);
}

uint16_t SplitRingModel::allocate_descriptors(DescChainFSM &fsm) {
	uint16_t head = 0;
	if (ic_ingest16(&head, 0, (uint16_t)(queue()->desc_ring->size - 1)) < 0) {
		return UINT16_MAX;
	}
	uint16_t total = (uint16_t)(fsm.sg_num_out + fsm.sg_num_in);
	for (uint16_t i = 0; i < total; i++) {
		fuzzer::DescInfo desc_info{ .queue_id = (uint16_t)queue()->idx,
					    .desc_idx = (uint16_t)i,
					    .is_out = i < fsm.sg_num_out };
		auto desc_with_info = desc_pool_get()->ingest_desc(&desc_info);
		if (!desc_with_info) {
			return UINT16_MAX;
		}

		vring_desc desc = {};
		memcpy(&desc, desc_with_info->desc, sizeof(desc));
		uint64_t addr = desc.addr;
		conveyor_round(&addr, get_guest_ram_start(),
			       get_guest_ram_start() + get_guest_ram_size());
		desc.addr = addr;
		desc.len %= 0x10000;
		desc.flags =
			(uint16_t)(desc_info.is_out ? 0 : VRING_DESC_F_WRITE);

		uint16_t index =
			(head + i) % (uint16_t)(queue()->desc_ring->size);
		if ((i + 1) < total) {
			desc.flags |= VRING_DESC_F_NEXT;
			desc.next = (head + i + 1) %
				    (uint16_t)(queue()->desc_ring->size);
		} else {
			desc.next = 0;
		}

		memcpy(desc_with_info->desc, &desc, sizeof(desc));
		queue()->desc_ring->write_elem(0, index, desc_with_info->desc);

		get_vqueue_manager().add_desc(desc_with_info);
		fsm.add_desc(desc_with_info);
		AddDescSize(queue()->idx, desc_info.desc_idx, desc_info.is_out, desc.len);
	}
	return head;
}

void SplitRingModel::notify(uint16_t head) {
	auto *q = queue();
	if (!q || !q->desc_ring || !q->avail_ring) {
		return;
	}

	uint16_t avail_idx = 0;
	if (q->avail_ring->addr_hpa) {
		BX_MEM(0)->readPhysicalPage(
			nullptr, q->avail_ring->addr_hpa + sizeof(uint16_t),
			sizeof(avail_idx), &avail_idx);
	}
	uint16_t avail_pos = (uint16_t)(avail_idx % q->avail_ring->size);
	vring_avail_elem elem = head;
	q->avail_ring->write_elem(0, avail_pos, &elem);
	q->avail_ring->set_idx(0, (uint16_t)(avail_idx + 1));

	vdev().common_cfg.set_queue_enable(q->queue_sel);
	bx_address addr = vdev().notify_cfg.address +
			  vdev().multiplier * queue_notify_off(q->queue_sel);
	if (inject_write(addr, 2, q->queue_sel)) {
		start_cpu();
	}
}

void SplitRingModel::reset() {
	queue_state_.clear();
	reset_completion_tracking();
}

PackedRingModel::PackedRingModel(VirtioDev &vdev)
	: SyntaxModel(vdev) {
}

void PackedRingModel::init_impl() {
	set_model_features(1ULL << VIRTIO_F_RING_PACKED);
	shadow_queue_state_.clear();
	for (uint16_t i = 0; i < vdev().queue_num; i++) {
		auto *q = vdev().queues[i];
		if (!q || !q->desc_ring || !q->desc_ring->addr_hpa) {
			continue;
		}
		auto &state = shadow_state_for_queue(i);
		// iterate the desc table to recover the last_avail_idx
		vring_packed_desc desc = {};
		vring_packed_desc last_desc = {};
		bool recovered = false;
		for (uint16_t idx = 1; idx < q->desc_ring->size; idx++) {
			// print every desc.flag
			q->desc_ring->read_elem(0, idx, &desc);
			q->desc_ring->read_elem(0, (uint16_t)((idx + q->desc_ring->size - 1) % q->desc_ring->size), &last_desc);
			bool has_avail = (desc.flags & VIRTQ_DESC_F_AVAIL) != 0;
			bool has_used = (desc.flags & VIRTQ_DESC_F_USED) != 0;
			// printf("Desc %u: flags=0x%x, has_avail=%d, has_used=%d\n", idx, desc.flags, has_avail, has_used);
			bool last_has_avail = (last_desc.flags & VIRTQ_DESC_F_AVAIL) != 0;
			bool last_has_used = (last_desc.flags & VIRTQ_DESC_F_USED) != 0;

			/* case-1: has inflight descriptors */	
			if (last_has_used != last_has_avail and has_used == has_avail) {
				state.next_desc_idx = idx;
				state.wrap = last_has_avail;
				recovered = true;	
				break;
			}
			/* case-2: no inflight descriptors */
			if (last_has_used == last_has_avail and has_used == has_avail and last_has_used != has_used) {
				state.next_desc_idx = idx;
				state.wrap = last_has_avail;
				recovered = true;	
				break;
			}
		}	
		if (!recovered) {
			state.next_desc_idx = 0;
			q->desc_ring->read_elem(0, 0, &desc);
			state.wrap = !(desc.flags & VIRTQ_DESC_F_AVAIL);
		}
		// printf("Recovered Packed Queue %u: next_desc_idx=%u, wrap=%d\n", i, state.next_desc_idx, state.wrap);
	}
}

bool PackedRingModel::matched(uint64_t features) const {
	return (features & (1ULL << VIRTIO_F_RING_PACKED)) != 0;
}

bool PackedRingModel::completed(uint16_t head) {
	auto *q = queue();
	if (!q || !q->desc_ring || !q->desc_ring->addr_hpa) {
		return false;
	}
	if (has_completed(queue_sel_, head)) {
		return true;
	}

	vring_packed_desc desc = {};
	q->desc_ring->read_elem(0, head % q->desc_ring->size, &desc);

	bool has_avail = (desc.flags & VIRTQ_DESC_F_AVAIL) != 0;
	bool has_used = (desc.flags & VIRTQ_DESC_F_USED) != 0;
	if (has_avail == has_used) {
		mark_completed(queue_sel_, head);
		return true;
	}
	return false;
}

PackedRingModel::PackedQueueState &
PackedRingModel::state_for_queue(uint16_t queue_sel) {
	auto &state = queue_state_[queue_sel];
	if (!state.inited) {
		state = shadow_state_for_queue(queue_sel);
	}
	return state;
}

PackedRingModel::PackedQueueState &
PackedRingModel::shadow_state_for_queue(uint16_t queue_sel) {
	auto &state = shadow_queue_state_[queue_sel];
	if (!state.inited) {
		state.inited = true;
		state.next_desc_idx = 0;
		state.wrap = true;
	}
	return state;
}

uint16_t PackedRingModel::allocate_descriptors(DescChainFSM &fsm) {
	auto *q = queue();
	if (!q || !q->desc_ring) {
		return UINT16_MAX;
	}

	auto &state = state_for_queue(q->queue_sel);
	uint16_t total = (uint16_t)(fsm.sg_num_out + fsm.sg_num_in);
	if (total == 0) {
		return UINT16_MAX;
	}

	uint16_t head = state.next_desc_idx;
	for (uint16_t i = 0; i < total; i++) {
		fuzzer::DescInfo desc_info{ .queue_id = (uint16_t)q->idx,
					    .desc_idx = (uint16_t)i,
					    .is_out = i < fsm.sg_num_out };
		auto desc_with_info = desc_pool_get()->ingest_desc(&desc_info);
		if (!desc_with_info) {
			return UINT16_MAX;
		}

		vring_desc canonical = {};
		memcpy(&canonical, desc_with_info->desc, sizeof(canonical));
		uint64_t addr = canonical.addr;
		conveyor_round(&addr, get_guest_ram_start(),
			       get_guest_ram_start() + get_guest_ram_size());
		canonical.addr = addr;
		canonical.len %= 0x10000;

		uint16_t index = state.next_desc_idx;
		vring_packed_desc desc{};
		desc.addr = canonical.addr;
		desc.len = canonical.len;
		desc.id = index;
		desc.flags =
			(uint16_t)(desc_info.is_out ? 0 : VRING_DESC_F_WRITE);
		if ((i + 1) < total) {
			desc.flags |= VRING_DESC_F_NEXT;
		}
		desc.flags |= state.wrap ? VIRTQ_DESC_F_AVAIL : VIRTQ_DESC_F_USED;
		q->desc_ring->write_elem(0, index, &desc);
		memcpy(desc_with_info->desc, &desc, sizeof(desc));

		if (index + 1 == q->desc_ring->size) {
			state.next_desc_idx = 0;
			state.wrap = !state.wrap;
		} else {
			state.next_desc_idx++;
		}

		get_vqueue_manager().add_desc(desc_with_info);
		fsm.add_desc(desc_with_info);
		AddDescSize(q->idx, desc_info.desc_idx, desc_info.is_out, desc.len);
	}
	return head;
}

void PackedRingModel::notify(uint16_t head) {
	auto *q = queue();
	if (!q || !q->desc_ring) {
		return;
	}
	vdev().common_cfg.set_queue_enable(q->queue_sel);
	bx_address addr = vdev().notify_cfg.address +
			  vdev().multiplier * queue_notify_off(q->queue_sel);
	if (inject_write(addr, 2, q->queue_sel)) {
		start_cpu();
	}
}

void PackedRingModel::reset() {
	queue_state_.clear();
	reset_completion_tracking();
}
