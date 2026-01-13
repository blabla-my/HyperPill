#ifndef SYNTAX_H
#define SYNTAX_H

#include "virtio.h"

#include <cstdint>
#include <memory>
#include <unordered_map>

class SyntaxModel {
public:
	explicit SyntaxModel(VirtioDev& vdev);
	virtual ~SyntaxModel() = default;

	SyntaxModel(const SyntaxModel&) = delete;
	SyntaxModel& operator=(const SyntaxModel&) = delete;

	// Submits one request to the selected queue and returns the head descriptor
	// index, or UINT16_MAX on failure.
	uint16_t submit_request();
	uint16_t submit_request(uint16_t queue_sel);

	static std::unique_ptr<SyntaxModel> Create(VirtioDev& vdev);

protected:
	virtual uint16_t allocate_descriptors(DescChainFSM& fsm) = 0;
	virtual void notify(uint16_t head) = 0;

	VQueue* queue() const { return queue_; }
	VirtioDev& vdev() const { return vdev_; }

	uint16_t queue_notify_off(uint16_t queue_sel);

protected:
	VirtioDev& vdev_;
	VQueue* queue_ = nullptr;
	uint16_t queue_sel_ = 0;

private:
	std::unordered_map<uint16_t, uint16_t> notify_off_cache_;
};

class SplitRingModel final : public SyntaxModel {
public:
	explicit SplitRingModel(VirtioDev& vdev);
	~SplitRingModel() override = default;

protected:
	uint16_t allocate_descriptors(DescChainFSM& fsm) override;
	void notify(uint16_t head) override;
};

class PackedRingModel final : public SyntaxModel {
public:
	explicit PackedRingModel(VirtioDev& vdev);
	~PackedRingModel() override = default;

protected:
	uint16_t allocate_descriptors(DescChainFSM& fsm) override;
	void notify(uint16_t head) override;

private:
	struct PackedQueueState {
		bool inited = false;
		uint16_t next_desc_idx = 0;
		bool wrap = true;
	};

	PackedQueueState& state_for_queue(uint16_t queue_sel);
	std::unordered_map<uint16_t, PackedQueueState> queue_state_;
};

#endif
