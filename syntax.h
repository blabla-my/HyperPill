#ifndef SYNTAX_H
#define SYNTAX_H

#include "virtio.h"

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <unordered_set>

class SyntaxModel {
    public:
	explicit SyntaxModel(VirtioDev &vdev);
	virtual ~SyntaxModel() = default;

	SyntaxModel(const SyntaxModel &) = delete;
	SyntaxModel &operator=(const SyntaxModel &) = delete;

	// Submits one request to the selected queue and returns the head
	// descriptor index, or UINT16_MAX on failure.
	uint16_t submit_request();
	uint16_t submit_request(uint16_t queue_sel);

	static SyntaxModel *CreateOrGet(VirtioDev &vdev);

	void init();
	virtual void reset() = 0;
	virtual bool matched(uint64_t features) const = 0;
	virtual bool completed(uint16_t head) = 0;
	bool all_completed();
	uint64_t model_features() const;

    protected:
	virtual void init_impl() = 0;
	void set_model_features(uint64_t features);
	void reset_completion_tracking();
	void mark_completed(uint16_t queue_sel, uint16_t head);
	bool has_completed(uint16_t queue_sel, uint16_t head) const;
	uint16_t desc_seq(uint16_t i, uint16_t out_num, uint16_t in_num) const;

	virtual uint16_t allocate_descriptors(DescChainFSM &fsm) = 0;
	virtual void notify(uint16_t head) = 0;

	VQueue *queue() const {
		return queue_;
	}
	VirtioDev &vdev() const {
		return vdev_;
	}

	uint16_t queue_notify_off(uint16_t queue_sel);

    protected:
	VirtioDev &vdev_;
	VQueue *queue_ = nullptr;
	uint16_t queue_sel_ = 0;

    private:
	bool select_queue(uint16_t queue_sel);
	void remember_pending(uint16_t queue_sel, uint16_t head);
	void clear_pending(uint16_t queue_sel, uint16_t head);

	bool inited_ = false;
	bool model_features_inited_ = false;
	uint64_t model_features_ = 0;
	std::unordered_map<uint16_t, uint16_t> notify_off_cache_;
	std::unordered_map<uint16_t, std::unordered_set<uint16_t> >
		pending_heads_;
	std::unordered_map<uint16_t, std::unordered_set<uint16_t> >
		completed_heads_;
};

class SplitRingModel final : public SyntaxModel {
    public:
	explicit SplitRingModel(VirtioDev &vdev);
	~SplitRingModel() override = default;

	void reset() override;
	bool matched(uint64_t features) const override;
	bool completed(uint16_t head) override;

    protected:
	void init_impl() override;
	uint16_t allocate_descriptors(DescChainFSM &fsm) override;
	void notify(uint16_t head) override;

    private:
	struct SplitQueueState {
			bool inited = false;
			uint16_t used_idx = 0;
			uint16_t avail_idx = 0;
	};

	SplitQueueState &state_for_queue(uint16_t queue_sel);
	std::unordered_map<uint16_t, SplitQueueState> queue_state_;
	std::unordered_map<uint16_t, SplitQueueState> shadow_queue_state_;
};

class PackedRingModel final : public SyntaxModel {
    public:
	explicit PackedRingModel(VirtioDev &vdev);
	~PackedRingModel() override = default;

	void reset() override;
	bool matched(uint64_t features) const override;
	bool completed(uint16_t head) override;

    protected:
	void init_impl() override;
	uint16_t allocate_descriptors(DescChainFSM &fsm) override;
	void notify(uint16_t head) override;

    private:
	struct PackedQueueState {
		bool inited = false;
		uint16_t next_desc_idx = 3;
		bool wrap = false;
		uint16_t next_scan_idx = 0;
		bool scan_wrap = true;
	};

	PackedQueueState &state_for_queue(uint16_t queue_sel);
	PackedQueueState &shadow_state_for_queue(uint16_t queue_sel);
	std::unordered_map<uint16_t, PackedQueueState> queue_state_;
	std::unordered_map<uint16_t, PackedQueueState> shadow_queue_state_;
};

#endif
