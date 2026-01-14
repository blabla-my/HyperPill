#ifndef VIRTIO_H
#define VIRTIO_H

#include "config.h"
#include <cstdint>
#include <sstream>
#include <stddef.h>
#include <linux/virtio_config.h>
#include "bochs.h"
#include "cpu/cpu.h"
#include <map>
#include <vector>
#include "tsl/robin_map.h"
#include "tsl/robin_set.h"

#include "task.h"
#include "vendor/libfuzzer-ng/FuzzerTracePC.h"

namespace fuzzer {
struct vring_desc_with_info;
}

/* Status byte for guest to report progress, and synchronize features. */
/* We have seen device and processed generic fields (VIRTIO_CONFIG_F_VIRTIO) */
#define VIRTIO_CONFIG_S_ACKNOWLEDGE	1
/* We have found a driver for the device. */
#define VIRTIO_CONFIG_S_DRIVER		2
/* Driver has used its parts of the config, and is happy */
#define VIRTIO_CONFIG_S_DRIVER_OK	4
/* Driver has finished configuring features */
#define VIRTIO_CONFIG_S_FEATURES_OK	8
/* Device entered invalid state, driver must reset it */
#define VIRTIO_CONFIG_S_NEEDS_RESET	0x40
/* We've given up on this device. */

#define VIRTIO_PCI_COMMON_DFSELECT	0
#define VIRTIO_PCI_COMMON_DF		4
#define VIRTIO_PCI_COMMON_GFSELECT	8
#define VIRTIO_PCI_COMMON_GF		12
#define VIRTIO_PCI_COMMON_MSIX		16
#define VIRTIO_PCI_COMMON_NUMQ		18
#define VIRTIO_PCI_COMMON_STATUS	20
#define VIRTIO_PCI_COMMON_CFGGENERATION	21
#define VIRTIO_PCI_COMMON_Q_SELECT	22
#define VIRTIO_PCI_COMMON_Q_SIZE	24
#define VIRTIO_PCI_COMMON_Q_MSIX	26
#define VIRTIO_PCI_COMMON_Q_ENABLE	28
#define VIRTIO_PCI_COMMON_Q_NOFF	30
#define VIRTIO_PCI_COMMON_Q_DESCLO	32
#define VIRTIO_PCI_COMMON_Q_DESCHI	36
#define VIRTIO_PCI_COMMON_Q_AVAILLO	40
#define VIRTIO_PCI_COMMON_Q_AVAILHI	44
#define VIRTIO_PCI_COMMON_Q_USEDLO	48
#define VIRTIO_PCI_COMMON_Q_USEDHI	52
#define VIRTIO_PCI_COMMON_Q_NDATA	56
#define VIRTIO_PCI_COMMON_Q_RESET	58
#define VIRTIO_PCI_COMMON_ADM_Q_IDX	60
#define VIRTIO_PCI_COMMON_ADM_Q_NUM	62
/* This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT	1
/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE	2
/* This means the buffer contains a list of buffer descriptors. */
#define VRING_DESC_F_INDIRECT	4

#define VIRTQ_DESC_F_AVAIL	(1u << 7)
#define VIRTQ_DESC_F_USED	(1u << 15)

#define VIRTIO_RING_F_INDIRECT_DESC	28

/* The Guest publishes the used index for which it expects an interrupt
 * at the end of the avail ring. Host should ignore the avail->flags field. */
/* The Host publishes the avail index for which it expects a kick
 * at the end of the used ring. Guest should ignore the used->flags field. */
#define VIRTIO_RING_F_EVENT_IDX		29

#define VIRTIO_QUEUE_MAX 1024


#define GUEST_MEM_START 0x100000000UL
#define GUEST_MEM_SIZE  0x80000000UL 

struct ConfigSpace;
struct VQueue;
struct vring_desc_with_info;
/* desc chaining FSM */
#define DESC_CHAIN_MAX_LEN 8
class DescChainFSM {
public:
    enum State {
        WAIT, 
        INITED,
        RUNNING,
        DONE
    };
    enum SGType {
        OUT,
        OUT_HEAD,
        IN,
        IN_HEAD,
        IN_HEAD_TAIL,
        IN_TAIL,
        NONE
    };

    DescChainFSM()
        : state(WAIT), used_index(), sg_num_in(0), sg_num_in_remain(0), sg_num_out(0),
          sg_num_out_remain(0), inited_count(0), generated_descs{}, generated_descs_size(0) {}
    void init(unsigned max_len, int queue_type);
    SGType consume();
    State get_state() {return state;}
    uint8_t get_inited_count() const {return inited_count;}
    uint16_t desc_seq(); // return the number of last consumed desc; out, in, counts independently
    void reset() {
        state = WAIT;
        used_index.clear();
        sg_num_in = 0;
        sg_num_in_remain = 0;
        sg_num_out = 0;
        sg_num_out_remain = 0;
        inited_count = 0;
        generated_descs_size = 0;
    }
    void add_used_index(uint16_t idx) {used_index.insert(idx);}
    void remove_used_index(uint16_t idx) {used_index.erase(idx);}
    void add_desc(const fuzzer::vring_desc_with_info* desc_with_info);
    const vring_desc_with_info* get_desc_by_gpa(uint64_t gpa);
    size_t get_request_offset(bx_address gpa) const;
    void increment_inited_count() {inited_count++;}
    bool has_used_index(uint16_t idx) {return used_index.contains(idx);}
    bool is_wait() const {return state == WAIT;}
    bool is_done() const {return state == DONE;}
    bool is_running() const {return state == RUNNING;}
    bool is_inited() const {return state == INITED or state == RUNNING;}

    State state;
    tsl::robin_set<uint16_t> used_index;
    uint8_t sg_num_in;
    uint8_t sg_num_in_remain;
    uint8_t sg_num_out;
    uint8_t sg_num_out_remain;
    uint8_t inited_count;
    const fuzzer::vring_desc_with_info* generated_descs[DESC_CHAIN_MAX_LEN*2];
    size_t generated_descs_size;
};

struct vring_desc {
	uint64_t addr;
	uint32_t len;
	uint16_t flags;
	uint16_t next;
};

struct vring_packed_desc {
	uint64_t addr;
	uint32_t len;
	uint16_t id;
	uint16_t flags;
};

struct vring_desc_with_info {
    struct DescInfo desc_info;
    vring_desc desc;
#define MAX_USED_CNT 1
    uint8_t used_cnt;
} __attribute__((packed));

typedef uint16_t vring_avail_elem;

struct alignas(8) vring_used_elem {
	/* Index of start of used descriptor chain. */
	uint32_t id;
	/* Total length of the descriptor chain which was used (written to) */
	uint32_t len;
};

#define VQUEUE(vring) ((vring)->queue)
struct VRing {
    size_t size; // the number of items in the ring
    bx_address addr_gpa; // Address of the ring
    bx_address addr_hpa;
    VQueue* queue;
    enum Type {
        VRING_BASE = 0,
        VRING_DESC = 1,
        VRING_AVAIL,
        VRING_USED 
    } type; // Type of the ring
    enum Align {
        VRING_BASE_ALIGN = 1,
        VRING_AVAIL_ALIGN = 2,
        VRING_USED_ALIGN = 4,
        VRING_DESC_ALIGN = 16
    } align;
    mutable uint16_t last_generated_idx = UINT16_MAX;
    VRing() {}
    VRing(size_t size, bx_address addr_gpa, VQueue* vqueue);
    bx_address start() const {return addr_gpa;}
    bx_address ring_start() const {return addr_gpa + ring_offset();}
    virtual bx_address ring_end() const {return ring_start() + size*element_size();}
    virtual bx_address end() const {return addr_gpa;} 
    bx_address start_pagenum() const {
        return PAGE_NUM(start());
    }
    bx_address end_pagenum() const {
        return PAGE_NUM(end()-1);
    }
    bool in_ring(bx_address address) const {
        return address >= start() && address < end();
    }
    virtual size_t element_size() const {return 0;}
    virtual size_t ring_offset() const {return 0;}
    virtual uint16_t element_index(bx_address gpa) const {
        return (gpa - start() - ring_offset()) / element_size();
    }
    virtual int ingest_elem(unsigned cpu, void*, int index=-1) const {return 0;};
    virtual const char* type_str() const {return "base";};
    virtual void write_elem(unsigned cpu, int index, void* elem) const;
    virtual void read_elem(unsigned cpu, int index, void* elem) const;

    enum FILED_TYPE {
        FLAGS, 
        INDEX,
        VRING_ELEM,
        EVENT_INDEX
    };
    virtual FILED_TYPE filed_type(bx_address address) const {return FILED_TYPE::VRING_ELEM;};

    virtual int ingest_idx(unsigned cpu, uint16_t* idx) const {return 0;};
    void set_flags(unsigned cpu, uint16_t flags) const;
    void set_idx(unsigned cpu, uint16_t idx) const;
    void set_event(unsigned cpu, uint16_t event) const;
};

struct AvailRing: VRing {
    using VRing::VRing;
    AvailRing(size_t size, bx_address addr_gpa, VQueue* queue): VRing(size, addr_gpa, queue) {
        type = VRING_AVAIL;
        align = VRING_AVAIL_ALIGN;
        last_generated_idx = UINT16_MAX;
    }
    bx_address end() const override {
        return addr_gpa + 3*sizeof(uint16_t) + size*sizeof(vring_avail_elem);
    }
    size_t element_size() const override {return sizeof(vring_avail_elem);}
    size_t ring_offset() const override {return sizeof(uint16_t)*2;}
    int ingest_elem(unsigned cpu, void*, int index) const override;
    const char* type_str() const override {return "avail";}
    virtual FILED_TYPE filed_type(bx_address address) const override;
    virtual int ingest_idx(unsigned cpu, uint16_t* idx) const override;
};

struct UsedRing: VRing {
    using VRing::VRing;
    UsedRing(size_t size, bx_address addr_gpa, VQueue* queue): VRing(size, addr_gpa, queue) {
        type = VRING_USED;
        align = VRING_USED_ALIGN;
    }
    bx_address end() const override {
        return addr_gpa + 2*sizeof(uint16_t) + size*sizeof(vring_used_elem) + sizeof(uint16_t);
    }
    size_t element_size() const override {return sizeof(vring_used_elem);}
    size_t ring_offset() const override {return sizeof(uint16_t)*2;}
    int ingest_elem(unsigned cpu, void*, int index) const override;
    const char* type_str() const override {return "used";}
    virtual FILED_TYPE filed_type(bx_address address) const override;
};

struct DescRing: VRing {
    using VRing::VRing;
    DescRing(size_t size, bx_address addr_gpa, VQueue* queue): VRing(size,addr_gpa,queue) {
        type = VRING_DESC;
        align = VRING_DESC_ALIGN;
    }
    bx_address end() const override {
        return addr_gpa + size*sizeof(vring_desc);
    }
    size_t element_size() const override  {return sizeof(vring_desc);}
    size_t ring_offset() const override {return 0;}
    int ingest_elem(unsigned cpu, void*, int index) const override;
    const char* type_str() const override {return "desc";}
};

struct RequestStatus {
    enum Status {
        SUBMITTED,
        COMPLETED
    } status;
    uint16_t head; // request head desc index
    RequestStatus(): status(SUBMITTED), head(0) {}
};
struct VQueue {
    VQueue(): desc_ring(NULL), avail_ring(NULL), used_ring(NULL), idx(0),
        num(0), last_avail_idx(0), last_used_idx(0), desc_chain_fsm(), generated_descs(), 
        vdev(nullptr), queue_sel(0), polling_count(0), request_cnt(0) {}
    void reset();
    void add_desc(vring_desc *desc);
    const vring_desc* get_belonging_desc(unsigned long addr, size_t size);
    bool inited();
    void submit_request(uint16_t head);
    void complete_request(uint16_t head);
    bool all_request_completed();
    void update_polling_count();
    DescRing* desc_ring;  // Descriptor ring
    AvailRing* avail_ring; // Available ring
    UsedRing* used_ring;  // Used ring
    size_t idx;
    size_t num;         // Number of descriptors
    size_t last_avail_idx; // Last available index processed
    size_t last_used_idx;  // Last used index processed
    DescChainFSM desc_chain_fsm;
    std::vector<vring_desc> generated_descs;
    struct VirtioDev* vdev;
    uint16_t queue_sel;
    size_t polling_count;
#define MAX_REQUEST_NUMBER 3
    mutable RequestStatus request_status[MAX_REQUEST_NUMBER];
    mutable size_t request_cnt = 0;
    enum {
        QUEUE_RX,
        QUEUE_TX,
        QUEUE_NORMAL,
        QUEUE_CTRL,
        QUEUE_EVENT
    } type;
};

struct ConfigSpace {
    unsigned long address; // Address of the config space
    size_t size;        // Size of the config space
    enum ConfigSpaceType {
        COMMON=1,
        ISR,
        DEVICE,
        NOTIFY
    } type;
    unsigned long read(size_t offset, size_t sz) const;
    bx_address get_avail_ring_addr() const;
    bx_address get_used_ring_addr() const;
    bx_address get_desc_ring_addr() const;
    bool set_avail_ring_addr(unsigned long addr) const;
    bool set_used_ring_addr(unsigned long addr) const;
    bool set_desc_ring_addr(unsigned long addr) const;
    bool setup_queue() const;
    size_t get_queue_size() const;
    size_t get_queue_num() const;
    size_t get_queue_sel() const;
    void set_queue_size(size_t sz) const;
    void set_queue_num(size_t num) const;
    bool set_queue_sel(size_t sel) const;
    bool set_queue_enable(size_t sel) const;
    uint64_t get_features() const;
    bool write(size_t offset, size_t sz, unsigned long value) const;
    bool contains(unsigned long addr) const;
};

#define VIRTIO_NAME_MAX 64
#define CFG_START(addr) ((addr) >> 14 << 14)
class VQueueManager;
struct VirtioDev {
    VirtioDev();
    char name[VIRTIO_NAME_MAX]; // Name of the device
    VQueue* queues[VIRTIO_QUEUE_MAX];
    size_t queue_num;
    unsigned long features; // Device features
    unsigned long multiplier;
    ConfigSpace common_cfg; // Common configuration space
    ConfigSpace isr_cfg;
    ConfigSpace device_cfg; // Device-specific configuration space
    ConfigSpace notify_cfg; // Notification configuration space
    bool to_fuzz;
    bool is_net;
    bool is_scsi;
    bool packed;
    bool indirect_desc;
    void enumerate_queues_from_common_cfg();
    bool inited();
    void set_status(uint8_t status);
    void set_device_features(uint64_t features);
    void set_guest_features(uint64_t features);
    uint8_t get_status();
    uint64_t get_device_features();
    uint64_t get_guest_features();
    bool set_packed_queue(bool enable);
    bool disable_packed_queue();
    bool renegotiate_features(uint64_t new_guest_features);
    
};

class VQueueManager {
public:
    VQueueManager(): virtio_devs(), virtio_dev_list(), queue_list(), rings_grouped_by_page(), all_queue_count(0UL), generated_descs(), seen_buffers(), indirect_tables(), fuzzed_dev_cache(nullptr), hook_disabled(false) {}
    typedef tsl::robin_set<const VRing*> VRingSet;
    bool create_virtio_device(const std::string& name, bool to_fuzz=false);
    void add_config_space(const std::string& name, enum ConfigSpace::ConfigSpaceType type, unsigned long address, size_t size);
    void group_vrings_by_page();
    const VRing* get_belonging_vring(bx_address address);
    void reset_all_queue();
    size_t get_num_virtio_dev() {return virtio_dev_list.size();}
    VirtioDev* get_virtio_dev(size_t index) {
        if (index >= virtio_dev_list.size()) return NULL;
        else return virtio_dev_list[index];
    }
    size_t allocate_new_queue_idx() {return all_queue_count++;}
    bool init_queues_for_dev(VirtioDev* vdev);
    bool init_queues();
    VirtioDev* get_vdev_by_name(const std::string& name);
    VirtioDev* get_fuzzed_dev();
    void add_desc(const fuzzer::vring_desc_with_info* desc) {generated_descs.push_back(desc);}
    void reset_generated_desc() {generated_descs.clear();}
    const fuzzer::vring_desc_with_info* get_desc_by_gpa(uint64_t gpa);

    void add_seen_buffer(uint64_t start, uint64_t size);
    void reset_seen_buffer() {seen_buffers.clear();}
    uint64_t overlapped_size(uint64_t start, uint64_t size); /* if non-overlap, return 0 */

    size_t get_queue_list_size() const {return queue_list.size();}
    void add_to_queue_list(VQueue* queue) {queue_list.push_back(queue);}
    VQueue* get_queue_by_id(size_t index) {
        if (index >= queue_list.size()) return NULL;
        else return queue_list[index];
    }
    void disable_hook() {hook_disabled = true;}
    void enable_hook() {hook_disabled = false;}
    bool hooks_disabled() const {return hook_disabled;}

    void reset_indirect_tables() {
        indirect_tables.clear();
        indirect_alloc_scratch_idx = 4;
        indirect_alloc_off = 0;
    }
    void add_indirect_table(bx_address base_gpa, std::vector<uint8_t>&& bytes);
    const std::vector<uint8_t>* find_indirect_table(bx_address gpa, bx_address* base_gpa_out) const;
    bx_address alloc_indirect_table_gpa(size_t bytes_len);

private:
    void group_vring_by_page(const VRing* vring);
    tsl::robin_map<std::string, VirtioDev*> virtio_devs; // Map of Virtio devices by name
    std::vector<VirtioDev*> virtio_dev_list;                                                           
    std::vector<VQueue*> queue_list;
    tsl::robin_map<bx_address, VRingSet> rings_grouped_by_page;
    size_t all_queue_count;
    std::vector<const fuzzer::vring_desc_with_info*> generated_descs;
    tsl::robin_map<uint64_t, size_t> seen_buffers;
    tsl::robin_map<bx_address, std::vector<uint8_t>> indirect_tables;
    size_t indirect_alloc_scratch_idx = 4;
    size_t indirect_alloc_off = 0;
    VirtioDev* fuzzed_dev_cache;
    bool hook_disabled = false;
};

VQueueManager& get_vqueue_manager();

typedef uint64_t hwaddr;
typedef struct VirtQueueElement
{
    unsigned int index;
    unsigned int len;
    unsigned int ndescs;
    unsigned int out_num;
    unsigned int in_num;
    /* Element has been processed (VIRTIO_F_IN_ORDER) */
    bool in_order_filled;
    hwaddr *in_addr;
    hwaddr *out_addr;
    struct iovec *in_sg;
    struct iovec *out_sg;
    size_t in_sgl_size(unsigned cpu);
    size_t out_sgl_size(unsigned cpu);
} VirtQueueElement;

int read_virtqueue_element(unsigned cpu, bx_address elem_ptr_hva, VirtQueueElement* elem);

int ingest_vring(unsigned cpu, bx_address addr, size_t len, void* data);
inline int ingest_vring(bx_address addr, size_t len, void* data) {
    return ingest_vring(0, addr, len, data);
}

void AddDescSize(uint16_t queue_id, uint16_t desc_idx, bool is_out, uint32_t size);
const DescSize* GetDescSizeHints(uint16_t queue_id, uint16_t desc_idx, bool is_out);

#endif
