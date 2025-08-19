#ifndef VIRTIO_H
#define VIRTIO_H

#include "config.h"
#include <cstdint>
#include <sstream>
#include <stddef.h>
#include "bochs.h"
#include "cpu/cpu.h"
#include <map>
#include "tsl/robin_map.h"
#include "tsl/robin_set.h"

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

#define VIRTIO_QUEUE_MAX 1024

#define PAGE_SHIFT 12
#define PAGE_NUM(x) ((x)>>PAGE_SHIFT)

#define GUEST_MEM_SIZE 0x100000000UL 

struct ConfigSpace;

struct vring_desc {
	uint64_t addr;
	uint32_t len;
	uint16_t flags;
	uint16_t next;
};

typedef uint16_t vring_avail_elem;

struct alignas(8) vring_used_elem {
	/* Index of start of used descriptor chain. */
	uint32_t id;
	/* Total length of the descriptor chain which was used (written to) */
	uint32_t len;
};

struct VRing {
    size_t size; // the number of items in the ring
    bx_address addr_gpa; // Address of the ring
    bx_address addr_hpa;
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
    VRing() {}
    VRing(size_t size, bx_address addr_gpa);
    bx_address start() const {return addr_gpa;}
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
    virtual int ingest_elem(void*) const {return 0;};
    virtual const char* type_str() const {return "base";};

    enum FILED_TYPE {
        FLAGS, 
        INDEX,
        VRING_ELEM
    };
    virtual FILED_TYPE filed_type(bx_address address) const {return FILED_TYPE::VRING_ELEM;};

    virtual int ingest_idx(uint16_t* idx) const ;
};

struct AvailRing: VRing {
    using VRing::VRing;
    AvailRing(size_t size, bx_address addr_gpa): VRing(size,addr_gpa) {
        type = VRING_AVAIL;
        align = VRING_AVAIL_ALIGN;
    }
    bx_address end() const override {
        return addr_gpa + 3*sizeof(uint16_t) + size*sizeof(vring_avail_elem);
    }
    size_t element_size() const override {return sizeof(vring_avail_elem);}
    size_t ring_offset() const override {return sizeof(uint16_t)*2;}
    int ingest_elem(void*) const override;
    const char* type_str() const override {return "avail";}
    virtual FILED_TYPE filed_type(bx_address address) const override;
};

struct UsedRing: VRing {
    using VRing::VRing;
    UsedRing(size_t size, bx_address addr_gpa): VRing(size,addr_gpa) {
        type = VRING_USED;
        align = VRING_USED_ALIGN;
    }
    bx_address end() const override {
        return addr_gpa + 2*sizeof(uint16_t) + size*sizeof(vring_used_elem);
    }
    size_t element_size() const override {return sizeof(vring_used_elem);}
    size_t ring_offset() const override {return sizeof(uint16_t)*2;}
    int ingest_elem(void*) const override;
    const char* type_str() const override {return "used";}
    virtual FILED_TYPE filed_type(bx_address address) const override;
};

struct DescRing: VRing {
    using VRing::VRing;
    DescRing(size_t size, bx_address addr_gpa): VRing(size,addr_gpa) {
        type = VRING_DESC;
        align = VRING_DESC_ALIGN;
    }
    bx_address end() const override {
        return addr_gpa + size*sizeof(vring_desc);
    }
    size_t element_size() const override  {return sizeof(vring_desc);}
    size_t ring_offset() const override {return 0;}
    int ingest_elem(void*) const override;
    const char* type_str() const override {return "desc";}
};

struct VQueue {
    VQueue(): desc_ring(NULL), avail_ring(NULL), used_ring(NULL),
        num(0), last_avail_idx(0), last_used_idx(0) {}
    DescRing* desc_ring;  // Descriptor ring
    AvailRing* avail_ring; // Available ring
    UsedRing* used_ring;  // Used ring
    size_t num;         // Number of descriptors
    size_t last_avail_idx; // Last available index processed
    size_t last_used_idx;  // Last used index processed
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
    unsigned long read(size_t offset, size_t size) const;
    bx_address get_avail_ring_addr() const;
    bx_address get_used_ring_addr() const;
    bx_address get_desc_ring_addr() const;
    size_t get_queue_size() const;
    size_t get_queue_num() const;
    size_t get_queue_sel() const;
    void set_queue_num(size_t num) const;
    void set_queue_sel(size_t sel) const;
    bool write(size_t offset, size_t size, unsigned long value) const;
};

#define VIRTIO_NAME_MAX 64
struct VirtioDev {
    VirtioDev();
    char name[VIRTIO_NAME_MAX]; // Name of the device
    VQueue* queues[VIRTIO_QUEUE_MAX];
    size_t queue_num;
    unsigned long features; // Device features
    ConfigSpace common_cfg; // Common configuration space
    ConfigSpace isr_cfg;
    ConfigSpace device_cfg; // Device-specific configuration space
    ConfigSpace notify_cfg; // Notification configuration space
    void enumerate_queues_from_common_cfg();
};

class VQueueManager {
public:
    typedef tsl::robin_set<const VRing*> VRingSet;
    static bool create_virtio_device(const std::string& name);
    static void add_config_space(const std::string& name, enum ConfigSpace::ConfigSpaceType type, unsigned long address, size_t size);
    static void group_vrings_by_page();
    static const VRing* get_belonging_vring(bx_address address);
private:
    static void group_vring_by_page(const VRing* vring);
    static tsl::robin_map<std::string, VirtioDev> virtio_devs; // Map of Virtio devices by name
    static tsl::robin_map<bx_address, VRingSet> rings_grouped_by_page;
};

#endif