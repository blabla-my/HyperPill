#ifndef VQUEUE_H
#define VQUEUE_H

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

struct vring_used_elem {
	/* Index of start of used descriptor chain. */
	uint32_t id;
	/* Total length of the descriptor chain which was used (written to) */
	uint32_t len;
};

#define VRING_AVAIL_HEADER_SIZE 4
struct VRing {
    size_t size; // the number of items in the ring
    size_t addr; // Address of the ring
    enum Type {
        VRING_DESC = 1,
        VRING_AVAIL,
        VRING_USED 
    } type; // Type of the ring
    bx_address start() const {return addr;}
    bx_address end() const {return addr;} 
    bx_address start_pagenum() const {
        return PAGE_NUM(start());
    }
    bx_address end_pagenum() const {
        return PAGE_NUM(end());
    }
    bool in_ring(bx_address address) const {
        return address >= start() && address < end();
    }
    const char* type_str() const;
};

struct AvailRing: VRing {
    bx_address end() {
        return addr + 2*sizeof(uint16_t) + size*sizeof(vring_avail_elem);
    }
    int ingest_elem(vring_avail_elem*) const;
    const char* type_str() const {return "avail";}
};

struct UsedRing: VRing {
    bx_address end() {
        return addr + 2*sizeof(uint16_t) + size*sizeof(vring_used_elem);
    }
    int ingest_elem(vring_used_elem*) const;
    const char* type_str() const {return "used";}
};

struct DescRing: VRing {
    bx_address end() {
        return addr + size*sizeof(vring_desc);
    }
    int ingest_elem(vring_desc*) const;
    const char* type_str() const {return "used";}
};

struct VQueue {
    DescRing desc_ring;  // Descriptor ring
    AvailRing avail_ring; // Available ring
    UsedRing used_ring;  // Used ring
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
    VQueue queues[VIRTIO_QUEUE_MAX];
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
    static void group_vring_by_page(const VRing& vring);
    static tsl::robin_map<std::string, VirtioDev> virtio_devs; // Map of Virtio devices by name
    static tsl::robin_map<bx_address, VRingSet> rings_grouped_by_page;
};

#endif