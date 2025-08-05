#ifndef VQUEUE_H
#define VQUEUE_H

#include "config.h"
#include <stddef.h>
#include "fuzz.h"
#include "bochs.h"
#include "cpu/cpu.h"

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

struct VRing {
    size_t size; // Size of the ring
    size_t addr; // Address of the ring
    enum {
        VRING_DESC = 0,
        VRING_AVAIL = 1,
        VRING_USED = 2
    } type; // Type of the ring
};

struct VQueue {
    VRing desc;  // Descriptor ring
    VRing avail; // Available ring
    VRing used;  // Used ring
    size_t num;         // Number of descriptors
    size_t last_avail_idx; // Last available index processed
    size_t last_used_idx;  // Last used index processed
};

struct ConfigSpace {
    unsigned long address; // Address of the config space
    size_t size;        // Size of the config space
    unsigned readw(size_t offset);
    bx_address avail_ring_addr();
    bx_address used_ring_addr();
    bx_address desc_ring_addr();
    size_t queue_size();
    bool writew(size_t offset, unsigned value);
};

struct VirtioDev {
    VQueue queues[VIRTIO_QUEUE_MAX];
    unsigned long features; // Device features
    ConfigSpace common_cfg; // Common configuration space
    ConfigSpace isr_cfg;
    ConfigSpace device_cfg; // Device-specific configuration space
    ConfigSpace notify_cfg; // Notification configuration space
};

#endif