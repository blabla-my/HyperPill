#ifndef MUTATE_H
#define MUTATE_H

#include <stdint.h>
#include <stddef.h>
#include "virtio.h"

#define DESC_ARRAY_MAX_LEN 0x40
#define DESC_POOL_SEPARATOR "DESCPOOL"
#define DESC_POOL_SEPARATOR_LEN 8

struct vring_desc_with_info;
struct DescInfo;

struct DescPool {
    size_t len;
    vring_desc_with_info array[DESC_ARRAY_MAX_LEN];

    const size_t get_size() const;
    const vring_desc_with_info* get_item(size_t idx) const;
    bool add(const vring_desc_with_info* desc_with_info);
    vring_desc_with_info* new_desc();
    const vring_desc_with_info* ingest_desc(const DescInfo* desc_info);
    size_t deserialize(const uint8_t* data, size_t len);
    size_t serialize(void* dst, size_t max_len) const;

    DescPool();
    ~DescPool();
} __attribute__((packed));

#endif
