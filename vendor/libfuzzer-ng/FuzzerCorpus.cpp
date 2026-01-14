#include "FuzzerCorpus.h"
#include <cstdint>
#include <random>
#include <array>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif

namespace fuzzer {

// Thread-local RNG for DMA data generation. Seed can be overridden via env `DMA_SEED` for reproducibility.
static thread_local std::mt19937 dma_gen = []{
    const char* s = getenv("DMA_SEED");
    uint32_t seed = 0;
    if (s) {
        seed = (uint32_t)strtoul(s, NULL, 10);
    } else {
        std::random_device rd;
        seed = rd();
#if defined(__x86_64__) || defined(__i386__)
        seed ^= (uint32_t)__rdtsc();
#endif
    }
    return std::mt19937(seed);
}();

// Define small integer ranges and discrete weights for sampling.
static const std::array<std::pair<uint32_t, uint32_t>, 4> dmadata_ranges = {{
    std::make_pair<uint32_t,uint32_t>(0u, 0x1fu),        // [0, 31]
    std::make_pair<uint32_t,uint32_t>(0x20u, 0xffu),     // [32, 255]
    std::make_pair<uint32_t,uint32_t>(0x100u, 0x11fu),   // [256, 287]
    std::make_pair<uint32_t,uint32_t>(0x120u, UINT32_MAX) // [0x120, UINT32_MAX]
}};
static std::discrete_distribution<int> dmadata_which({100, 20, 100, 10});

// Generate a DMA integer according to the configured ranges and weights.
static inline uint32_t generate_dmadata_integer() {
    int idx = dmadata_which(dma_gen);
    auto range = dmadata_ranges[idx];
    return std::uniform_int_distribution<uint32_t>(range.first, range.second)(dma_gen);
}

size_t DMAData::deserialize(const uint8_t* data, size_t size) {
    len = *(uint32_t*)data;
    assert(get_size() == size);
    memset(dma_data, 0, sizeof(dma_data));
    memcpy(dma_data, data+sizeof(len), len);
    cursor = 0;
    return get_size();
}

size_t DMAData::serialize(void* dst, size_t max_len) const {
    size_t serialized_len = sizeof(len) + len;
    assert(serialized_len <= max_len);

    // Copy the 'len' field
    memcpy(dst, &this->len, sizeof(this->len));
    // Copy the actual dma_data up to 'len'
    memcpy((uint8_t*)dst + sizeof(this->len), this->dma_data, this->len);

    return serialized_len;
}

uint8_t* DMAData::ingest_data(size_t data_len, bool switch_val, bool overwrite) {
    // use the thread-local dma_gen defined above
    uint8_t* addr = this->dma_data + cursor;
    size_t remaining_len = 0; // some data may not be generated yet, remaining_len is the length of this data
    if (this->cursor + data_len <= this->len) {
        this->cursor += data_len;
    } else if (this->cursor + data_len < DMA_DATA_MAX_LENGTH) {
        remaining_len = this->cursor + data_len - this->len;
        while (remaining_len >= sizeof(uint32_t)) {
            uint32_t val = dma_gen();
            auto p = addr + data_len - remaining_len;
            *(uint32_t*)p = val;
            remaining_len -= sizeof(uint32_t);
        }
        if (remaining_len > 0) {
            uint32_t val = dma_gen();
            auto p = addr + data_len - remaining_len;
            memcpy(p, &val, remaining_len);
        }
        /* remaining_len already used; update len and cursor */
        this->len = this->cursor + data_len;
        this->cursor += data_len;
    } else {
        return nullptr;
    }
    if (overwrite && switch_val && data_len >= sizeof(uint32_t)) {
        /* if we meet possible switch field */
        auto original_value = *(uint32_t*)addr;
        if (original_value > 0xffff) {
            uint32_t new_value = generate_dmadata_integer();
            *(uint32_t*)addr = new_value;
        }
    }
    return addr;
}

DMAData::DMAData() {
    len = 0;
    cursor = 0;
    memset(dma_data, 0, sizeof(dma_data));
}

DescPool::DescPool() {
    len = 0;
    memset(array, 0, sizeof(vring_desc_with_info) * DESC_ARRAY_MAX_LEN);
}

const size_t DescPool::get_size() const {return len * sizeof(array[0]) + sizeof(len);}

const vring_desc_with_info* DescPool::get_item(size_t idx) const {
    if(idx >= len)
        return NULL;
    return &array[idx];
}
bool DescPool::add(const vring_desc_with_info* desc_with_info) {
    if(len >= DESC_ARRAY_MAX_LEN)
        return false;
    memcpy(&array[len], desc_with_info, sizeof(vring_desc_with_info));
    len++;
    return true;
}
vring_desc_with_info* DescPool::new_desc() {
    if(len >= DESC_ARRAY_MAX_LEN)
        return NULL;
    vring_desc_with_info* ret = &array[len];
    memset(ret, 0, sizeof(vring_desc_with_info));
    len++;
    srand(__rdtsc());
    vring_desc desc = {};
    desc.addr = ((uint64_t)rand() << 32) | rand();
    desc.len = rand();
    desc.flags = 0;
    desc.next = 0;
    memcpy(ret->desc, &desc, sizeof(desc));
    return ret;
}
vring_desc_with_info* DescPool::ingest_desc(const DescInfo* desc_info) {
    for (size_t i = 0; i < len; i++) {
        vring_desc_with_info* desc_with_info = &array[i];
        if (desc_with_info->desc_info.queue_id == desc_info->queue_id &&
            desc_with_info->desc_info.desc_idx == desc_info->desc_idx &&
            desc_with_info->desc_info.is_out == desc_info->is_out) {
            if (desc_with_info->used_cnt < MAX_USED_CNT) {
                desc_with_info->used_cnt ++;
                return desc_with_info;
            }
        }
    }
    auto new_desc = this->new_desc();
    if (new_desc) {
        new_desc->desc_info = *desc_info;
        new_desc->used_cnt = MAX_USED_CNT;
        return new_desc;
    }
    return nullptr;
}
size_t DescPool::deserialize(const uint8_t* data, size_t size) {
    len = *(uint32_t*)data;
    assert(get_size() == size);
    memcpy(array, data+sizeof(len), sizeof(vring_desc_with_info) * len);
    return get_size();
}
size_t DescPool::serialize(void* dst, size_t max_len) const {
    size_t serialized_len = get_size();
    assert(serialized_len <= max_len);

    // Copy the 'len' field
    memcpy(dst, &this->len, sizeof(this->len));
    // Copy the actual array data up to 'len' elements
    memcpy((uint8_t*)dst + sizeof(this->len), this->array, this->len * sizeof(vring_desc_with_info));

    return serialized_len;
}

bool input_deserialize(const uint8_t* data, size_t size, uint8_t* ops, size_t* ops_len, DMAData* dma_data, DescPool* desc_pool) {
    if (sizeof(input_hdr) > size) {
        // fallback to ops only
        memcpy(ops, data, size);
        *ops_len = size;
        dma_data->len = 0;
        dma_data->cursor = 0;
        desc_pool->len = 0;
        return false;
    }
    struct input_hdr* hdr = (struct input_hdr*)data;
    if (!hdr->check_magic()) {
        memcpy(ops, data, size);
        *ops_len = size;
        dma_data->len = 0;
        dma_data->cursor = 0;
        desc_pool->len = 0;
        return false;
    }
    size_t current_offset = sizeof(struct input_hdr);

    // Deserialize ops
    if (hdr->ops_size > 0) {
        memcpy(ops, data + current_offset, hdr->ops_size);
        *ops_len = hdr->ops_size;
        current_offset += hdr->ops_size;
    } else {
        *ops_len = 0;
    }

    // Deserialize dma_data
    dma_data->deserialize(data + current_offset, hdr->dma_data_size);
    current_offset += hdr->dma_data_size;

    // Deserialize desc_pool
    desc_pool->deserialize(data + current_offset, hdr->desc_pool_size);
    current_offset += hdr->desc_pool_size;
    return true;
}

size_t input_serialize(uint8_t* data, size_t max_size, const uint8_t* ops, size_t ops_len, const DMAData* dma_data, const DescPool* desc_pool) {
    struct input_hdr hdr;
    hdr.ops_size = ops_len;
    hdr.dma_data_size = dma_data->get_size();
    hdr.desc_pool_size = desc_pool->get_size();
    hdr.set_magic();

    size_t total_size = sizeof(struct input_hdr) + hdr.ops_size + hdr.dma_data_size + hdr.desc_pool_size;
    assert(total_size <= max_size);

    size_t current_offset = 0;

    // Serialize header
    memcpy(data + current_offset, &hdr, sizeof(struct input_hdr));
    current_offset += sizeof(struct input_hdr);

    // Serialize ops
    memcpy(data + current_offset, ops, hdr.ops_size);
    current_offset += hdr.ops_size;

    // Serialize dma_data
    dma_data->serialize(data + current_offset, max_size - current_offset);
    current_offset += hdr.dma_data_size;

    // Serialize desc_pool
    desc_pool->serialize(data + current_offset, max_size - current_offset);
    current_offset += hdr.desc_pool_size;

    return total_size;
}

} // namespace fuzzer
