#include "FuzzerCorpus.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#endif

namespace fuzzer {

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

uint8_t* DMAData::ingest_data(size_t data_len) {
    srand(__rdtsc());
    uint8_t* addr = this->dma_data + cursor;
    if (this->cursor + data_len <= this->len) {
        this->cursor += data_len;
    } else if (this->cursor + data_len < DMA_DATA_MAX_LENGTH) {
        // Extend data with random values
        for (size_t i = this->len; i < this->cursor + data_len; i++) {
            this->dma_data[i] = rand() & 0xff;
        }
        this->len = this->cursor + data_len;
        this->cursor += data_len;
    } else {
        return nullptr;
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
    ret->desc.addr = GUEST_MEM_START + (rand() % (GUEST_MEM_SIZE));
    ret->desc.len = rand() % 0x10000;
    // ret->desc.flags = rand() & 0xffff;
    return ret;
}
const vring_desc_with_info* DescPool::ingest_desc(const DescInfo* desc_info) {
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
