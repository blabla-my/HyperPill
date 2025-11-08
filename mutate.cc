#include "vendor/libfuzzer-ng/FuzzerTracePC.h"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>

#include "mutate.h"
#include "virtio.h"
#include "conveyor.h"
#include "conveyor.h"
#include <sys/types.h>

static DescPool* mutate_desc_pool1 = nullptr;
static DescPool* mutate_desc_pool2 = nullptr;
static DMAData* mutate_dma_data = nullptr;
static uint8_t* crossover_buffer = nullptr;

extern bool log_ops;
#define DBG_PRINT if (BX_CPU(0)->fuzztrace || log_ops)

namespace DescMutator {

static void AlignLength(DescPool* desc_pool, std::mt19937 &gen) {
    if (desc_pool->len == 0) return;
    auto desc = &desc_pool->array[gen() % desc_pool->len];
    const size_t align[] = {512, 1024};
    auto choice = align[gen() % (sizeof(align)/sizeof(align[0]))];
    int mul = gen() % 4 + 1;
    desc->desc.len = mul * choice;  
}

static void SmallLength(DescPool* desc_pool, std::mt19937 &gen) {
    if (desc_pool->len == 0) return;
    auto desc = &desc_pool->array[gen() % desc_pool->len];
    size_t new_len = gen() % 0x80; // [0,64]
    desc->desc.len = new_len;
}

static void MiddleLength(DescPool* desc_pool, std::mt19937 &gen) {
    if (desc_pool->len == 0) return;
    auto desc = &desc_pool->array[gen() % desc_pool->len];
    size_t new_len = (gen() % 0x200) + 0x50; // [256,4352]
    desc->desc.len = new_len;
}

static void MutateLength(DescPool* desc_pool, std::mt19937 &gen) {
    if (desc_pool->len == 0) return;
    auto desc = &desc_pool->array[gen() % desc_pool->len];
    size_t change = (gen() % 33); // [0,32]
    if (gen() % 2 == 0) {
        // increase length
        desc->desc.len += change;
    } else {
        // decrease length
        if (desc->desc.len > change) {
            desc->desc.len -= change;
        } else {
            desc->desc.len = 0;
        }
    }
}

static void FlipBitLength(DescPool* desc_pool, std::mt19937 &gen) {
    if (desc_pool->len == 0) return;
    auto desc = &desc_pool->array[gen() % desc_pool->len];
    // Assuming desc->desc.len is a 32-bit unsigned integer
    uint32_t bit_pos = gen() % 32; // Random bit position from 0 to 31
    desc->desc.len ^= (1U << bit_pos); // Flip the bit
}

static void ByteFlipLength(DescPool* desc_pool, std::mt19937 &gen) {
    if (desc_pool->len == 0) return;
    auto desc = &desc_pool->array[gen() % desc_pool->len];
    // Assuming desc->desc.len is a 32-bit unsigned integer
    uint32_t byte_pos = gen() % 4; // Random byte position from 0 to 3
    uint32_t bit_pos = gen() % 8; // Random bit position within the byte from 0 to 7
    uint32_t mask = (1U << bit_pos) << (byte_pos * 8); // Create a mask for the specific bit
    desc->desc.len ^= mask; // Flip the bit in the chosen byte
}

static void AlignAddress(DescPool* desc_pool, std::mt19937 &gen) {
    if (desc_pool->len == 0) return;
    auto desc = &desc_pool->array[gen() % desc_pool->len];
    const size_t align[] = {16, 256, 512, 1024};
    auto choice = align[gen() % (sizeof(align)/sizeof(align[0]))];
    if (desc->desc.addr % choice != 0) {
        desc->desc.addr = (desc->desc.addr / choice) * choice;
    }
}

static void UpdateWithHints(DescPool* desc_pool, std::mt19937 &gen) {
    if (desc_pool->len == 0) return;
    auto desc = &desc_pool->array[gen() % desc_pool->len];
    auto hints = GetDescSizeHints(desc->desc_info.queue_id, desc->desc_info.desc_idx, desc->desc_info.is_out);
    if (hints) {
        size_t len = 0;
        auto cur = hints;
        // get the length of hints
        for (cur=hints;cur;cur = cur->next, len++);
        auto choosed_hint_idx = gen() % len;
        for (cur=hints; cur && choosed_hint_idx >0; cur = cur->next, choosed_hint_idx--);
        desc->desc.len = cur->size;
        DBG_PRINT {
            printf("Mutator: Updated desc len with hint: queue %d, desc %d, is_out %d, len %u\n",
                    desc->desc_info.queue_id,desc->desc_info.desc_idx, desc->desc_info.is_out, desc->desc.len);
        }
    } else {
        // no hints, do nothing
    }
}

static void RemoveDesc(DescPool* desc_pool, std::mt19937 &gen) {
    if (desc_pool->len == 0) return;
    size_t idx = gen() % desc_pool->len;
    if (idx < desc_pool->len - 1) {
        memmove(&desc_pool->array[idx], &desc_pool->array[idx + 1], (desc_pool->len - idx - 1) * sizeof(vring_desc_with_info));
    }
    desc_pool->len--;
}

std::vector<void (*)(DescPool*, std::mt19937 &)> mutators = {
    AlignLength,
    SmallLength,
    MiddleLength,
    MutateLength,
    FlipBitLength,
    ByteFlipLength,
    AlignAddress,
    UpdateWithHints,
    RemoveDesc
};

} // namespace DescMutator

static void mutate_desc(DescPool* pool, std::mt19937 &gen) {
    if (pool->len == 0) {
        return;
    }

    /* mutation */
    for (int i = 0; i < 1; i++) {
        auto choosed_mutator = DescMutator::mutators[gen() % DescMutator::mutators.size()];
        choosed_mutator(pool, gen);
    }
}

/**
 * @brief A custom mutator for libFuzzer.
 * * @param Data The buffer containing the input data to be mutated.
 * @param Size The current size (in bytes) of the input data.
 * @param MaxSize The maximum allowed size for the mutated data.
 * @param Seed A random seed to make mutations deterministic.
 * * @return The new size of the mutated data. You must return a size
 * less than or equal to MaxSize. Returning 0 is
 * generally discouraged unless you're at a dead end.
 */
extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                         size_t MaxSize, unsigned int Seed) {
    void* virtio_core = getenv("VIRTIO_CORE");
    if (!mutate_desc_pool1) {
        mutate_desc_pool1 = new DescPool();
    }
    if (!mutate_dma_data) {
        mutate_dma_data = new DMAData();
    }
    if (virtio_core ) {
        /* first, deserialize the input */
        uint8_t* ops = Data + sizeof(input_hdr);
        size_t ops_len = Size - sizeof(input_hdr);
        size_t new_ops_len;
        input_deserialize(Data, Size, ops, &ops_len, mutate_dma_data, mutate_desc_pool1);
        /* select one of the ops, dma_data, desc_pool to mutate */
        std::mt19937 gen(Seed);
        int choice = gen() % 3;
        switch (choice) {
            case 0: // mutate ops
                new_ops_len = LLVMFuzzerMutate(ops, ops_len, MaxSize);
                return input_serialize(Data, MaxSize, ops, new_ops_len, mutate_dma_data, mutate_desc_pool1);
            case 1: // mutate dma_data
                mutate_dma_data->len = LLVMFuzzerMutate(mutate_dma_data->dma_data, mutate_dma_data->len, MaxSize);
                return input_serialize(Data, MaxSize, ops, ops_len, mutate_dma_data, mutate_desc_pool1);
            case 2: // mutate desc pool
                mutate_desc(mutate_desc_pool1, gen);
                return input_serialize(Data, MaxSize, ops, ops_len, mutate_dma_data, mutate_desc_pool1);
            default:
                assert(false);
        }
    } else {
        return LLVMFuzzerMutate(Data, Size, MaxSize);
    }
}


#define DBG_PRINT if (BX_CPU(0)->fuzztrace || log_ops)

extern bool log_ops;

size_t DMAData::deserialize(const uint8_t* data, size_t size) {
    len = *(size_t*)data;
    assert(get_size() == size);
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
    DBG_PRINT {
        printf("DescPool: new desc addr %lx len %x total %x\n", 
            ret->desc.addr,
            ret->desc.len, len);
        fflush(stdout);
    }
    return ret;
}
const vring_desc_with_info* DescPool::ingest_desc(const DescInfo* desc_info) {
    for (size_t i = 0; i < len; i++) {
        vring_desc_with_info* desc_with_info = &array[i];
        if (desc_with_info->desc_info.queue_id == desc_info->queue_id &&
            desc_with_info->desc_info.desc_idx == desc_info->desc_idx &&
            desc_with_info->desc_info.is_out == desc_info->is_out) {
            // desc_with_info->used == false) {
            if (desc_with_info->used_cnt < MAX_USED_CNT) {
                desc_with_info->used_cnt ++;
                DBG_PRINT {
                    printf("DescPool: reusing desc idx %x for queue %u is_out %d addr %lx len %x cnt %x\n", 
                        desc_with_info->desc_info.desc_idx,
                        desc_with_info->desc_info.queue_id,
                        desc_with_info->desc_info.is_out,
                        desc_with_info->desc.addr,
                        desc_with_info->desc.len,
                        desc_with_info->used_cnt);
                }
                return desc_with_info;
            }/*  else {
                return nullptr;
            } */
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
    len = *(size_t*)data;
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

/* static size_t crossover_desc_pool(desc_pool_t* dst_pool, const desc_pool_t* src_pool, std::mt19937 &gen) {
    size_t MAX_SIZE = dst_pool->len < src_pool->len ? dst_pool->len : src_pool->len;
    for (size_t i = 0; i < MAX_SIZE; i++) {
        if (gen() % 2 == 0) {
            dst_pool->array[i] = src_pool->array[i];
        }
        if (i >= dst_pool->len) {
            dst_pool->len++;
        }
    }
    return desc_pool_get_size(dst_pool);
} */

/* extern "C" size_t __fuzzer_mutation_cross_over(const uint8_t *Data1, size_t Size1, const uint8_t *Data2,
             size_t Size2, uint8_t *Out, size_t MaxOutSize);
extern "C" size_t LLVMFuzzerCustomCrossOver(
    const uint8_t *Data1, size_t Size1,
    const uint8_t *Data2, size_t Size2,
    uint8_t *Out, size_t MaxOutSize, unsigned int Seed) {
    if (!mutate_desc_pool1) {
        mutate_desc_pool1 = new desc_pool_t();
    }
    if (!mutate_desc_pool2) {
        mutate_desc_pool2 = new desc_pool_t();
    }
    auto pool1 = mutate_desc_pool1->deserialize(Data1, Size1);
    auto pool2 = mutate_desc_pool2->deserialize(Data2, Size2);
    if (!pool1 && !pool2) {
        return __fuzzer_mutation_cross_over(Data1, Size1, Data2, Size2, Out, MaxOutSize);
    }
    if (pool1 && pool2){
        std::mt19937 gen(Seed);
        size_t data1_size = Size1 - mutate_desc_pool1->get_size();
        size_t data2_size = Size2 - mutate_desc_pool2->get_size();
        size_t copy_size = crossover_desc_pool(mutate_desc_pool1, mutate_desc_pool2, gen);
        size_t new_size = __fuzzer_mutation_cross_over(Data1, data1_size, Data2, data2_size, Out, MaxOutSize-copy_size);
        memcpy(Out + new_size, mutate_desc_pool1, copy_size);
        return new_size + copy_size;
    }
    if (pool1) {
        size_t data1_size = Size1 - mutate_desc_pool1->get_size();
        size_t copy_size = mutate_desc_pool1->get_size();
        size_t new_size = __fuzzer_mutation_cross_over(Data1, data1_size, Data2, Size2, Out, MaxOutSize - copy_size);
        memcpy(Out + new_size, mutate_desc_pool1, copy_size);
        return new_size + copy_size;
    } else {
        size_t data2_size = Size2 - mutate_desc_pool2->get_size();
        size_t copy_size = mutate_desc_pool2->get_size();
        size_t new_size = __fuzzer_mutation_cross_over(Data1, Size1, Data2, data2_size, Out, MaxOutSize - copy_size);
        memcpy(Out + new_size, mutate_desc_pool2, copy_size);
        return new_size + copy_size;
    }
} */
