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
static uint8_t* crossover_buffer = nullptr;

extern bool log_ops;
#define DBG_PRINT if (BX_CPU(0)->fuzztrace || log_ops)

namespace DescMutator {

static void AlignLength(vring_desc_with_info* desc, std::mt19937 &gen) {
    const size_t align[] = {512, 1024};
    auto choice = align[gen() % (sizeof(align)/sizeof(align[0]))];
    int mul = gen() % 4 + 1;
    desc->desc.len = mul * choice;  
}

static void SmallLength(vring_desc_with_info* desc, std::mt19937 &gen) {
    size_t new_len = gen() % 0x10; // [0,64]
    desc->desc.len = new_len;
}

static void MiddleLength(vring_desc_with_info* desc, std::mt19937 &gen) {
    size_t new_len = (gen() % 0x200) + 0x50; // [256,4352]
    desc->desc.len = new_len;
}

static void MutateLength(vring_desc_with_info* desc, std::mt19937 &gen) {
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

static void AlignAddress(vring_desc_with_info* desc, std::mt19937 &gen) {
    const size_t align[] = {16, 256, 512, 1024};
    auto choice = align[gen() % (sizeof(align)/sizeof(align[0]))];
    if (desc->desc.addr % choice != 0) {
        desc->desc.addr = (desc->desc.addr / choice) * choice;
    }
}

static void UpdateWithHints(vring_desc_with_info* desc, std::mt19937 &gen) {
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

std::vector<void (*)(vring_desc_with_info*, std::mt19937 &)> mutators = {
    AlignLength,
    SmallLength,
    MiddleLength,
    AlignAddress,
    UpdateWithHints
};

} // namespace DescMutator

static void mutate_desc(DescPool* pool, std::mt19937 &gen) {
    if (pool->len == 0) {
        return;
    }

    /* mutation */
    for (int i = 0; i < 4; i++) {
        auto choosed_desc = &pool->array[gen() % pool->len];
        auto choosed_mutator = DescMutator::mutators[gen() % DescMutator::mutators.size()];
        choosed_mutator(choosed_desc, gen);
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
    if (virtio_core && mutate_desc_pool1->deserialize(Data, Size)) {
        size_t new_size = LLVMFuzzerMutate(Data, Size, MaxSize - mutate_desc_pool1->get_size() - DESC_SEPARATOR_LEN);
        std::mt19937 gen(Seed);
        mutate_desc(mutate_desc_pool1, gen);
        auto sz = mutate_desc_pool1->serialize(Data+new_size, MaxSize - new_size);
        return new_size + sz;
    } else {
        return LLVMFuzzerMutate(Data, Size, MaxSize);
    }
}


#define DBG_PRINT if (BX_CPU(0)->fuzztrace || log_ops)

extern bool log_ops;

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
    ret->desc.len = rand() % (GUEST_MEM_SIZE - (ret->desc.addr - GUEST_MEM_START));
    ret->desc.flags = rand() & 0xffff;
    DBG_PRINT {
        printf("DescPool: new desc addr %lx len %x total %lx\n", 
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
        new_desc->valid = true;
        return new_desc;
    }
    return nullptr;
}
size_t DescPool::deserialize(const uint8_t* data, size_t len) {
    uint8_t* desc_pool_pos = NULL; // Will hold the *last* match
    uint8_t* search_start = (uint8_t*)data;
    size_t remaining_len = len;
    void* current_match = NULL;

    while ((current_match = memmem(search_start, 
                                   remaining_len, 
                                   DESC_POOL_SEPARATOR, 
                                   DESC_POOL_SEPARATOR_LEN)) != NULL) {
        
        desc_pool_pos = (uint8_t*)current_match;
        search_start = (uint8_t*)current_match + DESC_POOL_SEPARATOR_LEN;

        remaining_len = len - (search_start - data);

        if (remaining_len < DESC_POOL_SEPARATOR_LEN) {
            break;
        }
    }
    if (desc_pool_pos && desc_pool_pos + DESC_POOL_SEPARATOR_LEN + sizeof(size_t) - data <= len) {
        size_t desc_num = *(size_t*)(desc_pool_pos + DESC_POOL_SEPARATOR_LEN);
        if (desc_num > DESC_ARRAY_MAX_LEN)
            return 0;
        desc_pool_pos += DESC_POOL_SEPARATOR_LEN;
        if (desc_pool_pos + sizeof(size_t) + desc_num * sizeof(vring_desc_with_info) - data <= len) {
            memcpy(this, desc_pool_pos, sizeof(size_t) + desc_num * sizeof(vring_desc_with_info));
            DBG_PRINT {
                printf("Deserialized desc pool with %ld(%ld) entries.\n", this->len, desc_num);
            }
            return DESC_POOL_SEPARATOR_LEN + get_size();
        } else {
            DBG_PRINT {
                printf("Deserialize desc pool failed: insufficient length.\n");
            }
        }
    }
    return 0;
}
size_t DescPool::serialize(void* dst, size_t max_len) const {
    size_t required_size = DESC_POOL_SEPARATOR_LEN + get_size();
    if (required_size > max_len) {
        DBG_PRINT {
            printf("Serialize desc pool failed: insufficient length.\n");
        }
        return 0UL;
    }
    uint8_t* pos = (uint8_t*)dst;
    memcpy(pos, DESC_POOL_SEPARATOR, DESC_POOL_SEPARATOR_LEN);
    memcpy(pos+DESC_POOL_SEPARATOR_LEN, this, get_size());
    DBG_PRINT {
        printf("Serialized desc pool with %ld entries.\n", len);
        fflush(stdout);
    }
    return DESC_POOL_SEPARATOR_LEN + get_size();
}
void DescPool::mark_desc_valid(const vring_desc_with_info* desc_info, bool valid) {
    /* we assume that the pointer desc_info lies within the array */
    auto index = desc_info - array;
    assert(index >= 0 && index < DESC_ARRAY_MAX_LEN);
    array[index].valid = valid;
    DBG_PRINT {
        printf("DescPool: mark desc valid: idx %lx, validity: %d\n", index, valid);
    }
}

size_t DescPool::remove_invalid_descs() {
    DescPool tmp_pool;
    for (size_t i = 0; i < len; i++) {
        vring_desc_with_info* desc_with_info = &array[i];
        if (desc_with_info->valid) {
            tmp_pool.add(desc_with_info);
        } else {
            DBG_PRINT {
                printf("DescPool: removing invalid desc idx %x for queue %u is_out %d addr %lx len %x\n", 
                    desc_with_info->desc_info.desc_idx,
                    desc_with_info->desc_info.queue_id,
                    desc_with_info->desc_info.is_out,
                    desc_with_info->desc.addr,
                    desc_with_info->desc.len);
            }
        }
    }
    if (tmp_pool.len == len) {
        return 0;
    } else {
        size_t removed = len - tmp_pool.len;
        len = tmp_pool.len;
        memcpy(array, tmp_pool.array, sizeof(array));
        return removed;
    }
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
