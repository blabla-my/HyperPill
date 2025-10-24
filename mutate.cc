#include "vendor/libfuzzer-ng/FuzzerTracePC.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>

#include "mutate.h"
#include "virtio.h"
#include "conveyor.h"
#include "conveyor.h"
#include <sys/types.h>

static desc_pool_t* mutate_desc_pool1 = nullptr;
static desc_pool_t* mutate_desc_pool2 = nullptr;
static uint8_t* crossover_buffer = nullptr;

namespace DescMutator {

static void AlignLength(vring_desc_with_info* desc, std::mt19937 &gen) {
    const size_t align[] = {16, 256, 512, 1024};
    auto choice = align[gen() % (sizeof(align)/sizeof(align[0]))];
    int mul = gen() % 8 + 1;
    desc->desc.len = mul * choice;  
}

static void SmallLength(vring_desc_with_info* desc, std::mt19937 &gen) {
    size_t new_len = gen() % 0x200; // [0,64]
    desc->desc.len = new_len;
}

static void MiddleLength(vring_desc_with_info* desc, std::mt19937 &gen) {
    size_t new_len = (gen() % 0xe00) + 0x200; // [256,4352]
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
        printf("Mutator: Updated desc len with hint: queue %d, desc %d, is_out %d, len %u\n",
                desc->desc_info.queue_id,desc->desc_info.desc_idx, desc->desc_info.is_out, desc->desc.len);
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

static void mutate_desc(desc_pool_t* pool, std::mt19937 &gen) {
    if (pool->len == 0) {
        return;
    }
    // for (auto& choosed_desc : pool->array) {
    //     auto choosed_mutator = DescMutator::mutators[gen() % DescMutator::mutators.size()];
    //     choosed_mutator(&choosed_desc, gen);
    // }
    for (int i = 0; i < 100; i++) {
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
    if (!mutate_desc_pool1) {
        mutate_desc_pool1 = (desc_pool_t*)malloc(sizeof(desc_pool_t));
        memset(mutate_desc_pool1, 0, sizeof(desc_pool_t));
    }
    if (desc_pool_deserialize(Data, Size, mutate_desc_pool1)) {
        size_t new_size = LLVMFuzzerMutate(Data, Size, MaxSize - desc_pool_get_size(mutate_desc_pool1));
        std::mt19937 gen(Seed);
        mutate_desc(mutate_desc_pool1, gen);
        auto sz = desc_pool_serialize(mutate_desc_pool1, Data+new_size, MaxSize - new_size);
        return new_size + sz;
    } else {
        return LLVMFuzzerMutate(Data, Size, MaxSize);
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
        mutate_desc_pool1 = (desc_pool_t*)malloc(sizeof(desc_pool_t));
        memset(mutate_desc_pool1, 0, sizeof(desc_pool_t));
    }
    if (!mutate_desc_pool2) {
        mutate_desc_pool2 = (desc_pool_t*)malloc(sizeof(desc_pool_t));
        memset(mutate_desc_pool2, 0, sizeof(desc_pool_t));
    }
    auto pool1 = desc_pool_deserialize(Data1, Size1, mutate_desc_pool1);
    auto pool2 = desc_pool_deserialize(Data2, Size2, mutate_desc_pool2);
    if (!pool1 && !pool2) {
        return __fuzzer_mutation_cross_over(Data1, Size1, Data2, Size2, Out, MaxOutSize);
    }
    if (pool1 && pool2){
        std::mt19937 gen(Seed);
        size_t data1_size = Size1 - desc_pool_get_size(mutate_desc_pool1);
        size_t data2_size = Size2 - desc_pool_get_size(mutate_desc_pool2);
        size_t copy_size = crossover_desc_pool(mutate_desc_pool1, mutate_desc_pool2, gen);
        size_t new_size = __fuzzer_mutation_cross_over(Data1, data1_size, Data2, data2_size, Out, MaxOutSize-copy_size);
        memcpy(Out + new_size, mutate_desc_pool1, copy_size);
        return new_size + copy_size;
    }
    if (pool1) {
        size_t data1_size = Size1 - desc_pool_get_size(mutate_desc_pool1);
        size_t copy_size = desc_pool_get_size(mutate_desc_pool1);
        size_t new_size = __fuzzer_mutation_cross_over(Data1, data1_size, Data2, Size2, Out, MaxOutSize - copy_size);
        memcpy(Out + new_size, mutate_desc_pool1, copy_size);
        return new_size + copy_size;
    } else {
        size_t data2_size = Size2 - desc_pool_get_size(mutate_desc_pool2);
        size_t copy_size = desc_pool_get_size(mutate_desc_pool2);
        size_t new_size = __fuzzer_mutation_cross_over(Data1, Size1, Data2, data2_size, Out, MaxOutSize - copy_size);
        memcpy(Out + new_size, mutate_desc_pool2, copy_size);
        return new_size + copy_size;
    }
} */