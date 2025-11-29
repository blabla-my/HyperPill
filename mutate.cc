#include "vendor/libfuzzer-ng/FuzzerTracePC.h"
#include "vendor/libfuzzer-ng/FuzzerCorpus.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <ctype.h>

#include "mutate.h"
#include "virtio.h"
#include "conveyor.h"
#include "conveyor.h"
#include <sys/types.h>
#include "vendor/libfuzzer-ng/FuzzerMutate.h"

static fuzzer::DescPool* mutate_desc_pool1 = nullptr;
static fuzzer::DescPool* mutate_desc_pool2 = nullptr;
static fuzzer::DMAData* mutate_dma_data = nullptr;
static uint8_t* crossover_buffer = nullptr;

extern bool log_ops;
#define DBG_PRINT if (BX_CPU(0)->fuzztrace || log_ops)

namespace fuzzer {
    extern Fuzzer *F;
}

namespace DescMutator {

static void AlignLength(fuzzer::DescPool* desc_pool, std::mt19937 &gen) {
    if (desc_pool->len == 0) return;
    auto desc = &desc_pool->array[gen() % desc_pool->len];
    const size_t align[] = {512, 1024};
    auto choice = align[gen() % (sizeof(align)/sizeof(align[0]))];
    int mul = gen() % 4 + 1;
    desc->desc.len = mul * choice;  
}

static void AlignLengthForAll(fuzzer::DescPool* desc_pool, std::mt19937 &gen) {
    for (int i = 0; i < desc_pool->len; i++) {
        auto desc_with_info = &desc_pool->array[i];
        const auto& info = desc_with_info->desc_info;
        if (info.desc_idx == 0 && info.is_out == 1) {
            continue;
        }
        const size_t align[] = {512, 1024};
        auto choice = align[gen() % (sizeof(align)/sizeof(align[0]))];
        desc_with_info->desc.len = choice;
    }
}

static void SmallLength(fuzzer::DescPool* desc_pool, std::mt19937 &gen) {
    if (desc_pool->len == 0) return;
    auto desc = &desc_pool->array[gen() % desc_pool->len];
    size_t new_len = gen() % 0x80; // [0,64]
    desc->desc.len = new_len;
}

static void MiddleLength(fuzzer::DescPool* desc_pool, std::mt19937 &gen) {
    if (desc_pool->len == 0) return;
    auto desc = &desc_pool->array[gen() % desc_pool->len];
    size_t new_len = (gen() % 0x200) + 0x50; // [256,4352]
    desc->desc.len = new_len;
}

static void MutateLength(fuzzer::DescPool* desc_pool, std::mt19937 &gen) {
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

static void FlipBitLength(fuzzer::DescPool* desc_pool, std::mt19937 &gen) {
    if (desc_pool->len == 0) return;
    auto desc = &desc_pool->array[gen() % desc_pool->len];
    // Assuming desc->desc.len is a 32-bit unsigned integer
    uint32_t bit_pos = gen() % 32; // Random bit position from 0 to 31
    desc->desc.len ^= (1U << bit_pos); // Flip the bit
}

static void ByteFlipLength(fuzzer::DescPool* desc_pool, std::mt19937 &gen) {
    if (desc_pool->len == 0) return;
    auto desc = &desc_pool->array[gen() % desc_pool->len];
    // Assuming desc->desc.len is a 32-bit unsigned integer
    uint32_t byte_pos = gen() % 4; // Random byte position from 0 to 3
    uint32_t bit_pos = gen() % 8; // Random bit position within the byte from 0 to 7
    uint32_t mask = (1U << bit_pos) << (byte_pos * 8); // Create a mask for the specific bit
    desc->desc.len ^= mask; // Flip the bit in the chosen byte
}

static void AlignAddress(fuzzer::DescPool* desc_pool, std::mt19937 &gen) {
    if (desc_pool->len == 0) return;
    auto desc = &desc_pool->array[gen() % desc_pool->len];
    const size_t align[] = {16, 256, 512, 1024};
    auto choice = align[gen() % (sizeof(align)/sizeof(align[0]))];
    if (desc->desc.addr % choice != 0) {
        desc->desc.addr = (desc->desc.addr / choice) * choice;
    }
}

static void UpdateWithHints(fuzzer::DescPool* desc_pool, std::mt19937 &gen) {
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

static void RemoveDesc(fuzzer::DescPool* desc_pool, std::mt19937 &gen) {
    if (desc_pool->len == 0) return;
    size_t idx = gen() % desc_pool->len;
    if (idx < desc_pool->len - 1) {
        memmove(&desc_pool->array[idx], &desc_pool->array[idx + 1], (desc_pool->len - idx - 1) * sizeof(vring_desc_with_info));
    }
    desc_pool->len--;
}

std::vector<void (*)(fuzzer::DescPool*, std::mt19937 &)> mutators = {
    AlignLength,
    SmallLength,
    MiddleLength,
    MutateLength,
    // FlipBitLength,
    // ByteFlipLength,
    AlignAddress,
    UpdateWithHints,
    // RemoveDesc
};

} // namespace DescMutator

namespace DMAMutator {

static void EraseBytes(fuzzer::DMAData* dma_data, size_t MaxSize, std::mt19937 &gen) {
    if (dma_data->len <= 1) return;
    size_t n = gen() % (dma_data->len / 2) + 1;
    size_t idx = gen() % (dma_data->len - n + 1);
    memmove(dma_data->dma_data + idx, dma_data->dma_data + idx + n, dma_data->len - idx - n);
    dma_data->len -= n;
}

static void InsertByte(fuzzer::DMAData* dma_data, size_t MaxSize, std::mt19937 &gen) {
    if (dma_data->len >= std::min((size_t)DMA_DATA_MAX_LENGTH, MaxSize)) return;
    size_t idx = gen() % (dma_data->len + 1);
    memmove(dma_data->dma_data + idx + 1, dma_data->dma_data + idx, dma_data->len - idx);
    dma_data->dma_data[idx] = gen();
    dma_data->len++;
}

static void InsertRepeatedBytes(fuzzer::DMAData* dma_data, size_t MaxSize, std::mt19937 &gen) {
    const size_t kMinBytesToInsert = 3;
    size_t limit = std::min((size_t)DMA_DATA_MAX_LENGTH, MaxSize);
    if (dma_data->len + kMinBytesToInsert >= limit) return;
    size_t max_bytes_to_insert = std::min((size_t)limit - dma_data->len, (size_t)128);
    if (max_bytes_to_insert < kMinBytesToInsert) return;
    size_t n = gen() % (max_bytes_to_insert - kMinBytesToInsert + 1) + kMinBytesToInsert;
    if (dma_data->len + n > limit) return;
    size_t idx = gen() % (dma_data->len + 1);
    memmove(dma_data->dma_data + idx + n, dma_data->dma_data + idx, dma_data->len - idx);
    uint8_t byte = (gen() % 2 == 0) ? (gen() % 256) : ((gen() % 2 == 0) ? 0 : 255);
    for (size_t i = 0; i < n; i++)
        dma_data->dma_data[idx + i] = byte;
    dma_data->len += n;
}

static void ChangeByte(fuzzer::DMAData* dma_data, size_t MaxSize, std::mt19937 &gen) {
    if (dma_data->len == 0) return;
    size_t idx = gen() % dma_data->len;
    dma_data->dma_data[idx] = gen();
}

static void FlipBit(fuzzer::DMAData* dma_data, size_t MaxSize, std::mt19937 &gen) {
    if (dma_data->len == 0) return;
    size_t idx = gen() % dma_data->len;
    dma_data->dma_data[idx] ^= 1 << (gen() % 8);
}

static void ShuffleBytes(fuzzer::DMAData* dma_data, size_t MaxSize, std::mt19937 &gen) {
    if (dma_data->len < 2) return;
    size_t shuffle_amount = gen() % std::min((size_t)dma_data->len, (size_t)8) + 1;
    if (shuffle_amount > dma_data->len) shuffle_amount = dma_data->len;
    size_t shuffle_start = gen() % (dma_data->len - shuffle_amount + 1);
    std::shuffle(dma_data->dma_data + shuffle_start, dma_data->dma_data + shuffle_start + shuffle_amount, gen);
}

static void ChangeASCIIInteger(fuzzer::DMAData* dma_data, size_t MaxSize, std::mt19937 &gen) {
    if (dma_data->len == 0) return;
    size_t b = gen() % dma_data->len;
    while (b < dma_data->len && !isdigit(dma_data->dma_data[b])) b++;
    if (b == dma_data->len) return;
    size_t e = b;
    while (e < dma_data->len && isdigit(dma_data->dma_data[e])) e++;
    uint64_t val = 0;
    for (size_t i = b; i < e; i++)
        val = val * 10 + dma_data->dma_data[i] - '0';
    
    switch(gen() % 5) {
        case 0: val++; break;
        case 1: val--; break;
        case 2: val /= 2; break;
        case 3: val *= 2; break;
        case 4: val = gen() % (val * val + 1); break;
    }

    for (size_t i = b; i < e; i++) {
        size_t idx = e + b - i - 1;
        if (idx < dma_data->len) {
            dma_data->dma_data[idx] = (val % 10) + '0';
            val /= 10;
        }
    }
}

template<class T>
void ChangeBinaryInteger(fuzzer::DMAData* dma_data, size_t MaxSize, std::mt19937 &gen) {
    if (dma_data->len < sizeof(T)) return;
    size_t off = gen() % (dma_data->len - sizeof(T) + 1);
    T val;
    memcpy(&val, dma_data->dma_data + off, sizeof(val));
    val += (gen() % 21) - 10;
    memcpy(dma_data->dma_data + off, &val, sizeof(val));
}

static void Mutate_ChangeBinaryInteger(fuzzer::DMAData* dma_data, size_t MaxSize, std::mt19937 &gen) {
    switch (gen() % 4) {
        case 3: return ChangeBinaryInteger<uint64_t>(dma_data, MaxSize, gen);
        case 2: return ChangeBinaryInteger<uint32_t>(dma_data, MaxSize, gen);
        case 1: return ChangeBinaryInteger<uint16_t>(dma_data, MaxSize, gen);
        case 0: return ChangeBinaryInteger<uint8_t>(dma_data, MaxSize, gen);
    }
}

static void CopyPart(fuzzer::DMAData* dma_data, size_t MaxSize, std::mt19937 &gen) {
    if (dma_data->len == 0) return;
    size_t to_beg = gen() % dma_data->len;
    size_t copy_size = gen() % (dma_data->len - to_beg) + 1;
    copy_size = std::min(copy_size, (size_t)dma_data->len);
    size_t from_beg = gen() % (dma_data->len - copy_size + 1);
    memmove(dma_data->dma_data + to_beg, dma_data->dma_data + from_beg, copy_size);
}

static void ReplaceHotspotHint(fuzzer::DMAData* dma_data, size_t MaxSize, std::mt19937 &gen) {
    if (!fuzzer::F) return;
    const auto* II = fuzzer::F->GetMD().GetBaseII();
    if (!II || II->HotSpots.empty()) return;

    std::vector<const fuzzer::HotPos*> dma_hotspots;
    for (const auto& hotspot : II->HotSpots) {
        if (hotspot.type == fuzzer::HotPos::DMA) {
            dma_hotspots.push_back(&hotspot);
        }
    }

    if (dma_hotspots.empty()) return;

    const auto* hotspot = dma_hotspots[gen() % dma_hotspots.size()];
    if (hotspot->pos + hotspot->size > dma_data->len) return;

    memcpy(dma_data->dma_data + hotspot->pos, &hotspot->hint, hotspot->size);
}


std::vector<void (*)(fuzzer::DMAData*, size_t, std::mt19937 &)> mutators = {
    EraseBytes,
    InsertByte,
    InsertRepeatedBytes,
    ChangeByte,
    FlipBit,
    ShuffleBytes,
    ChangeASCIIInteger,
    Mutate_ChangeBinaryInteger,
    CopyPart,
    ReplaceHotspotHint,
};

} // namespace DMAMutator

namespace OpsMutator {

static size_t EraseBytes(uint8_t* data, size_t size, size_t MaxSize, std::mt19937 &gen) {
    if (size <= 1) return size;
    size_t n = gen() % (size / 2) + 1;
    size_t idx = gen() % (size - n + 1);
    memmove(data + idx, data + idx + n, size - idx - n);
    return size - n;
}

static size_t InsertByte(uint8_t* data, size_t size, size_t MaxSize, std::mt19937 &gen) {
    if (size >= std::min((size_t)MAX_OPS_LEN, MaxSize)) return size;
    size_t idx = gen() % (size + 1);
    memmove(data + idx + 1, data + idx, size - idx);
    data[idx] = gen();
    return size + 1;
}

static size_t InsertRepeatedBytes(uint8_t* data, size_t size, size_t MaxSize, std::mt19937 &gen) {
    const size_t kMinBytesToInsert = 3;
    size_t limit = std::min((size_t)MAX_OPS_LEN, MaxSize);
    if (size + kMinBytesToInsert >= limit) return size;
    size_t max_bytes_to_insert = std::min((size_t)limit - size, (size_t)128);
    if (max_bytes_to_insert < kMinBytesToInsert) return size;
    size_t n = gen() % (max_bytes_to_insert - kMinBytesToInsert + 1) + kMinBytesToInsert;
    if (size + n > limit) return size;
    size_t idx = gen() % (size + 1);
    memmove(data + idx + n, data + idx, size - idx);
    uint8_t byte = (gen() % 2 == 0) ? (gen() % 256) : ((gen() % 2 == 0) ? 0 : 255);
    for (size_t i = 0; i < n; i++)
        data[idx + i] = byte;
    return size + n;
}

static size_t ChangeByte(uint8_t* data, size_t size, size_t MaxSize, std::mt19937 &gen) {
    if (size == 0) return size;
    size_t idx = gen() % size;
    data[idx] = gen();
    return size;
}

static size_t FlipBit(uint8_t* data, size_t size, size_t MaxSize, std::mt19937 &gen) {
    if (size == 0) return size;
    size_t idx = gen() % size;
    data[idx] ^= 1 << (gen() % 8);
    return size;
}

static size_t ShuffleBytes(uint8_t* data, size_t size, size_t MaxSize, std::mt19937 &gen) {
    if (size < 2) return size;
    size_t shuffle_amount = gen() % std::min((size_t)size, (size_t)8) + 1;
    if (shuffle_amount > size) shuffle_amount = size;
    size_t shuffle_start = gen() % (size - shuffle_amount + 1);
    std::shuffle(data + shuffle_start, data + shuffle_start + shuffle_amount, gen);
    return size;
}

static size_t ReplaceHotspotHint(uint8_t* data, size_t size, size_t MaxSize, std::mt19937 &gen) {
    if (!fuzzer::F) return size;
    const auto* II = fuzzer::F->GetMD().GetBaseII();
    if (!II || II->HotSpots.empty()) return size;

    std::vector<const fuzzer::HotPos*> ops_hotspots;
    for (const auto& hotspot : II->HotSpots) {
        if (hotspot.type == fuzzer::HotPos::OPS) {
            ops_hotspots.push_back(&hotspot);
        }
    }

    if (ops_hotspots.empty()) return size;

    const auto* hotspot = ops_hotspots[gen() % ops_hotspots.size()];
    if (hotspot->pos + hotspot->size > size) return size;

    memcpy(data + hotspot->pos, &hotspot->hint, hotspot->size);
    return size;
}


static size_t ChangeASCIIInteger(uint8_t* data, size_t size, size_t MaxSize, std::mt19937 &gen) {
    if (size == 0) return size;
    size_t b = gen() % size;
    while (b < size && !isdigit(data[b])) b++;
    if (b == size) return size;
    size_t e = b;
    while (e < size && isdigit(data[e])) e++;
    uint64_t val = 0;
    for (size_t i = b; i < e; i++)
        val = val * 10 + data[i] - '0';
    
    switch(gen() % 5) {
        case 0: val++; break;
        case 1: val--; break;
        case 2: val /= 2; break;
        case 3: val *= 2; break;
        case 4: val = gen() % (val * val + 1); break;
    }

    for (size_t i = b; i < e; i++) {
        size_t idx = e + b - i - 1;
        if (idx < size) {
            data[idx] = (val % 10) + '0';
            val /= 10;
        }
    }
    return size;
}

template<class T>
void ChangeBinaryInteger(uint8_t* data, size_t size, std::mt19937 &gen) {
    if (size < sizeof(T)) return;
    size_t off = gen() % (size - sizeof(T) + 1);
    T val;
    memcpy(&val, data + off, sizeof(val));
    val += (gen() % 21) - 10;
    memcpy(data + off, &val, sizeof(val));
}

static size_t Mutate_ChangeBinaryInteger(uint8_t* data, size_t size, size_t MaxSize, std::mt19937 &gen) {
    switch (gen() % 4) {
        case 3: ChangeBinaryInteger<uint64_t>(data, size, gen); break;
        case 2: ChangeBinaryInteger<uint32_t>(data, size, gen); break;
        case 1: ChangeBinaryInteger<uint16_t>(data, size, gen); break;
        case 0: ChangeBinaryInteger<uint8_t>(data, size, gen); break;
    }
    return size;
}

static size_t CopyPart(uint8_t* data, size_t size, size_t MaxSize, std::mt19937 &gen) {
    if (size == 0) return size;
    size_t to_beg = gen() % size;
    size_t copy_size = gen() % (size - to_beg) + 1;
    copy_size = std::min(copy_size, size);
    size_t from_beg = gen() % (size - copy_size + 1);
    memmove(data + to_beg, data + from_beg, copy_size);
    return size;
}

static size_t InsertFUZZString(uint8_t* data, size_t size, size_t MaxSize, std::mt19937 &gen) {
    const char* fuzz_str = "FUZZ";
    const size_t fuzz_str_len = 4;

    size_t limit = std::min((size_t)MAX_OPS_LEN, MaxSize);

    if (size + fuzz_str_len > limit) {
        return size; // Not enough space
    }

    size_t idx = gen() % (size + 1); // Random insertion point

    // Shift existing data to the right
    memmove(data + idx + fuzz_str_len, data + idx, size - idx);

    // Insert "FUZZ"
    memcpy(data + idx, fuzz_str, fuzz_str_len);

    return size + fuzz_str_len;
}

std::vector<size_t (*)(uint8_t*, size_t, size_t, std::mt19937 &)> mutators = {
    EraseBytes,
    InsertByte,
    InsertRepeatedBytes,
    ChangeByte,
    FlipBit,
    ShuffleBytes,
    ReplaceHotspotHint,
    InsertFUZZString,
    ChangeASCIIInteger,
    Mutate_ChangeBinaryInteger,
    CopyPart,
};

} // namespace OpsMutator


static void mutate_desc(fuzzer::DescPool* pool, std::mt19937 &gen) {
    if (pool->len == 0) {
        return;
    }

    /* mutation */
    for (int i = 0; i < 1; i++) {
        auto choosed_mutator = DescMutator::mutators[gen() % DescMutator::mutators.size()];
        choosed_mutator(pool, gen);
    }
}

void mutate_dma(fuzzer::DMAData* dma_data, size_t MaxSize, std::mt19937 &gen) {
    if (dma_data->len == 0) {
        return;
    }

    /* mutation */
    for (int i = 0; i < 1; i++) {
        auto choosed_mutator = DMAMutator::mutators[gen() % DMAMutator::mutators.size()];
        choosed_mutator(dma_data, MaxSize, gen);
    }
}

static size_t mutate_ops(uint8_t* ops, size_t ops_len, size_t MaxSize, std::mt19937 &gen) {
    if (ops_len == 0) {
        return ops_len;
    }

    /* mutation */
    for (int i = 0; i < 1; i++) {
        auto choosed_mutator = OpsMutator::mutators[gen() % OpsMutator::mutators.size()];
        ops_len = choosed_mutator(ops, ops_len, MaxSize, gen);
    }
    return ops_len;
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
extern "C" size_t LLVMFuzzerMutateParadox(uint8_t *Data, size_t Size, size_t MaxSize, int type);
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                         size_t MaxSize, unsigned int Seed) {
    static void* virtio_core = getenv("VIRTIO_CORE");
    if (!mutate_desc_pool1) {
        mutate_desc_pool1 = new fuzzer::DescPool();
    }
    if (!mutate_dma_data) {
        mutate_dma_data = new fuzzer::DMAData();
    }
    if (virtio_core) {
        /* first, deserialize the input */
        uint8_t* ops = Data + sizeof(fuzzer::input_hdr);
        size_t ops_len = Size - sizeof(fuzzer::input_hdr);
        size_t new_ops_len;
        fuzzer::input_deserialize(Data, Size, ops, &ops_len, mutate_dma_data, mutate_desc_pool1);
        /* select one of the ops, dma_data, desc_pool to mutate */
        std::mt19937 gen(Seed);
        std::uniform_int_distribution<> distrib(0, 2);
        int choice = distrib(gen);
        size_t real_max_size;
        switch (choice) {
            case 0: // mutate ops
            {
                size_t MaxOpsSize = MAX_OPS_LEN < MaxSize ? MAX_OPS_LEN : MaxSize;
                ops_len = LLVMFuzzerMutateParadox(ops, ops_len, MaxOpsSize, fuzzer::HotPos::OPS);
                // ops_len = mutate_ops(ops, ops_len, MaxOpsSize, gen);
                return fuzzer::input_serialize(Data, MaxSize, ops, ops_len, mutate_dma_data, mutate_desc_pool1);
            }
            case 1: // mutate dma data
            {
                size_t MaxDMASize = DMA_DATA_MAX_LENGTH < MaxSize ? DMA_DATA_MAX_LENGTH : MaxSize;
                // mutate_dma(mutate_dma_data, MaxDMASize, gen);
                mutate_dma_data->len = LLVMFuzzerMutateParadox(mutate_dma_data->dma_data, mutate_dma_data->len, MaxDMASize, fuzzer::HotPos::DMA);
                return fuzzer::input_serialize(Data, MaxSize, ops, ops_len, mutate_dma_data, mutate_desc_pool1);
            }
            case 2: // mutate desc pool
                mutate_desc(mutate_desc_pool1, gen);
                return fuzzer::input_serialize(Data, MaxSize, ops, ops_len, mutate_dma_data, mutate_desc_pool1);
            default:
                assert(false);
        }
    } else {
        return LLVMFuzzerMutate(Data, Size, MaxSize);
    }
}
