#include "vendor/libfuzzer-ng/FuzzerTracePC.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>

#include "mutate.h"
#include "virtio.h"
#include "conveyor.h"
#include <sys/types.h>


void get_desc_regions(uint8_t *Data, size_t Size, std::vector<DescRegion> &regions) {
    // search all occurrences of DESC_SEPARATOR
    size_t pos = 0;
    while (pos < Size) {
        uint8_t* token_position = (uint8_t*) memmem(Data + pos,
                Size - pos,
                DESC_SEPARATOR,
                DESC_SEPARATOR_LEN);
        if (!token_position) {
            break;
        }
        size_t token_offset = token_position - Data;
        ssize_t desc_start_offset = token_offset - sizeof(DescInfo) - sizeof(vring_desc);
        if (desc_start_offset < 0) {
            pos = token_offset + DESC_SEPARATOR_LEN;
            continue;
        }
        vring_desc* desc_ptr = (vring_desc*)(Data + desc_start_offset);
        DescInfo* desc_info_ptr = (DescInfo*)(Data + desc_start_offset + sizeof(vring_desc));
        if (desc_info_ptr->desc_idx > 0x10) {
            pos = token_offset + DESC_SEPARATOR_LEN;
            continue;
        }
        
        DescRegion region;
        region.desc_info = *desc_info_ptr;
        region.pos = desc_start_offset;
        region.len = sizeof(vring_desc);
        regions.push_back(region);

        pos = token_offset + DESC_SEPARATOR_LEN;
    }
}

size_t mutate_desc(uint8_t *Data, size_t Size, size_t MaxSize, std::mt19937 &gen) {
    std::vector<DescRegion> desc_regions;
    get_desc_regions(Data, Size, desc_regions);

    if (desc_regions.empty()) {
        return Size;
    }
    
    for (const DescRegion& region : desc_regions) {
        vring_desc* desc_ptr = (vring_desc*)(Data + region.pos);
        const DescInfo& desc_info = region.desc_info;
        // static std::vector<double> weights = {20.0, 80.0};
        DescSize* hints = (DescSize*)GetDescSizeHints(desc_info.queue_id, desc_info.desc_idx, desc_info.is_out);
        if (hints) {
            int choosed = gen() % 0x5;
            auto cur = hints;
            while (choosed > 0) {
                if (cur->next) {
                    --choosed;
                    cur = cur->next;
                } else {
                    break;
                }
            }          
            desc_ptr->len = cur->size;
            printf("mutate_desc: set len to %x, queue %x, desc_seq %x, is_out: %d\n", cur->size, desc_info.queue_id, desc_info.desc_idx, desc_info.is_out);
        } else { // no hints, set desc length to magic number
            desc_ptr->len = 0xdeadbeef + desc_info.desc_idx + desc_info.queue_id;
            printf("mutate_desc: set to magic num %x, %x\n", desc_ptr->len, desc_info.desc_idx);
        }
    }
    
    return Size;
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
  // Use the seed to initialize a simple PRNG
  static void* size_infer = getenv("SGL_SIZE_INFER");
  if (!size_infer)
    return LLVMFuzzerMutate(Data, Size, MaxSize);

  std::mt19937 gen(Seed);
  std::discrete_distribution<> dist({
        20.0,  // Weight for mutate_desc
        80.0   // Weight for LLVMFuzzerMutate
    });
  int choice = dist(gen);
  if (choice == 0)
    return mutate_desc(Data, Size, MaxSize, gen);
  else
    return LLVMFuzzerMutate(Data, Size, MaxSize);
}