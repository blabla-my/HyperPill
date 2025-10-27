#ifndef CONVEYOR_H
#define CONVEYOR_H

#include "vendor/libfuzzer-ng/FuzzerTracePC.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <vector>

#include "virtio.h"
#include "mutate.h"

#define SEPARATOR "FUZZ"
#define SEPARATOR_LEN 4

// #define DESC_SEPARATOR "DESC_END"
#define DESC_SEPARATOR "\xad\xde"
#define DESC_SEPARATOR_LEN 8

#define conveyor_round(ptr, min, max) \
    do { \
        if(max>min && max - min + 1 != 0) \
            *(ptr) = ((*(ptr)) % (max - min+1)); \
        else if (max > min) \
            *(ptr) = (*(ptr)); \
        else \
            *(ptr) = 0; \
        *(ptr) += min; \
    } while(0)

DescPool* desc_pool_get();


uint8_t* final_input_get(size_t* length);
const size_t final_input_len_get();

const size_t remaining_input_len();
void ic_setup(size_t max_input);
void ic_new_input(const uint8_t* in, size_t len);
uint8_t *ic_get_output(size_t *len);
int ic_ingest8(uint8_t *result, uint8_t min, uint8_t max, bool protect);
int ic_ingest16(uint16_t *result, uint16_t min, uint16_t max, bool protect);
int ic_ingest32(uint32_t *result, uint32_t min, uint32_t max, bool protect);
int ic_ingest64(uint64_t *result, uint64_t min, uint64_t max, bool protect);
int ic_ingest8(uint8_t *result, uint8_t min, uint8_t max);
int ic_ingest16(uint16_t *result, uint16_t min, uint16_t max);
int ic_ingest32(uint32_t *result, uint32_t min, uint32_t max);
int ic_ingest64(uint64_t *result, uint64_t min, uint64_t max);
int ic_ingest_uint(void *result, size_t len, unsigned long min, unsigned long max);
uint8_t* ic_ingest_len(size_t len);
uint8_t* ic_ingest_buf(size_t *len, const char* token, size_t token_len, int minlen, int string);
void *ic_advance_until_token(const char* token, size_t len);
size_t ic_get_last_token(void);
void* ic_insert(void* src, size_t len, size_t pos);
void* ic_append(const void* src, size_t len);
size_t ic_length_until_token(const char* token, size_t len);
void ic_erase_backwards_until_token(void);
uint8_t *ic_get_cursor(void);
unsigned long ic_get_offset(void);
void ic_dump();
void ic_dump_file(const char* filepath);
void ic_dump_file_with_sha1(const char* prefix);

// Returns the size of the next buffer
size_t ic_lookahead(const char* token, size_t token_len) ;
void ic_subtract(size_t l);

int new_op(uint8_t op, uint32_t start, uint32_t end, uint32_t dma_start, uint32_t dma_len);

/* for virtio fuzz */
typedef struct {
    unsigned long pos;
    unsigned long len;
    // unsigned long addr;
} buffer_pos;
typedef std::vector<buffer_pos> buffer_pos_list;
typedef buffer_pos_list::const_iterator buffer_pos_iterator;
bool buffer_pos_empty();
void update_desc_region(uint16_t queue_idx, uint16_t desc_idx, bool is_out, unsigned long pos, unsigned long len);
void reset_buffer_pos();
buffer_pos_iterator buffer_pos_begin();
buffer_pos_iterator buffer_pos_end();

extern "C" {
void __fuzzer_set_output(uint8_t *data, size_t size);
void __fuzzer_set_op_log(void *log);
void __fuzzer_compute_sha1(const uint8_t *Data, size_t Len, uint8_t *Out);

void __trace_pc_add_desc_size(uint16_t queue_id, uint16_t desc_idx, bool is_out, uint32_t size);
void* __trace_pc_get_desc_size_hints(uint16_t queue_id, uint16_t desc_idx, bool is_out);      
void __trace_pc_add_desc_region(uint16_t queue_idx, uint16_t desc_idx, bool is_out, unsigned long pos, unsigned long len);
void* __trace_pc_get_desc_regions();
size_t __trace_pc_get_desc_regions_size();
}

#endif
