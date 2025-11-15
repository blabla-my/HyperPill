#include "vendor/libfuzzer-ng/FuzzerCorpus.h"
#include "vendor/libfuzzer-ng/FuzzerTracePC.h"
#include "virtio.h"
#include <cstddef>
#include <cstdint>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "conveyor.h"
#include <sys/types.h>
#include <x86intrin.h>
#include <stdio.h>
#include <vector>

#ifndef DEBUG                                                                    
#define DEBUG 0
#endif                                                                           
#define debug_printf(fmt, ...)                                                 \
do {                                                                       \
    if (DEBUG){\
        printf("\n====== pos: %ld\n", input_cursor-input);                                 \
        printf(fmt, __VA_ARGS__);                                 \
            fflush(stdout); \
    } \
} while (0)
        /* printf("INPUT: ");\ */
        /* for(int i=0; i< input_len; i ++){\ */
        /*     if(i == input_cursor -input) printf( "[" );\ */
        /*     printf("%02x ", input[i]); \ */
        /* } \ */
        /* printf("\nOUTPUT: ");\ */
        /* for(int i=0; i< *output_len; i ++){\ */
        /*     printf("%02x ", output[i]); \ */
        /* } \ */
        /* printf("\n=====\n");\ */

#define MAXLEN 8192
#define DBG_PRINT if (BX_CPU(0)->fuzztrace || log_ops)

extern bool log_ops;

static uint8_t input[MAX_OPS_LEN];
static const uint8_t *input_cursor = input;
static size_t input_len;

static uint8_t output[MAX_OPS_LEN];
static uint8_t output_mutation_mask[MAX_OPS_LEN];
static uint8_t *output_cursor = output;
static size_t output_len;
static size_t output_lenn;

static uint8_t *output_with_desc_pool;
static size_t output_with_desc_pool_len;

static uint8_t *final_input;
static size_t final_input_len;

static fuzzer::DescPool desc_pool;
static fuzzer::DMAData dma_data;

fuzzer::DescPool* desc_pool_get() {return &desc_pool;}
fuzzer::DMAData* dma_data_get() {return &dma_data;}

uint8_t* input_get() {return (uint8_t*)input;}
size_t* input_len_get() {return &input_len;}
void reset_input_output() {
    input_cursor = input;
    input_len = 0;
    output_cursor = output;
    output_len = 0;
}

static uint8_t *last_token;
static size_t bufsize=MAX_OPS_LEN;



static uint8_t zeros[MAX_OPS_LEN];

typedef struct __attribute__((packed)){
    uint8_t op;
    uint32_t start;
    uint32_t len;
    uint32_t dma_start;
    uint32_t dma_len;
} op_log_entry;

struct{
    size_t len;
    op_log_entry data[(4096-sizeof(size_t))/(sizeof(op_log_entry))];
} op_log __attribute__ ((aligned (4096)));

int new_op(uint8_t op, uint32_t start, uint32_t end, uint32_t dma_start, uint32_t dma_len) {
    op_log.data[op_log.len].op = op;
    op_log.data[op_log.len].start = start;
    op_log.data[op_log.len].len = end - start;
    op_log.data[op_log.len].dma_start = dma_start;
    op_log.data[op_log.len].dma_len = dma_len;
    op_log.len++;
    return op_log.len;
}

// Ingest a new input
void ic_new_input(const uint8_t* in, size_t len) {
    memcpy(input, in, len);
    input_len = len;
    input_cursor = input;

    output_cursor = output;
    output_len = 0;
    memset(output_mutation_mask, 0, bufsize-output_len);
    last_token = output;
}

uint8_t *ic_get_cursor(void){
    return output_cursor;
}

unsigned long ic_get_offset(void){
    return (unsigned long)(output_cursor - output);
}

size_t ic_get_last_token(void){
    return last_token-output;
}

size_t ic_lookahead(const char* token, size_t token_len) { 
    size_t ret = 0;
    uint8_t *next_token = (uint8_t*) memmem(input_cursor,
            input + input_len - input_cursor,
            token,
            token_len);
    if(!next_token || next_token+token_len >= input+input_len)
        return ret;
    uint8_t *after_next_token = (uint8_t*) memmem(next_token+token_len,
            input + input_len - next_token - token_len,
            token,
            token_len);
    if(!after_next_token)
        return (input+input_len-next_token-token_len);
    return after_next_token - next_token - token_len;
}

static inline uint8_t* append(const void* src, size_t len){
    if(output_cursor + len > output + bufsize)
        return NULL;
    if(!(output_cursor && output_cursor - output + len <= bufsize)){
        debug_printf("append: %s", "Assert: (output_cursor && output_cursor - output + len < bufsize)\n");
        abort();
    }
    if(DEBUG){
        printf("Appending %lx Bytes: ", len);
        for(int i=0; i<len; i++)
            printf("%02x ", ((uint8_t*)src)[i]);
        printf("\n");
    }
    memcpy(output_cursor, src, len);
    output_cursor += len;
    output_len = output_cursor - output;
    return output_cursor;
}

void* ic_insert(void* src, size_t len, size_t pos){
    if(!(output_cursor && output_cursor - output + len < bufsize)) {
        debug_printf("ic_insert: %s", "Assert: (output_cursor && output_cursor - output + len < bufsize)\n");
        abort();
    }
    if(!((output_cursor - output) + len < bufsize) ) {
        debug_printf("ic_insert: %s", "Assert: ((output_cursor - output) + len < bufsize)\n");
        abort();
    }
    if(!(pos < bufsize)) {
        debug_printf("ic_insert: %s", "Assert: (pos < bufsize)\n");
        abort();
    }
    memmove(output+pos+len, output+pos, len);
    memcpy(output+pos, src, len);
    output_cursor += len;
    output_len = output_cursor - output;
    return output_cursor;
}

void* ic_append(const void* src, size_t len){
    if(!(output_cursor && output_cursor - output + len < bufsize)) {
        debug_printf("ic_insert: %s", "Assert: (output_cursor && output_cursor - output + len < bufsize)\n");
        return NULL;
    }
    if(!((output_cursor - output) + len < bufsize) ) {
        debug_printf("ic_insert: %s", "Assert: ((output_cursor - output) + len < bufsize)\n");
        return NULL;
    }
    return append(src, len);
}


static inline const uint8_t* size_ptr(size_t len){
    if (input_cursor + len > input + input_len)
        return NULL;
    input_cursor += len;
    return input_cursor - len;
}

const size_t remaining_input_len(){
    return input + input_len - input_cursor;
}

// Return a "cannonical input": one with extraneous bytes removed, and missing
// bytes inserted (where needed).

uint8_t *ic_get_output(size_t *len)
{
    // __fuzzer_set_output(output,
    //         *output_len);
    // __fuzzer_set_op_log((void*)&op_log);
    // op_log.len = 0;
    *len = output_len;
    return output;
}

uint8_t* final_input_get(size_t* length) {
    static void* virtio_core = getenv("VIRTIO_CORE");
    if(!final_input) {
        final_input = (uint8_t*)malloc(MAXLEN + sizeof(fuzzer::DescPool) + sizeof(fuzzer::DMAData));
    }
    size_t sz = 0;

    if (virtio_core) {
        /* reset desc used state */
        for (size_t i = 0; i < desc_pool.len; i++) {
            desc_pool.array[i].used_cnt = 0;
        }
        *length = final_input_len = fuzzer::input_serialize(final_input, MAXLEN, output, output_len, dma_data_get(), desc_pool_get());
    } else {
        memcpy(final_input, output, output_len);
        *length = final_input_len = output_len;
    }

    __fuzzer_set_output(final_input,
            final_input_len);
    __fuzzer_set_op_log((void*)&op_log);
    op_log.len = 0;
    return final_input;
}
const size_t final_input_len_get() {
    return final_input_len;
}

int ic_ingest8(uint8_t *result, uint8_t min, uint8_t max, bool protect) {
    const void *src = size_ptr(sizeof(uint8_t));
    assert(max >= min);
    if(src){
        memcpy(result, src, sizeof(uint8_t));
        if(max>min && max - min + 1 != 0)
            *result = ((*result) % (max - min+1));
        else if (max > min)
            *result = (*result);
        else
            *result = 0;
        *result += min;
        if(!append(result, sizeof(uint8_t)))
            return -1;
        return 0;
    }
    return -1;
}
int ic_ingest16(uint16_t *result, uint16_t min, uint16_t max, bool protect) {
    const void *src = size_ptr(sizeof(*result));
    assert(max >= min);
    if(src){
        memcpy(result, src, sizeof(*result));
        if(max>min && max - min + 1 != 0)
            *result = ((*result) % (max - min+1));
        else if (max > min)
            *result = (*result);
        else
            *result = 0;
        *result += min;
        if(!append(result, sizeof(*result)))
            return -1;
        return 0;
    }
    return -1;
}
int ic_ingest32(uint32_t *result,uint32_t min, uint32_t max, bool protect) {

    const void *src = size_ptr(sizeof(*result));
    assert(max >= min);
    if(src){
        memcpy(result, src, sizeof(*result));
        if(max>min && max - min + 1 != 0)
            *result = ((*result) % (max - min+1));
        else if (max > min)
            *result = (*result);
        else
            *result = 0;
        *result += min;
        if(!append(result, sizeof(*result)))
            return -1;
        return 0;
    }
    return -1;
}

int ic_ingest64(uint64_t *result, uint64_t min, uint64_t max, bool protect) {
    const void *src = size_ptr(sizeof(*result));
    assert(max >= min);
    if(src){
        memcpy(result, src, sizeof(*result));
        if(max>min && max - min + 1 != 0)
            *result = ((*result) % (max - min+1));
        else if (max > min)
            *result = (*result);
        else
            *result = 0;
        *result += min;
        if(!append(result, sizeof(*result)))
            return -1;
        return 0;
    }
    return -1;
}

int ic_ingest8(uint8_t *result, uint8_t min, uint8_t max) {
    return ic_ingest8(result, min, max, false);
}
int ic_ingest16(uint16_t *result, uint16_t min, uint16_t max) {
    return ic_ingest16(result, min, max, false);
}
int ic_ingest32(uint32_t *result, uint32_t min, uint32_t max) {
    return ic_ingest32(result, min, max, false);
}
int ic_ingest64(uint64_t *result, uint64_t min, uint64_t max) {
    return ic_ingest64(result, min, max, false);
}

uint8_t* ic_ingest_len(size_t len) {
    debug_printf("INGEST LEN: %ld. CURSOR: %ld INPUT_LEN: %lx\n", len, input_cursor-input, input_len);
    uint8_t *result = output_cursor;

    size_t copy;
    if(input_cursor + len > input + input_len) {
        copy = input+input_len - input_cursor; // len from current input_cursor to end
    } else {
        copy = len;
    }
    const void *src = size_ptr(copy);
    if(!append(src, copy)) {
            return NULL;
    }

    size_t remaining_len = len - copy;
    if(copy != len) {
        srand(__rdtsc());
        for (int i=0; i<remaining_len; i++){
            zeros[i] = rand() % 0xFF;
        }
    }
    if(!append(zeros, remaining_len)) {
            return NULL;
    }
    return result;
}

int ic_ingest_uint(void*result, size_t len, unsigned long min, unsigned long max) {
    uint8_t *src = ic_ingest_len(len);
    if(src == NULL)
        return -1;
    memcpy(result, src, len);
    switch(len) {
        case sizeof(uint8_t):
            conveyor_round((uint8_t*)result, min, max);
            break;
        case sizeof(uint16_t):
            conveyor_round((uint16_t*)result, min, max);
            break;
        case sizeof(uint32_t):
            conveyor_round((uint32_t*)result, min, max);
            break;
        case sizeof(uint64_t):
            conveyor_round((uint64_t*)result, min, max);
            break;
        default:
            return -1;
    }
    return 0;
}

// Reads len bytes up until the token.
// If there are insufficient bytes before the token, fill with random bytes (biased to 0)
// Use minlen to increase the number of random bytes, or set minlen = -1 to disable
// Set string=1 if the random bytes should only contain ASCII characters, 0 otherwise
uint8_t* ic_ingest_buf(size_t *len, const char* token, size_t token_len, int minlen, int string) {
    debug_printf("INGEST: %ld %d. CURSOR: %ld INPUT_LEN: %lx\n", *len, minlen, input_cursor-input, input_len);
    uint8_t *result = output_cursor;
    uint8_t *token_position;
    size_t maxlen, until_token_len;
    maxlen = *len;
    size_t remaining_len = maxlen;
    size_t filled = 0;

    token_position = (uint8_t*) memmem(input_cursor,
            input + input_len - input_cursor,
            token,
            token_len);
    token_position= NULL;
    /* debug_printf("TOKEN_POSITION: %p\n", token_position - input_cursor); */
    if(token_position && token_position - input_cursor < maxlen) {
        until_token_len = token_position - input_cursor;
    } else if(token_position) {
        until_token_len = maxlen;
    } else if(input+input_len-input_cursor > maxlen) {
        until_token_len = maxlen;
    } else {
        until_token_len = input+input_len-input_cursor;
    }
    
    debug_printf("UNTIL_TOKEN_LEN: %ld\n", until_token_len);
    // First try to read data from the actual buffer (until token)
    const uint8_t* ret = size_ptr(until_token_len);
    if(ret) { 
        if(!append(ret, until_token_len))
            return NULL;
        filled += until_token_len;
        remaining_len -= until_token_len;
    }

    // Next, fill the rest with random data.
    // Increase the total len to minlen if required
    if(minlen != -1 && remaining_len + filled > minlen) {
        if(minlen > filled)
            remaining_len = minlen - filled;
        else 
            remaining_len = 0;
    }
    srand(__rdtsc());
    memset(zeros, 0, remaining_len);

    if(string) { // Fill it with random ascii
        for(int i=0; i<remaining_len && remaining_len; i++){
            zeros[i] = 0x32 + (rand()%(0x7e - 0x32));
        }
        if(remaining_len){
            zeros[remaining_len-1] = '\x00';
        }
    } else {
        for(int i=0; i < rand()%16*remaining_len/16 && remaining_len; i++) {
            zeros[rand()%remaining_len] = rand()&0xFF;
        }
    }

    if(!append(zeros, remaining_len)) {
            return NULL;
    } else {
        filled += remaining_len;
    }
    *len = filled;
    debug_printf("INGEST RESULT: %ld @%p\n", *len, result);
    return result;
}

void *ic_advance_until_token(const char* token, size_t len) {
    uint8_t* token_position = (uint8_t*) memmem(input_cursor,
            input + input_len - input_cursor,
            token,
            len);
    if (token_position) {
        if(output_len){
            last_token = append(token, len);
            if(!last_token)
                return NULL;
        }
        input_cursor = token_position + len;
    } 
    /* else if (input_cursor < input + input_len) { */
    /*     last_token = append(token, len) - len; */
    /*     token_position = (uint8_t*)input_cursor; */
    /* } */
    return token_position;
}

void ic_dump(){
    printf("IC DUMP:\nINPUT:\n");
    for(int i=0; i<input_len; i++){
        printf("\\x%02x",input[i]);
    }
    printf("\nOUTPUT:\n");
    for(int i=0; i<output_len; i++){
        printf("\\x%02x",output[i]);
    }
    printf("\n");
}

void ic_dump_file(const char* filepath) {
    static void* virtio_core = getenv("VIRTIO_CORE");
    FILE *f = fopen(filepath, "wb");

    uint8_t* data;
    size_t size;
    if (virtio_core) {
        data = final_input_get(&size);
    } else {
        data = output;
        size = output_len;
    }

    if (f) {
        printf("Dumping input to %s\n", filepath);
        fwrite(data, 1, size, f);
        fclose(f);
    } else {
        perror("Failed to open file");
    }
}

void ic_dump_file_with_sha1(const char* prefix){
    uint8_t sha1[20];
    memset(sha1, 0, sizeof(sha1));
    __fuzzer_compute_sha1(input, input_len, sha1);

    char sha1_filename[128];
    // replace space or '\n' in prefix
    char* p = strdup(prefix);
    for(int i=0; i<strlen(p); i++){
        if(p[i] == ' ' || p[i] == '\n')
            p[i] = '-';
    }

    snprintf(sha1_filename, sizeof(sha1_filename), "%s-", p);
    for(int i=0; i<20; i++){
        snprintf(sha1_filename+strlen(sha1_filename), sizeof(sha1_filename)-strlen(sha1_filename), "%02x", sha1[i]);
    }

    ic_dump_file(sha1_filename);
}

size_t ic_length_until_token(const char* token, size_t len) {
    uint8_t* token_position = (uint8_t*) memmem(input_cursor,
            input + input_len - input_cursor,
            token,
            len);
    if (token_position) {
        return token_position-input_cursor;
    }
    return -1;
}

// Erase until the last token 
void ic_erase_backwards_until_token(void) {
    if(last_token) {
        output_cursor = last_token;
        output_len = output_cursor - output;
    } else {
        output_cursor = output;
        output_len = 0;
    }
    debug_printf("Erased Backwards. Cursor is now at %lx\n", output_len);
    memset(output_mutation_mask, 0, bufsize-output_len);
}

void ic_subtract(size_t l){
    if(output_cursor - output >=l){
        output_cursor -= l;
        output_len = output_cursor - output;
    }
    debug_printf("Subtracted %lx. Cursor is now at %lx\n", l, output_len);
}

/* only when VIRTIO_CORE is enabled, we call input_deserialize to deserialize input*/
void input_deserialize(const uint8_t *data, size_t size, 
                         uint8_t *ops, size_t *ops_len, 
                         fuzzer::DMAData *dma_data, fuzzer::DescPool *desc_pool) {
    if (size < sizeof(fuzzer::input_hdr)) {
        ic_new_input(data, size);
        if (ops_len)
            *ops_len = size;
        return;
    }
    fuzzer::input_hdr* hdr = (fuzzer::input_hdr*)data;
    if (!hdr->check_magic()) {
        ic_new_input(data, size);
        if (ops_len)
            *ops_len = size;
        return;
    }
    assert(hdr->ops_size + hdr->dma_data_size + hdr->desc_pool_size + sizeof(*hdr) == size);
    //     ic_new_input(data, size);
    //     if (ops_len)
    //         *ops_len = size;
    //     return;
    // }
    data += sizeof(*hdr);
    dma_data->deserialize(data + hdr->ops_size, hdr->dma_data_size);
    desc_pool->deserialize(data + hdr->ops_size + hdr->dma_data_size, hdr->desc_pool_size);
    if (ops && ops_len) {
        if (ops != data)
            memcpy(ops, data, hdr->ops_size);
        *ops_len = hdr->ops_size;
    } else {
        ic_new_input(data, hdr->ops_size);
    }
}
size_t input_serialize(uint8_t *data, size_t max_size, uint8_t *ops, size_t ops_len, fuzzer::DMAData *dma_data, fuzzer::DescPool *desc_pool) {
    if (!ops) {
        ops = output;
        ops_len = output_len;
    } 
    assert(sizeof(fuzzer::input_hdr) + ops_len + dma_data->get_size() + desc_pool->get_size() <= max_size);
    fuzzer::input_hdr hdr = {
        .ops_size = (uint32_t)ops_len, 
        .dma_data_size = (uint32_t)dma_data->get_size(), 
        .desc_pool_size = (uint32_t)desc_pool->get_size()
    };
    hdr.set_magic();
    memcpy(data, &hdr, sizeof(hdr));
    data += sizeof(hdr);
    if (ops != data)
        memcpy(data, ops, hdr.ops_size);
    dma_data->serialize(data+hdr.ops_size, hdr.dma_data_size);
    desc_pool->serialize(data+hdr.ops_size+hdr.dma_data_size, hdr.desc_pool_size);
    return sizeof(hdr) + hdr.ops_size + hdr.dma_data_size + hdr.desc_pool_size;
}

/* for virtio fuzz */



void update_desc_region(uint16_t queue_idx, uint16_t desc_idx, bool is_out, unsigned long pos, unsigned long len) {
    __trace_pc_add_desc_region(queue_idx, desc_idx, is_out, pos, len);
}




