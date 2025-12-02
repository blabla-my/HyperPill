// Header for coverage helpers in cov.cc
#ifndef HYPERPILL_COV_H
#define HYPERPILL_COV_H

#include <cstdint>
#include <cstddef>

// Increment edge counter based on caller/target addresses.
uint64_t update_edge_counter(uint64_t prev_rip, uint64_t new_rip);

// Increment virtio request counter for a given queue id.
void update_virtio_req_counter(size_t queue_id, size_t desc_idx, bool is_out);

#endif // HYPERPILL_COV_H
