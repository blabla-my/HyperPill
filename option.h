#ifndef OPTION_H
#define OPTION_H

#include <stdbool.h>
#include <stddef.h>

void option_init(void);

bool replay_enabled(void);
bool no_double_fetch_enabled(void);
bool virtio_core_enabled(void);
bool virtio_feature_log_enabled(void);
bool virtio_ring_format_log_enabled(void);
bool fuzz_legacy_enabled(void);
bool fuzz_hypercalls_enabled(void);
bool log_ops_enabled(void);
bool log_new_pc_enabled(void);
bool fuzz_enum_enabled(void);
bool nocov_enabled(void);
bool kernel_dma_enabled(void);
bool hyperv_enabled(void);
bool cmplog_constant_only_enabled(void);
bool pc_filter_enabled(void);
bool new_pc_qemu_only_enabled(void);
bool log_crashes_enabled(void);
bool seen_edges_enabled(void);
bool progressive_timeout_enabled(void);
bool fuzz_ic_test_enabled(void);
bool log_writes_enabled(void);
bool verbose_enabled(void);
bool gdb_enabled(void);
bool fuzz_debug_disasm_enabled(void);
bool hack_timer_mod_enabled(void);
bool abort_on_err_enabled(void);
bool no_asan_enabled(void);
bool kvm_enabled(void);
bool sgl_size_infer_enabled(void);
size_t nocov_scale(void);
size_t pio_icount_scale(void);

const char *manual_ranges_path(void);
const char *range_regex(void);
const char *iomem_path(void);
const char *coverage_dump_precision_env(void);
const char *icp_db_path(void);
const char *icp_mem_md5sum(void);
const char *symbols_dir_path(void);
const char *tsc_factor_env(void);
const char *link_obj_path(void);
const char *nslots_env(void);
const char *link_obj_base_env(void);
const char *icp_mem_path(void);
const char *icp_regs_path(void);
const char *icp_vmcs_layout_path(void);
const char *icp_vmcs_addr_env(void);
const char *icp_ncpus_env(void);
const char *kallsyms_path(void);
const char *maps_path(void);
const char *snapshot_base(void);
const char *symbol_mapping_path(void);
const char *link_map_path(void);
const char *link_obj_regex(void);
const char *pci_id_env(void);
const char *virtio_vring_log(void);

#endif
