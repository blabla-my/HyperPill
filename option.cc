#include "option.h"
#include <cstdio>
#include <cstdlib>
#include <strings.h>
#include <vector>

static bool option_checked = false;
static bool option_checking = false;

static const char *get_env_cached(const char *name, const char **value,
				  bool *init) {
	if (!*init) {
		*init = true;
		*value = getenv(name);
	}
	return *value;
}

static bool parse_bool_value(const char *value, bool default_value) {
	if (!value)
		return default_value;
	if (value[0] == '\0')
		return true;
	if (!strcasecmp(value, "0") || !strcasecmp(value, "false") ||
	    !strcasecmp(value, "no"))
		return false;
	return true;
}

static void option_require_checked(void) {
	if (!option_checked)
		option_init();
}

static const char *manual_ranges_path_value;
static bool manual_ranges_path_init;
static const char *range_regex_value;
static bool range_regex_init;
static const char *iomem_path_value;
static bool iomem_path_init;
static const char *coverage_dump_precision_env_value;
static bool coverage_dump_precision_env_init;
static const char *icp_db_path_value;
static bool icp_db_path_init;
static const char *icp_mem_md5sum_value;
static bool icp_mem_md5sum_init;
static const char *symbols_dir_path_value;
static bool symbols_dir_path_init;
static const char *tsc_factor_env_value;
static bool tsc_factor_env_init;
static const char *link_obj_path_value;
static bool link_obj_path_init;
static const char *nslots_env_value;
static bool nslots_env_init;
static const char *link_obj_base_env_value;
static bool link_obj_base_env_init;
static const char *icp_mem_path_value;
static bool icp_mem_path_init;
static const char *icp_regs_path_value;
static bool icp_regs_path_init;
static const char *icp_vmcs_layout_path_value;
static bool icp_vmcs_layout_path_init;
static const char *icp_vmcs_addr_env_value;
static bool icp_vmcs_addr_env_init;
static const char *icp_ncpus_env_value;
static bool icp_ncpus_env_init;
static const char *kallsyms_path_value;
static bool kallsyms_path_init;
static const char *maps_path_value;
static bool maps_path_init;
static const char *snapshot_base_value;
static bool snapshot_base_init;
static const char *symbol_mapping_path_value;
static bool symbol_mapping_path_init;
static const char *link_map_path_value;
static bool link_map_path_init;
static const char *link_obj_regex_value;
static bool link_obj_regex_init;
static const char *pci_id_env_value;
static bool pci_id_env_init;
static const char *virtio_vring_log_value;
static bool virtio_vring_log_init;

void option_init(void) {
	if (option_checked || option_checking)
		return;
	option_checking = true;

	std::vector<const char *> missing;

	struct required_env {
		const char *name;
		const char **value;
		bool *init;
	};

	static const required_env required[] = {
		{"ICP_DB_PATH", &icp_db_path_value, &icp_db_path_init},
		{"ICP_MEM_PATH", &icp_mem_path_value, &icp_mem_path_init},
		{"ICP_REGS_PATH", &icp_regs_path_value, &icp_regs_path_init},
		{"ICP_VMCS_LAYOUT_PATH", &icp_vmcs_layout_path_value,
		 &icp_vmcs_layout_path_init},
		{"ICP_VMCS_ADDR", &icp_vmcs_addr_env_value,
		 &icp_vmcs_addr_env_init},
	};

	for (const auto &entry : required) {
		if (!get_env_cached(entry.name, entry.value, entry.init))
			missing.push_back(entry.name);
	}

	if (!missing.empty()) {
		fprintf(stderr,
			"Missing required environment variables:\n");
		for (const char *name : missing)
			fprintf(stderr, "  %s\n", name);
		exit(1);
	}

	option_checked = true;
	option_checking = false;
}

	#define DEFINE_BOOL_OPTION(func, env)                                          \
		bool func(void) {                                                      \
			static bool init = false;                                      \
			static bool value = false;                                     \
			if (!init) {                                                   \
				init = true;                                           \
				value = parse_bool_value(getenv(env), false);          \
			}                                                              \
			return value;                                                  \
		}

DEFINE_BOOL_OPTION(replay_enabled, "REPLAY")
DEFINE_BOOL_OPTION(no_double_fetch_enabled, "NO_DOUBLE_FETCH")
DEFINE_BOOL_OPTION(virtio_core_enabled, "VIRTIO_CORE")
DEFINE_BOOL_OPTION(virtio_feature_log_enabled, "VIRTIO_FEATURE_LOG")
DEFINE_BOOL_OPTION(virtio_ring_format_log_enabled, "VIRTIO_RING_FORMAT_LOG")
DEFINE_BOOL_OPTION(fuzz_legacy_enabled, "FUZZ_LEGACY")
DEFINE_BOOL_OPTION(fuzz_hypercalls_enabled, "FUZZ_HYPERCALLS")
DEFINE_BOOL_OPTION(log_ops_enabled, "LOG_OPS")
DEFINE_BOOL_OPTION(log_new_pc_enabled, "LOG_NEW_PC")
DEFINE_BOOL_OPTION(fuzz_enum_enabled, "FUZZ_ENUM")
DEFINE_BOOL_OPTION(nocov_enabled, "NOCOV")
DEFINE_BOOL_OPTION(kernel_dma_enabled, "KERNEL_DMA")
DEFINE_BOOL_OPTION(hyperv_enabled, "HYPERV")
DEFINE_BOOL_OPTION(cmplog_constant_only_enabled, "CMPLOG_CONSTANT_ONLY")
DEFINE_BOOL_OPTION(pc_filter_enabled, "PC_FILTER")
DEFINE_BOOL_OPTION(new_pc_qemu_only_enabled, "NEW_PC_QEMU_ONLY")
DEFINE_BOOL_OPTION(log_crashes_enabled, "LOG_CRASHES")
DEFINE_BOOL_OPTION(seen_edges_enabled, "SEEN_EDGES")
DEFINE_BOOL_OPTION(progressive_timeout_enabled, "PROGRESSIVE_TIMEOUT")
DEFINE_BOOL_OPTION(fuzz_ic_test_enabled, "FUZZ_IC_TEST")
DEFINE_BOOL_OPTION(log_writes_enabled, "LOG_WRITES")
DEFINE_BOOL_OPTION(verbose_enabled, "VERBOSE")
DEFINE_BOOL_OPTION(gdb_enabled, "GDB")
DEFINE_BOOL_OPTION(fuzz_debug_disasm_enabled, "FUZZ_DEBUG_DISASM")
DEFINE_BOOL_OPTION(hack_timer_mod_enabled, "HACK_TIMER_MOD")
DEFINE_BOOL_OPTION(abort_on_err_enabled, "ABORT_ON_ERR")
DEFINE_BOOL_OPTION(no_asan_enabled, "NO_ASAN")
DEFINE_BOOL_OPTION(kvm_enabled, "KVM")
DEFINE_BOOL_OPTION(sgl_size_infer_enabled, "SGL_SIZE_INFER")

#undef DEFINE_BOOL_OPTION

size_t nocov_scale(void) {
	static bool init = false;
	static size_t value = 1;
	if (!init) {
		init = true;
		const char *env = getenv("NOCOV_SCALE");
		if (env) {
			char *end = nullptr;
			unsigned long parsed = strtoul(env, &end, 10);
			if (end != env && *end == '\0' && parsed > 0)
				value = static_cast<size_t>(parsed);
		}
	}
	return value;
}

const char *manual_ranges_path(void) {
	option_require_checked();
	return get_env_cached("MANUAL_RANGES", &manual_ranges_path_value,
			      &manual_ranges_path_init);
}

const char *range_regex(void) {
	option_require_checked();
	return get_env_cached("RANGE_REGEX", &range_regex_value,
			      &range_regex_init);
}

const char *iomem_path(void) {
	option_require_checked();
	return get_env_cached("IOMEM", &iomem_path_value, &iomem_path_init);
}

const char *coverage_dump_precision_env(void) {
	option_require_checked();
	return get_env_cached("COVEARGE_DUMP_PRECISION",
			      &coverage_dump_precision_env_value,
			      &coverage_dump_precision_env_init);
}

const char *icp_db_path(void) {
	option_require_checked();
	return get_env_cached("ICP_DB_PATH", &icp_db_path_value,
			      &icp_db_path_init);
}

const char *icp_mem_md5sum(void) {
	option_require_checked();
	return get_env_cached("ICP_MEM_MD5SUM", &icp_mem_md5sum_value,
			      &icp_mem_md5sum_init);
}

const char *symbols_dir_path(void) {
	option_require_checked();
	return get_env_cached("SYMBOLS_DIR", &symbols_dir_path_value,
			      &symbols_dir_path_init);
}

const char *tsc_factor_env(void) {
	option_require_checked();
	return get_env_cached("TSC_FACTOR", &tsc_factor_env_value,
			      &tsc_factor_env_init);
}

const char *link_obj_path(void) {
	option_require_checked();
	return get_env_cached("LINK_OBJ_PATH", &link_obj_path_value,
			      &link_obj_path_init);
}

const char *nslots_env(void) {
	option_require_checked();
	return get_env_cached("NSLOTS", &nslots_env_value, &nslots_env_init);
}

const char *link_obj_base_env(void) {
	option_require_checked();
	return get_env_cached("LINK_OBJ_BASE", &link_obj_base_env_value,
			      &link_obj_base_env_init);
}

const char *icp_mem_path(void) {
	option_require_checked();
	return get_env_cached("ICP_MEM_PATH", &icp_mem_path_value,
			      &icp_mem_path_init);
}

const char *icp_regs_path(void) {
	option_require_checked();
	return get_env_cached("ICP_REGS_PATH", &icp_regs_path_value,
			      &icp_regs_path_init);
}

const char *icp_vmcs_layout_path(void) {
	option_require_checked();
	return get_env_cached("ICP_VMCS_LAYOUT_PATH",
			      &icp_vmcs_layout_path_value,
			      &icp_vmcs_layout_path_init);
}

const char *icp_vmcs_addr_env(void) {
	option_require_checked();
	return get_env_cached("ICP_VMCS_ADDR", &icp_vmcs_addr_env_value,
			      &icp_vmcs_addr_env_init);
}

const char *icp_ncpus_env(void) {
	option_require_checked();
	return get_env_cached("ICP_NCPUS", &icp_ncpus_env_value,
			      &icp_ncpus_env_init);
}

const char *kallsyms_path(void) {
	option_require_checked();
	return get_env_cached("KALLSYMS", &kallsyms_path_value,
			      &kallsyms_path_init);
}

const char *maps_path(void) {
	option_require_checked();
	return get_env_cached("MAPS", &maps_path_value, &maps_path_init);
}

const char *snapshot_base(void) {
	option_require_checked();
	return get_env_cached("SNAPSHOT_BASE", &snapshot_base_value,
			      &snapshot_base_init);
}

const char *symbol_mapping_path(void) {
	option_require_checked();
	return get_env_cached("SYMBOL_MAPPING", &symbol_mapping_path_value,
			      &symbol_mapping_path_init);
}

const char *link_map_path(void) {
	option_require_checked();
	return get_env_cached("LINK_MAP", &link_map_path_value,
			      &link_map_path_init);
}

const char *link_obj_regex(void) {
	option_require_checked();
	return get_env_cached("LINK_OBJ_REGEX", &link_obj_regex_value,
			      &link_obj_regex_init);
}

const char *pci_id_env(void) {
	option_require_checked();
	return get_env_cached("PCI_ID", &pci_id_env_value, &pci_id_env_init);
}

const char *virtio_vring_log(void) {
	option_require_checked();
	return get_env_cached("VIRTIO_VRING_LOG", &virtio_vring_log_value,
			      &virtio_vring_log_init);
}
