#include "fuzz.h"
#include "bochs.h"
#include "config.h"
#include "conveyor.h"
#include "syntax.h"
#include "virtio.h"
#include "cov.h"
#include "option.h"
#include "vendor/libfuzzer-ng/FuzzerInternal.h"
#include "vendor/libfuzzer-ng/FuzzerTracePC.h"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <tsl/robin_map.h>

#include <ctime>

namespace fuzzer
{
extern TracePC TPC;
extern Fuzzer *F;
};

static bool syntax_model_completed_pred(void *ctx) {
	return ((SyntaxModel *)ctx)->all_completed();
}

static bool syntax_model_sync_enabled() {
	return sync_enabled();
}

enum cmds {
	OP_READ,
	OP_WRITE,
	OP_IN,
	OP_OUT,
	OP_PCI_WRITE,
	OP_MSR_WRITE,
	OP_VMCALL,
	OP_NOTIFY
};

bool log_ops;

std::map<bx_address, uint32_t> mmio_regions;
std::map<uint16_t, uint16_t> pio_regions;
std::vector<std::pair<uint64_t, uint64_t> > ram_regions;

static tsl::robin_map<bx_address, size_t> seen_dma;
uint16_t dma_start = 0;
uint16_t dma_len = 0;

/*
 * A pattern used to populate a DMA region or perform a memwrite. This is
 * useful for e.g. populating tables of unique addresses.
 * Example {.index = 1; .stride = 2; .len = 3; .data = "\x00\x01\x02"}
 * Renders as: 00 01 02   00 03 02   00 05 02   00 07 02 ...
 */
typedef struct {
	uint8_t index; /* Index of a byte to increment by stride */
	uint8_t stride; /* Increment each index'th byte by this amount */
	size_t len;
	const uint8_t *data;
} pattern;

/*
 * Allocate a block of memory and populate it with a pattern.
 */
static void *pattern_alloc(pattern p, size_t len) {
	int i;
	uint8_t *buf = (uint8_t *)malloc(len);
	uint8_t sum = 0;

	for (i = 0; i < len; ++i) {
		buf[i] = p.data[i % p.len];
		if ((i % p.len) == p.index) {
			buf[i] += sum;
			sum += p.stride;
		}
	}
	return buf;
}

/*
	returns:
	 0: success
	-1: failed to ingest element
	1: not a vring element, should be considered as normal memory read
*/
static int ingest_vring_split(unsigned cpu, bx_address addr, size_t len,
			      void *data) {
	static bool replay = replay_enabled();
	auto gpa = lookup_gpa_by_hpa(addr);
	const VRing *vring = get_vqueue_manager().get_belonging_vring(gpa);
	int rc;
	bx_address off_in_elem = 0;
	if (vring) {
		if (vring->queue && vring->queue->vdev &&
		    !vring->queue->vdev->to_fuzz) {
			// device is not being fuzzed
			// just ignore
			return 0;
		}
		uint16_t vring_idx = 0;
		uint8_t vring_elem[16] = { 0 };
		switch (vring->filed_type(gpa)) {
		case VRing::FILED_TYPE::FLAGS:
			return 0;
		case VRing::FILED_TYPE::INDEX:
			if (get_vqueue_manager().hooks_disabled()) {
				return 0;
			}
			rc = vring->ingest_idx(cpu, &vring_idx);
			if (rc == -1) {
				// -1, ingest error
				// -2, queue locates at page 0
				// if (rc == -1) // ingest error
				/* here we should not call
				 * fuzz_emu_stop_unhealthy */
				// fuzz_emu_stop_unhealthy();
				return rc;
			}
			if (rc == -2) {
				fuzz_emu_stop_polling();
				return -2;
			}
			if (rc == 1) { // genereted index, already written
				// just mark the region, do nothing
				return 0;
			}
			BX_MEM(0)->writePhysicalPage(BX_CPU(cpu), addr, len,
						     (void *)&vring_idx);
			memcpy(data, &vring_idx, len);
			return 0;
		case VRing::FILED_TYPE::VRING_ELEM:
			if (get_vqueue_manager().hooks_disabled()) {
				return 0;
			}
			rc = vring->ingest_elem(cpu, (void *)vring_elem,
						vring->element_index(gpa));
			off_in_elem =
				gpa - (vring->start() + vring->ring_offset() +
				       vring->element_index(gpa) *
					       vring->element_size());
			if (rc == -1) {
				/* here we should not call
				 * fuzz_emu_stop_unhealthy */
				// fuzz_emu_stop_unhealthy();
				return -1;
			} else if (rc == -2) {
				fuzz_emu_stop_polling();
				return -2;
			} else if (rc == 0) {
				vring->write_elem(cpu,
						  vring->element_index(gpa),
						  vring_elem);
				memcpy(data, vring_elem + off_in_elem, len);
			} else if (rc == 1) { // genereted elem, already written
				// just mark the region, do nothing
			}
			return 0;
		case VRing::FILED_TYPE::EVENT_INDEX:
			return 0; // not a vring element
		default:
			assert(false);
			return -1;
		}
	} else { /* reading buffer */
		/* get the corresponding desc */
		if (get_vqueue_manager().hooks_disabled()) {
			return 0;
		}
		auto desc_with_info = get_vqueue_manager().get_desc_by_gpa(gpa);
		if (desc_with_info) {
			static bool no_double_fetch = no_double_fetch_enabled();
			auto overlapped_size =
				get_vqueue_manager().overlapped_size(gpa, len);
			auto *queue = get_vqueue_manager().get_queue_by_id(
				desc_with_info->desc_info.queue_id);
			assert(overlapped_size <= len);

			size_t offset =
				queue->desc_chain_fsm.get_request_offset(gpa);
			bool is_out = desc_with_info->desc_info.is_out;
			bool possible_switch =
				(offset == 0 && is_out &&
				 desc_with_info->desc_info.desc_idx == 0 &&
				 !queue->vdev->is_scsi);

			if (offset > 0x100)
				return 0;

			/* ingest random data */
			bool overwrite = !replay;
			uint8_t *buf = request_buffer_get()->ingest_data(
				len, possible_switch, overwrite);
			if (!buf)
				return -1;
			/* fetch overlapped data */
			if (no_double_fetch && overlapped_size)
				BX_MEM(0)->readPhysicalPage(BX_CPU(cpu), addr,
							    overlapped_size,
							    buf);

			if (queue->vdev->is_scsi && is_out) {
				const uint8_t valid_lun[8] = { 1, 1, 0, 0,
							       0, 0, 0, 0 };
				if (queue->type == VQueue::QUEUE_NORMAL) {
					if (offset == 0) {
						buf[0] = 1; // just fix lun[0]
							    // to 1
					}
				} else if (queue->type == VQueue::QUEUE_CTRL) {
					// lun should be [8, 16) or [4, 12)
				}
			}

			/* adjust addr = addr + len - remaining_len to avoid
			 * duplicated region */
			BX_MEM(0)->writePhysicalPage(BX_CPU(cpu), addr, len,
						     (void *)buf);
			memcpy(data, buf, len);
			get_vqueue_manager().add_seen_buffer(gpa, len);
			update_virtio_req_counter(
				desc_with_info->desc_info.queue_id,
				desc_with_info->desc_info.desc_idx, is_out);
			return 0;
		} else { /* the DMA is not issued by fuzzer, do nothing */
			return 0;
		}
	}
	return 1;
}

/* packed queue variant mirroring ingest_vring_split for future packed ring
 * support */
static int ingest_vring_packed(unsigned cpu, bx_address addr, size_t len,
			       void *data) {
	static bool replay = replay_enabled();
	if (get_vqueue_manager().hooks_disabled()) {
		return 0;
	}
	auto gpa = lookup_gpa_by_hpa(addr);
	const VRing *vring = get_vqueue_manager().get_belonging_vring(gpa);
	int rc;
	bx_address off_in_elem = 0;
	if (vring) {
		if (vring->queue && vring->queue->vdev &&
		    !vring->queue->vdev->to_fuzz) {
			// device is not being fuzzed
			// just ignore
			return 0;
		}
		uint16_t vring_idx = 0;
		uint8_t vring_elem[16] = { 0 };
		switch (vring->filed_type(gpa)) {
		case VRing::FILED_TYPE::FLAGS:
			return 0;
		case VRing::FILED_TYPE::INDEX:
			if (vring->type == VRing::VRING_AVAIL && vring->queue) {
				vring->queue->update_polling_count();
			}
			rc = vring->ingest_idx(cpu, &vring_idx);
			if (rc == -1) {
				// -1, ingest error
				// -2, queue locates at page 0
				// if (rc == -1) // ingest error
				/* here we should not call
				 * fuzz_emu_stop_unhealthy */
				// fuzz_emu_stop_unhealthy();
				return rc;
			}
			if (rc == -2) {
				fuzz_emu_stop_polling();
				return -2;
			}
			if (rc == 1) { // genereted index, already written
				// just mark the region, do nothing
				return 0;
			}
			BX_MEM(0)->writePhysicalPage(BX_CPU(cpu), addr, len,
						     (void *)&vring_idx);
			memcpy(data, &vring_idx, len);
			return 0;
		case VRing::FILED_TYPE::VRING_ELEM:
			rc = vring->ingest_elem(cpu, (void *)vring_elem,
						vring->element_index(gpa));
			off_in_elem =
				gpa - (vring->start() + vring->ring_offset() +
				       vring->element_index(gpa) *
					       vring->element_size());
			if (rc == -1) {
				/* here we should not call
				 * fuzz_emu_stop_unhealthy */
				// fuzz_emu_stop_unhealthy();
				return -1;
			} else if (rc == -2) {
				fuzz_emu_stop_polling();
				return -2;
			} else if (rc == 0) {
				vring->write_elem(cpu,
						  vring->element_index(gpa),
						  vring_elem);
				memcpy(data, vring_elem + off_in_elem, len);
			} else if (rc == 1) { // genereted elem, already written
				// just mark the region, do nothing
			}
			return 0;
		case VRing::FILED_TYPE::EVENT_INDEX:
			return 0; // not a vring element
		default:
			assert(false);
			return -1;
		}
	} else { /* reading buffer */
		/* get the corresponding desc */
		auto desc_with_info = get_vqueue_manager().get_desc_by_gpa(gpa);
		if (desc_with_info) {
			static bool no_double_fetch = no_double_fetch_enabled();
			auto overlapped_size =
				get_vqueue_manager().overlapped_size(gpa, len);
			auto *queue = get_vqueue_manager().get_queue_by_id(
				desc_with_info->desc_info.queue_id);
			assert(overlapped_size <= len);

			size_t offset =
				queue->desc_chain_fsm.get_request_offset(gpa);
			bool is_out = desc_with_info->desc_info.is_out;
			bool possible_switch =
				(offset == 0 && is_out &&
				 desc_with_info->desc_info.desc_idx == 0 &&
				 !queue->vdev->is_scsi);

			if (offset > 0x100)
				return 0;

			/* ingest random data */
			bool overwrite = !replay;
			uint8_t *buf = request_buffer_get()->ingest_data(
				len, possible_switch, overwrite);
			if (!buf)
				return -1;
			/* fetch overlapped data */
			if (no_double_fetch && overlapped_size)
				BX_MEM(0)->readPhysicalPage(BX_CPU(cpu), addr,
							    overlapped_size,
							    buf);

			if (queue->vdev->is_scsi && is_out) {
				const uint8_t valid_lun[8] = { 1, 1, 0, 0,
							       0, 0, 0, 0 };
				if (queue->type == VQueue::QUEUE_NORMAL) {
					if (offset == 0) {
						buf[0] = 1; // just fix lun[0]
							    // to 1
					}
				} else if (queue->type == VQueue::QUEUE_CTRL) {
					// lun should be [8, 16) or [4, 12)
				}
			}

			/* adjust addr = addr + len - remaining_len to avoid
			 * duplicated region */
			BX_MEM(0)->writePhysicalPage(BX_CPU(cpu), addr, len,
						     (void *)buf);
			memcpy(data, buf, len);
			get_vqueue_manager().add_seen_buffer(gpa, len);
			update_virtio_req_counter(
				desc_with_info->desc_info.queue_id,
				desc_with_info->desc_info.desc_idx, is_out);
			return 0;
		} else { /* the DMA is not issued by fuzzer, do nothing */
			return 0;
		}
	}
	return 1;
}

void clear_seen_dma() {
	seen_dma.clear();
}

void fuzz_dma_read_cb(unsigned cpu, bx_phy_address addr, unsigned len,
		      void *data) {
	static bool bypass_virtio_core = virtio_core_enabled();
	uint8_t *buf;
	int rc;
	bx_phy_address origin_addr = addr;
	bx_phy_address origin_len = len;

	if (!fuzzing)
		return;

	/* we should not ignore polling */
	if (!bypass_virtio_core && seen_dma[addr + len - 1] == len) {
		// printf("DMA at %lx len %x already handled\n", addr, len);
		return;
	}

	// for (auto it = seen_dma.begin(); it != seen_dma.end(); it++) {
	// 	bx_address start = it->first - it->second + 1;
	// 	bx_address end = it->first + 1;
	// 	if ((addr >= start && addr < end)) {
	// 		if (addr + len >= end) {
	// 			len = addr + len - end;
	// 			addr = end;
	// 		} else {
	// 			return;
	// 		}
	// 	}
	// }

	if (bypass_virtio_core) {
		int rc = ingest_vring(cpu, addr, len, data);
		if (rc <= 0)
			return;
	}

	if (seen_dma.find(addr - 1) != seen_dma.end()) {
		seen_dma[addr + len - 1] = seen_dma[addr - 1] + len;
		seen_dma.erase(addr - 1);
	} else {
		seen_dma[addr + len - 1] = len;
	}
	size_t sectionlen = seen_dma[addr + len - 1];
	// might have multiple dma reads per op
	dma_len += len;

	if (sectionlen < 0x100) {
		// if DMA read is a reasonable size, obtain fuzz input for the
		// entire DMA read
		size_t l = len;
		buf = ic_ingest_buf(&l, SEPARATOR, SEPARATOR_LEN, -1, 0);
		if (buf == NULL) {
			fuzz_emu_stop_unhealthy();
			return;
		}
		BX_MEM(0)->writePhysicalPage(BX_CPU(cpu), addr, l, (void *)buf);
		memcpy(data, buf, l);
	} else if (sectionlen > 0x1000) {
	} else {
		uint8_t buf[100];
		size_t source = addr + len + 1 - sectionlen;
		if ((source + len) >> 12 != (source >> 12))
			source -= len;
		BX_MEM(0)->readPhysicalPage(BX_CPU(cpu), source, len, buf);

		// if (BX_CPU(id)->fuzztrace || log_ops) {
		// 	printf("!(medium size)dma inject: [HPA: %lx, GPA: %lx]
		// len: %lx data: ", 	       addr, lookup_gpa_by_hpa(addr),
		// len); 	for (int i = 0; i < len; i++)
		// printf("%02x ", buf[i]); 	printf("\n");
		// }
		BX_MEM(0)->writePhysicalPage(BX_CPU(cpu), addr, len, buf);
	}
}

unsigned int num_mmio_regions() {
	return mmio_regions.size();
}

static bx_address mmio_region(int idx) {
	for (auto &it : mmio_regions) {
		if (idx == 0) {
			return it.first;
		}
		idx -= 1;
	}
	return 0;
}

static bx_address mmio_region_size(bx_address addr) {
	return mmio_regions[addr];
}

static unsigned int num_pio_regions() {
	return pio_regions.size();
}

static uint16_t pio_region(int idx) {
	for (auto &it : pio_regions) {
		if (idx == 0)
			return it.first;
		idx -= 1;
	}
	return 0;
}

static uint16_t pio_region_size(uint16_t addr) {
	return pio_regions[addr];
}

static void clear_synthetic_vmexit_sideband() {
	BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_INTERRUPTION_INFO, 0);
	BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_INTERRUPTION_ERR_CODE, 0);
	BX_CPU(0)->VMwrite32(VMCS_32BIT_IDT_VECTORING_INFO, 0);
	BX_CPU(0)->VMwrite32(VMCS_32BIT_IDT_VECTORING_ERR_CODE, 0);
	BX_CPU(0)->VMwrite64(VMCS_64BIT_GUEST_PHYSICAL_ADDR, 0);
	BX_CPU(0)->VMwrite_natural(VMCS_GUEST_LINEAR_ADDR, 0);
}

static void prepare_synthetic_vmexit(uint32_t exit_reason,
				     bx_address qualification,
				     uint32_t instruction_length) {
	clear_synthetic_vmexit_sideband();
	BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, exit_reason);
	BX_CPU(0)->VMwrite_natural(VMCS_VMEXIT_QUALIFICATION, qualification);
	BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH,
			     instruction_length);
}

bool inject_halt() {
	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(0)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(0)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	prepare_synthetic_vmexit(VMX_VMEXIT_HLT, 0, 1);
	cpu_physical_memory_write(phy, "\xf4", 1);
	return true;
}

static void warn_missing_mmio_linear(const char *op, bx_address addr,
				     int size) {
	fprintf(stderr,
		"Warning: failed to find guest linear address for MMIO %s "
		"gpa=%lx size=%d\n",
		op, addr, size);
}

// INJECTORS
bool inject_write(bx_address addr, int size, uint64_t val) {
	enum Sizes { Byte, Word, Long, Quad, end_sizes };
	Bit32u combined_access = 0;
	bx_address guest_linear_addr;
	uint32_t exit_reason = vmcs_walk_guest_physical_ept(addr,
							    &combined_access);
	if (!exit_reason && (combined_access & BX_EPT_WRITE) != BX_EPT_WRITE)
		exit_reason = VMX_VMEXIT_EPT_VIOLATION;
	if (!exit_reason)
		return false;
	if (!vmcs_guest_phy2linear(addr, &guest_linear_addr, true)) {
		warn_missing_mmio_linear("write", addr, size);
		return false;
	}

	bx_address qualification = 0;
	if (exit_reason == VMX_VMEXIT_EPT_VIOLATION) {
		qualification = static_cast<bx_address>(BX_EPT_WRITE |
							(combined_access
							 << 3));
		qualification |= static_cast<bx_address>(1) << 7;
		if (BX_CPU(0)->nmi_unblocking_iret)
			qualification |= static_cast<bx_address>(1) << 12;
	}

	clear_synthetic_vmexit_sideband();
	BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, exit_reason);
	BX_CPU(0)->VMwrite_natural(VMCS_VMEXIT_QUALIFICATION,
				   qualification);
	BX_CPU(0)->VMwrite64(VMCS_64BIT_GUEST_PHYSICAL_ADDR, addr);
	if (exit_reason == VMX_VMEXIT_EPT_VIOLATION)
		BX_CPU(0)->VMwrite_natural(VMCS_GUEST_LINEAR_ADDR,
					   guest_linear_addr);

	BX_CPU(0)->set_reg64(BX_64BIT_REG_RDX, guest_linear_addr);
	BX_CPU(0)->set_reg64(BX_64BIT_REG_RAX, val);

	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(0)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(0)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	switch (size) {
	case Byte:
		BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		cpu_physical_memory_write(phy, "\x88\x02", 2);
		break;
	case Word:
		BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		cpu_physical_memory_write(phy, "\x66\x89\x02", 3);
		break;
	case Long:
		BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		cpu_physical_memory_write(phy, "\x89\x02", 2);
		break;
	case Quad:
		BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		cpu_physical_memory_write(phy, "\x48\x89\x02", 3);
		break;
	}
	return true;
}

bool inject_read(bx_address addr, int size) {
	enum Sizes { Byte, Word, Long, Quad, end_sizes };
	Bit32u combined_access = 0;
	bx_address guest_linear_addr;
	uint32_t exit_reason = vmcs_walk_guest_physical_ept(addr,
							    &combined_access);
	if (!exit_reason && (combined_access & BX_EPT_READ) != BX_EPT_READ)
		exit_reason = VMX_VMEXIT_EPT_VIOLATION;
	if (!exit_reason)
		return false;
	if (!vmcs_guest_phy2linear(addr, &guest_linear_addr, false)) {
		warn_missing_mmio_linear("read", addr, size);
		return false;
	}

	bx_address qualification = 0;
	if (exit_reason == VMX_VMEXIT_EPT_VIOLATION) {
		qualification = static_cast<bx_address>(BX_EPT_READ |
							(combined_access
							 << 3));
		qualification |= static_cast<bx_address>(1) << 7;
		if (BX_CPU(0)->nmi_unblocking_iret)
			qualification |= static_cast<bx_address>(1) << 12;
	}

	clear_synthetic_vmexit_sideband();
	BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, exit_reason);
	BX_CPU(0)->VMwrite_natural(VMCS_VMEXIT_QUALIFICATION,
				   qualification);
	BX_CPU(0)->VMwrite64(VMCS_64BIT_GUEST_PHYSICAL_ADDR, addr);
	if (exit_reason == VMX_VMEXIT_EPT_VIOLATION)
		BX_CPU(0)->VMwrite_natural(VMCS_GUEST_LINEAR_ADDR,
					   guest_linear_addr);

	BX_CPU(0)->set_reg64(BX_64BIT_REG_RCX, guest_linear_addr);

	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(0)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(0)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	switch (size) {
	case Byte:
		cpu_physical_memory_write(phy, "\x8a\x01", 2); // mov al,BYTE
							       // PTR [rcx]
		BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		break;
	case Word:
		cpu_physical_memory_write(phy, "\x66\x8b\x01", 3); // mov
								   // ax,WORD
								   // PTR [rcx]
		BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		break;
	case Long:
		cpu_physical_memory_write(phy, "\x8b\x01", 2); // mov eax,DWORD
							       // PTR [rcx]
		BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		break;
	case Quad:
		cpu_physical_memory_write(phy,
					  "\x48\x8b\x01", // mov rax,QWORD PTR
							  // [rcx]
					  3);
		BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		break;
	}
	return true;
}

bool inject_in(uint16_t addr, uint16_t size) {
	enum Sizes { Byte, Word, Long, end_sizes };
	uint64_t field_64 = 0;
	if (BX_CPU(0)->fuzztrace || log_ops) {
		printf("!in inject: [GPA: %x] len: %d\n", addr, size);
	}
	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(0)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(0)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	switch (size) {
	case Byte:
		// writes the 'in' instruction with the appropriate size into
		// code
		cpu_physical_memory_write(phy, // L0 physical addr of $rip in
					       // L2, inside the saved VMCS
					  // uses VMREAD to read the VMCS's
					  // $rip, which is a GVA look for
					  // existing code somewhere that
					  // alreaedy does the conversion
					  "\xec", 1);
		BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 1);
		break;
	case Word:
		cpu_physical_memory_write(phy, "\x66\xed", 2);
		BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		field_64 |= 1; // access size
		break;
	case Long:
		cpu_physical_memory_write(phy, "\xed", 1);
		BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 1);
		field_64 |= 3; // access size
		break;
	}

	field_64 |= (addr << 16); // port number
	field_64 |= (1 << 3); // //IN
	prepare_synthetic_vmexit(VMX_VMEXIT_IO_INSTRUCTION, field_64,
				 BX_CPU(0)->VMread32(
					 VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH));
	BX_CPU(0)->set_reg64(BX_64BIT_REG_RDX, addr);
	return true;
}

bool inject_out(uint16_t addr, uint16_t size, uint32_t value) {
	enum Sizes { Byte, Word, Long, end_sizes };
	uint64_t field_64 = 0;
	if (BX_CPU(0)->fuzztrace || log_ops) {
		printf("!out inject: [GPA: %x] len: %d data: ", addr, size);
		for (int i = 0; i < size; i++)
			printf("%02x", ((uint8_t *)&value)[i]);
		printf("\n");
	}
	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(0)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(0)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	switch (size) {
	case Byte:
		cpu_physical_memory_write(phy, "\xee", 1);
		BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 1);
		break;
	case Word:
		cpu_physical_memory_write(phy, "\x66\xef", 2);
		BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		field_64 |= 1; // access size
		break;
	case Long:
		cpu_physical_memory_write(phy, "\xef", 1);
		BX_CPU(0)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 1);
		field_64 |= 3; // access size
		break;
	}

	BX_CPU(0)->set_reg64(BX_64BIT_REG_RDX, addr);

	// write value for out
	BX_CPU(0)->set_reg64(BX_64BIT_REG_RAX, value);

	field_64 |= (addr << 16);
	prepare_synthetic_vmexit(VMX_VMEXIT_IO_INSTRUCTION, field_64,
				 BX_CPU(0)->VMread32(
					 VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH));
	return true;
}

uint32_t inject_pci_read(uint8_t device, uint8_t function, uint8_t offset) {
	uint32_t value;
	inject_out(0xcf8, 2,
		   (1U << 31) | (device << 11) | (function << 8) | offset);
	start_cpu();
	inject_in(0xcfc, 2);
	start_cpu();
	uint32_t val = BX_CPU(0)->gen_reg[BX_64BIT_REG_RAX].rrx;
	return val;
}

bool inject_pci_write(uint8_t device, uint8_t function, uint8_t offset,
		      uint32_t value) {
	inject_out(0xcf8, 2,
		   (1U << 31) | (device << 11) | (function << 8) | offset);
	start_cpu();
	inject_out(0xcfc, 2, value);
	start_cpu();
	return true;
}

bool inject_wrmsr(bx_address msr, uint64_t value) {
	bx_address phy;
	BX_CPU(0)->set_reg64(BX_64BIT_REG_RAX, value & 0xFFFFFFFF);
	BX_CPU(0)->set_reg64(BX_64BIT_REG_RDX, value >> 32);

	int res = vmcs_linear2phy(BX_CPU(0)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(0)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	cpu_physical_memory_write(phy, "\x0f\x30", 2);
	prepare_synthetic_vmexit(VMX_VMEXIT_WRMSR, 0, 2);

	BX_CPU(0)->set_reg64(BX_64BIT_REG_RCX, msr);
	start_cpu();
	return true;
}

uint64_t inject_rdmsr(bx_address msr) {
	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(0)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(0)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	cpu_physical_memory_write(phy, "\x0f\x32", 2);
	prepare_synthetic_vmexit(VMX_VMEXIT_RDMSR, 0, 2);

	BX_CPU(0)->set_reg64(BX_64BIT_REG_RCX, msr);
	start_cpu();
	return (BX_CPU(0)->get_reg64(BX_64BIT_REG_RDX) << 32) |
	       (BX_CPU(0)->get_reg64(BX_64BIT_REG_RAX) & 0xFFFFFFFF);
}

/* OPERATIONS */

bool op_write() {
	enum Sizes { Byte, Word, Long, Quad, end_sizes };
	uint8_t size;
	uint8_t base;
	uint32_t offset;
	uint64_t value;
	size_t input_off;

	if (ic_ingest8(&size, 0, Quad))
		return false;
	if (!num_mmio_regions())
		return false;
	if (ic_ingest8(&base, 0, num_mmio_regions() - 1))
		return false;
	bx_address addr = mmio_region(base);

	if (ic_ingest32(&offset, 0, mmio_region_size(addr) - 1))
		return false;
	addr += offset;

	input_off = ic_get_offset();
	switch (size) {
	case Byte:
		uint8_t val8;
		if (ic_ingest8(&val8, 0, -1))
			return false;
		value = val8;
		break;
	case Word:
		uint16_t val16;
		if (ic_ingest16(&val16, 0, -1))
			return false;
		value = val16;
		break;
	case Long:
		uint32_t val32;
		if (ic_ingest32(&val32, 0, -1))
			return false;
		value = val32;
		break;
	case Quad:
		if (ic_ingest64(&value, 0, -1))
			return false;
		break;
	}

	if (BX_CPU(0)->fuzztrace || log_ops) {
		uint32_t exit_reason =
			vmcs_translate_guest_physical_ept(addr, NULL, NULL);
		printf("!write inject: [GPA: %lx] len: %d data: ", addr,
		       1 << size);
		for (int i = 0; i < (1 << size); i++)
			printf("%02x", ((uint8_t *)&value)[i]);
		printf(" (reason: %d)\n", exit_reason);
	}
	if (!inject_write(addr, size, value))
		return false;

	start_cpu();

	return true;
}

bool op_read() {
	enum Sizes { Byte, Word, Long, Quad, end_sizes };
	uint8_t size;
	uint8_t base;
	// uint16_t offset;
	uint32_t offset;

	if (ic_ingest8(&size, 0, Quad))
		return false;
	if (!num_mmio_regions())
		return false;
	if (ic_ingest8(&base, 0, num_mmio_regions() - 1))
		return false;
	bx_address addr = mmio_region(base);
	if (ic_ingest32(&offset, 0, mmio_region_size(addr) - 1))
		return false;
	addr += offset;

	if (BX_CPU(0)->fuzztrace || log_ops) {
		printf("!read inject: [GPA: %lx] len: %d\n", addr, 1 << size);
	}
	if (!inject_read(addr, size))
		return false;

	start_cpu();
	return true;
}

bool op_out() {
	enum Sizes { Byte, Word, Long, end_sizes };
	uint8_t size;
	uint8_t base;
	uint16_t offset;
	uint32_t value;

	if (ic_ingest8(&size, 0, Long))
		return false;
	if (!num_pio_regions())
		return false;
	if (ic_ingest8(&base, 0, num_pio_regions() - 1))
		return false;

	bx_address addr = pio_region(base);
	if (ic_ingest16(&offset, 0, pio_region_size(addr) - 1))
		return false;

	bx_address phy;
	addr += offset;
	uint64_t field_64 = 0;
	if (addr == 0x160)
		return false;
	switch (size) {
	case Byte:
		uint8_t val8;
		if (ic_ingest8(&val8, 0, -1))
			return false;
		value = val8;
		break;
	case Word:
		uint16_t val16;
		if (ic_ingest16(&val16, 0, -1))
			return false;
		value = val16;
		break;
	case Long:
		uint32_t val32;
		if (ic_ingest32(&val32, 0, -1))
			return false;
		value = val32;
		break;
	}

	if (!inject_out(addr, size, value))
		return false;
	start_cpu();
	return true;
}

bool op_in() {
	enum Sizes { Byte, Word, Long, end_sizes };
	uint8_t size;
	uint8_t base;
	uint16_t offset;

	if (ic_ingest8(&size, 0, Long))
		return false;
	if (!num_pio_regions())
		return false;
	if (ic_ingest8(&base, 0, num_pio_regions() - 1))
		return false;

	bx_address addr = pio_region(base);
	if (ic_ingest16(&offset, 0, pio_region_size(addr) - 1))
		return false;
	addr += offset;

	if (!inject_in(addr, size))
		return false;
	start_cpu();
	return true;
}

static uint8_t pci_dev;
static uint8_t pci_fn;
void set_pci_device(uint8_t dev, uint8_t function) {
	pci_dev = dev;
	pci_fn = function;
	uint32_t original = inject_pci_read(pci_dev, pci_fn, 4);
	inject_pci_write(pci_dev, pci_fn, 4, original |= 0b111);
}

bool op_pci_write() {
	uint8_t device = pci_dev;
	uint8_t function = pci_fn;
	uint8_t offset;
	uint32_t value;
	if (!pci_dev)
		return false;

	if (ic_ingest8(&offset, 0, 64))
		return false;
	offset *= 4;
	if (offset == 4)
		return false;
	if (offset <= 0x10 + 24 && offset + 4 >= 0x10) // dont let us shift
						       // around BARS
		return false;
	if (offset <= 0x30 + 0x4 && offset + 4 >= 0x30) // dont let us shift
							// around BARS
		return false;
	if (offset <= 0x34 + 0x4 && offset + 4 >= 0x34) // dont let us shift
							// around BARS
		return false;
	if (offset <= 0x38 + 4 && offset + 4 >= 0x38) // dont let us shift
						      // around BARS
		return false;

	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(0)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(0)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	uint32_t val32;
	if (ic_ingest32(&val32, 0, -1))
		return false;
	value = val32;
	if (offset == 4) // dont let us shift around ROM
		value = (value & ~(0b11)) | 0b10;
	inject_pci_write(device, function, offset, value);
	return true;
}

bool op_msr_write() {
	uint32_t msr;
	uint64_t value;
	if (ic_ingest32(&msr, 0, -1))
		return false;
	if (ic_ingest64(&value, 0, -1))
		return false;

	if (BX_CPU(0)->fuzztrace || log_ops) {
		printf("!wrmsr inject: %x = %lx\n", msr, value);
	}
	return inject_wrmsr(msr, value);
}

static bx_gen_reg_t vmcall_gpregs[16 + 4];
static __typeof__(BX_CPU(0)->vmm) vmcall_xmmregs BX_CPP_AlignN(64);
static uint32_t vmcall_enabled_regs;

void insert_register_value_into_fuzz_input(int idx) {
	vmcall_enabled_regs |= (1 << idx);
}

/* Strategy:
 * vmcalls don't have a set ABI. Here are the examples of how they work for
 * various hypervisors:
 *
 * XEN:     RAX (call code), RDI, RSI, RDX, R10 R8
 * Hyper-V: RCX (rich call code), RDX, R8, XMM0-XMM5
 * KVM:     RAX (call code), RBX, RCX, RDX
 *
 * Setting all of that from the fuzzer input would waste a ton of fuzzer input.
 * Idea: Fill all guest registers with a random pattern. If this pattern pops up
 * later down the line, we know that for some reason the hypervisor cares about
 * it. With that information, we can modify the input to specify that the
 * corresponding register should be fuzzer provided.
 *
 * So a VMCALL looks like:
 * [opcode]
 * [bitfield to select which registers are fuzzer provided]
 * [the corresponding registers in natural order]
 */
bool op_vmcall() {
	static bool disable_with_virtio_core_nocov = virtio_core_enabled() &&
						     nocov_enabled();
	if (disable_with_virtio_core_nocov)
		return false;

	static uint8_t local_dma[4096]; // Used to make a copy of dma data
					// before rewriting regs
	size_t local_dma_len; // Used to make a copy of dma data before
			      // rewriting regs
	const uint64_t fuzzable_regs_bitmap = (0b11111111111111001110);
	if (ic_ingest32(&vmcall_enabled_regs, 0, -1, true))
		return false;

	static bx_gen_reg_t gen_reg_snap[BX_GENERAL_REGISTERS + 4];

	static uint8_t xmm_reg_snap[sizeof(BX_CPU(0)->vmm)];

	// If the op was skipped, we need to reset the register state
	memcpy(vmcall_gpregs, BX_CPU(0)->gen_reg, sizeof(BX_CPU(0)->gen_reg));
	memcpy(vmcall_xmmregs, BX_CPU(0)->vmm, sizeof(BX_CPU(0)->vmm));
	vmcall_enabled_regs &= fuzzable_regs_bitmap;
	for (int i = 0; i < 16; i++) {
		if ((vmcall_enabled_regs >> i) & 1) {
			if (i == BX_64BIT_REG_RSP)
				continue;
			uint64_t val;
			if (ic_ingest64(&val, 0, -1)) {
				return false;
			}
			vmcall_gpregs[i].rrx = val;
		}
	}
	for (int i = 0; i < BX_XMM_REGISTERS; i++) {
		if ((vmcall_enabled_regs >> (16 + i)) & 1) {
			uint8_t *value =
				ic_ingest_len(sizeof(BX_CPU(0)->vmm[i]));
			if (!value) {
				return false;
			}
			memcpy(&vmcall_xmmregs[i], value,
			       sizeof(BX_CPU(0)->vmm[i]));
		}
	}

	prepare_synthetic_vmexit(VMX_VMEXIT_VMCALL, 0, 3);

	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(0)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(0)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	cpu_physical_memory_write(phy, "\x0f\x01\xc1", 3);

	memcpy(BX_CPU(0)->gen_reg, vmcall_gpregs, sizeof(BX_CPU(0)->gen_reg));
	memcpy(BX_CPU(0)->vmm, vmcall_xmmregs, sizeof(BX_CPU(0)->vmm));

	uint8_t *dma_start = ic_get_cursor();

	if (BX_CPU(0)->fuzztrace || log_ops) {
		printf("!hypercall inject: [RAX: %lx, RBX: %lx, RCX: %lx, RDX: %lx, RSI: %lx]\n",
		       vmcall_gpregs[BX_64BIT_REG_RAX].rrx,
		       vmcall_gpregs[BX_64BIT_REG_RBX].rrx,
		       vmcall_gpregs[BX_64BIT_REG_RCX].rrx,
		       vmcall_gpregs[BX_64BIT_REG_RDX].rrx,
		       vmcall_gpregs[BX_64BIT_REG_RSI].rrx);
	}
	start_cpu();
	/* printf("Hypercall %lx Result: %lx\n",vmcall_gpregs[BX_64BIT_REG_RCX],
	 * BX_CPU(id)->get_reg64(BX_64BIT_REG_RAX)); */

	uint8_t *dma_end = ic_get_cursor();

	local_dma_len = dma_end - dma_start;
	if (local_dma_len > sizeof(local_dma)) {
		fuzz_emu_stop_unhealthy();
		return false;
	}
	memcpy(local_dma, dma_start, local_dma_len);

	ic_erase_backwards_until_token();
	vmcall_enabled_regs &= fuzzable_regs_bitmap;
	uint8_t opcode = OP_VMCALL;
	if (!ic_append(&opcode, sizeof(opcode)))
		fuzz_emu_stop_unhealthy();
	if (!ic_append(&vmcall_enabled_regs, sizeof(vmcall_enabled_regs)))
		fuzz_emu_stop_unhealthy();
	for (int i = 0; i < 16; i++) {
		if ((vmcall_enabled_regs >> i) & 1) {
			if (!ic_append(&vmcall_gpregs[i],
				       sizeof(vmcall_gpregs[i])))
				fuzz_emu_stop_unhealthy();
		}
	}
	for (int i = 0; i < BX_XMM_REGISTERS; i++) {
		if ((vmcall_enabled_regs >> (16 + i)) & 1) {
			if (!ic_append(&vmcall_xmmregs[i],
				       sizeof(BX_CPU(0)->vmm[i])))
				fuzz_emu_stop_unhealthy();
		}
	}

	if (!ic_append(local_dma, local_dma_len))
		fuzz_emu_stop_unhealthy();
	return true;
}

bool op_notify() {
	VirtioDev *vdev = get_vqueue_manager().get_fuzzed_dev();
	if (!vdev || vdev->queue_num < 1) {
		return false;
	}

	uint16_t queue_sel = 0;
	if (ic_ingest16(&queue_sel, 0, (uint16_t)(vdev->queue_num - 1)) < 0) {
		return false;
	}
	auto *model = SyntaxModel::CreateOrGet(*vdev);
	if (!model) {
		return false;
	}
	uint16_t head = model->submit_request(queue_sel);
	return head != UINT16_MAX;
}

bool op_trigger_aio() {
	if (!inject_out(0x80, 0x1, 0x0))
		return false;
	start_cpu();
	return true;
}

extern bool fuzz_unhealthy_input, fuzz_do_not_continue, fuzz_should_abort;

static void virtio_select_driver_features_for_input() {
	static bool log_enabled_inited;
	static bool log_enabled;
	if (!log_enabled_inited) {
		log_enabled_inited = true;
		log_enabled = virtio_feature_log_enabled() ||
			      virtio_ring_format_log_enabled();
	}

	VirtioDev *vdev = get_vqueue_manager().get_fuzzed_dev();
	if (!vdev) {
		return;
	}
	if (vdev->common_cfg.type != ConfigSpace::COMMON) {
		return;
	}

	uint64_t device_features = vdev->get_device_features();
	uint64_t mask = 0;
	if (ic_ingest64(&mask, 0, UINT64_MAX, true) < 0) {
		mask = 0;
	}

	uint64_t candidate = device_features & mask;
	/* Keep modern virtio (common cfg) semantics. */
	candidate |= (1ULL << VIRTIO_F_VERSION_1);

	if (log_enabled || log_ops || BX_CPU(0)->fuzztrace) {
		uint64_t packed_bit = (1ULL << VIRTIO_F_RING_PACKED);
		uint64_t indirect_bit = (1ULL << VIRTIO_RING_F_INDIRECT_DESC);
		int want_packed = (candidate & packed_bit) != 0;
		int want_indirect = (candidate & indirect_bit) != 0;
		printf("virtio feature select: dev=%s mask=%lx dev=%lx -> guest=%lx (packed=%d indirect=%d)\n",
		       vdev->name, mask, device_features, candidate,
		       want_packed, want_indirect);
	}

	vdev->renegotiate_features(candidate);
}

static void virtio_select_ring_format_for_input() {
	VirtioDev *vdev = get_vqueue_manager().get_fuzzed_dev();
	if (!vdev) {
		return;
	}
	if (vdev->common_cfg.type != ConfigSpace::COMMON) {
		return;
	}

	/*
	 * Deterministic per-input "randomness": derive from the current ops
	 * buffer without consuming bytes.
	 */
	uint8_t byte = 0;
	size_t ops_len = *input_len_get();
	if (ops_len) {
		byte = input_get()[0];
	}
	bool want_packed = (byte & 1) != 0;

	auto *active = vdev->active_syntax_model();
	if (syntax_model_sync_enabled() && active && !active->all_completed()) {
		return;
	}

	vdev->set_packed_queue(want_packed);

	auto *model = vdev->get_syntax_model();
	assert(model);
	assert(model->matched(vdev->current_features()));
}

void fuzz_run_input(const uint8_t *Data, size_t Size) {
	bool (*ops[])() = {
		[OP_READ] = op_read,
		[OP_WRITE] = op_write,
		[OP_IN] = op_in,
		[OP_OUT] = op_out,
		[OP_PCI_WRITE] = op_pci_write,
		[OP_MSR_WRITE] = op_msr_write,
		[OP_VMCALL] = op_vmcall,
		[OP_NOTIFY] = op_notify,
	};
	static const uint8_t virtio_core_ops[] = {
		OP_READ,      OP_WRITE,	    OP_IN,     OP_OUT,
		OP_PCI_WRITE, OP_MSR_WRITE, OP_VMCALL, OP_NOTIFY,
	};
	static const uint8_t virtio_core_ops_nocov[] = {
		OP_READ, OP_WRITE, OP_IN, OP_OUT, OP_PCI_WRITE, OP_NOTIFY,
	};
	static const uint8_t nr_ops = sizeof(ops) / sizeof((ops)[0]);
	static const uint8_t nr_virtio_core_ops =
		sizeof(virtio_core_ops) / sizeof((virtio_core_ops)[0]);
	static const uint8_t nr_virtio_core_ops_nocov =
		sizeof(virtio_core_ops_nocov) /
		sizeof((virtio_core_ops_nocov)[0]);
	uint8_t op;

	static bool fuzz_legacy;
	static bool fuzz_hypercalls;
	static bool virtio_core;
	static bool nocov_mode;
	static int inited;
	if (!inited) {
		inited = 1;
		fuzz_legacy = fuzz_legacy_enabled();
		fuzz_hypercalls = fuzz_hypercalls_enabled();
		log_ops = log_ops_enabled() || BX_CPU(0)->fuzztrace;
		virtio_core = virtio_core_enabled();
		nocov_mode = nocov_enabled();
	}

	if (virtio_core) {
		reset_input_output();
		input_deserialize(Data, Size, input_get(), input_len_get(),
				  request_buffer_get(), desc_pool_get());
	} else {
		ic_new_input(Data, Size);
	}
	get_vqueue_manager().reset_request_history();
	uint16_t start = 0;
	int nops = 0;
	uint8_t *input_start = ic_get_cursor();
	do {
		dma_start = ic_get_cursor() - input_start;
		dma_len = 0;
		if (fuzz_legacy) {
			if (ic_ingest8(&op, OP_READ, OP_OUT, true)) {
				ic_erase_backwards_until_token();
				ic_subtract(4);
				continue;
			}
		} else if (fuzz_hypercalls) {
			if (ic_ingest8(&op, OP_MSR_WRITE, OP_VMCALL, true)) {
				ic_erase_backwards_until_token();
				ic_subtract(4);
				continue;
			}
		} else if (virtio_core) {
			const uint8_t *virtio_ops =
				nocov_mode ? virtio_core_ops_nocov :
						   virtio_core_ops;
			uint8_t virtio_nr_ops =
				nocov_mode ? nr_virtio_core_ops_nocov :
						   nr_virtio_core_ops;
			uint8_t op_idx;

			if (ic_ingest8(&op_idx, 0, virtio_nr_ops - 1, true)) {
				ic_erase_backwards_until_token();
				ic_subtract(4);
				continue;
			}
			op = virtio_ops[op_idx];
		} else { /* Fuzz Everything */
			if (ic_ingest8(&op, 0, OP_VMCALL, true)) {
				ic_erase_backwards_until_token();
				ic_subtract(4);
				continue;
			}
		}
		if (!ops[op]()) {
			ic_erase_backwards_until_token();
			ic_subtract(4);
			continue;
		}
		if (fuzz_unhealthy_input || fuzz_do_not_continue)
			break;
		// if (new_op(op, start, ic_get_cursor() - input_start,
		// dma_start, 	   dma_len) >= 8) 	break;
	} while (ic_advance_until_token(SEPARATOR, 4));

	if (virtio_core && !fuzz_unhealthy_input) {
		VirtioDev *vdev = get_vqueue_manager().get_fuzzed_dev();
		if (vdev) {
			auto *model = vdev->get_syntax_model();
			if (!model)
				return;
			if (syntax_model_sync_enabled()) {
#if BX_SUPPORT_SMP
				if (bx_cpu_count > 1 &&
				    !model->all_completed()) {
					drain_begin(syntax_model_completed_pred,
						    model);
					inject_halt();
					start_cpu();
					DrainStats stats = drain_end();
					return;
				}
#endif
				size_t cnt = 0;
				while (!fuzz_unhealthy_input &&
				       !model->all_completed()) {
					cnt++;
					start_cpu();
				}
			}
		}
	}
}

void add_pio_region(uint16_t addr, uint16_t size) {
	pio_regions[addr] = size;
	printf("pio_regions %lx = %x + %x\n", pio_regions.size(), addr, size);
}
void add_mmio_region(uint64_t addr, uint64_t size) {
	mmio_regions[addr] = size;
	printf("mmio_regions %lx = %lx + %lx\n", mmio_regions.size(), addr,
	       size);
}
void add_mmio_range_alt(uint64_t addr, uint64_t end) {
	add_mmio_region(addr, end - addr);
}
void add_ram_region(uint64_t addr, uint64_t size) {
	ram_regions.push_back({ addr, size });
}
void init_regions(const char *path) {
	open_db(path);
	if (fuzz_enum_enabled()) {
		enum_pio_regions();
		enum_mmio_regions();
		exit(0);
	}
	if (manual_ranges_path()) {
		load_manual_ranges(const_cast<char *>(manual_ranges_path()),
				   const_cast<char *>(range_regex()),
				   pio_regions, mmio_regions);
		load_ram_regions_from_iomem(const_cast<char *>(iomem_path()));
	} else {
		load_regions(pio_regions, mmio_regions);
	}
}

uint64_t get_guest_ram_start() {
	if (ram_regions.size() == 0)
		return GUEST_MEM_START;
	auto last_region = ram_regions.rbegin();
	return last_region->first;
}

uint64_t get_guest_ram_size() {
	if (ram_regions.size() == 0)
		return GUEST_MEM_SIZE;
	auto last_region = ram_regions.rbegin();
	return last_region->second;
}

static unsigned bx_num_cpus() {
#if BX_SUPPORT_SMP
	return BX_SMP_PROCESSORS;
#else
	return 1;
#endif
}

unsigned bx_kernel_cpu() {
	static unsigned cached_cpu = 0;
	static bool cached_valid = false;

	auto cpu_usable_for_kernel = [](unsigned cpu) -> bool {
#if BX_SUPPORT_VMX
		if (BX_CPU(cpu)->in_vmx_guest)
			return false;
#endif
		return true;
	};

	const unsigned ncpu = bx_num_cpus();
	if (cached_valid && cached_cpu < ncpu &&
	    cpu_usable_for_kernel(cached_cpu)) {
		return cached_cpu;
	}

	for (unsigned cpu = 0; cpu < ncpu; cpu++) {
		if (!cpu_usable_for_kernel(cpu))
			continue;
		if (BX_CPU(cpu)->get_cpl() == 0) {
			cached_cpu = cpu;
			cached_valid = true;
			return cpu;
		}
	}

	for (unsigned cpu = 0; cpu < ncpu; cpu++) {
		if (!cpu_usable_for_kernel(cpu))
			continue;
		cached_cpu = cpu;
		cached_valid = true;
		return cpu;
	}

	cached_cpu = 0;
	cached_valid = true;
	return 0;
}

bx_phy_address bx_kernel_translate_linear(unsigned cpu, bx_address laddr,
					  int rw) {
	Bit32u lpf_mask = 0xfff;
	Bit32u pkey = 0;
	// Bochs encodes access/memtype bits in the low bits of the returned
	// value. Mask those out and apply the offset bits from the original
	// linear address.
	bx_phy_address xlated = BX_CPU(cpu)->translate_linear_long_mode(
		laddr, lpf_mask, pkey, 0, rw);
	return (xlated & ~((bx_phy_address)lpf_mask)) | (laddr & lpf_mask);
}

void bx_kernel_read(unsigned cpu, bx_address laddr, void *buf, size_t len) {
	// we should consider paging
	bx_address kpage = laddr & ~0xfff;
	bx_address offset = laddr & 0xfff;
	for (; kpage < laddr + len; kpage += 0x1000) {
		bx_phy_address paddr =
			bx_kernel_translate_linear(cpu, kpage, BX_READ);
		size_t to_read = std::min((size_t)(0x1000 - offset), len);
		cpu_physical_memory_read(paddr + offset, (char *)buf, to_read);
		buf = (char *)buf + to_read;
		len -= to_read;
		offset = 0;
	}
}

void bx_kernel_write(unsigned cpu, bx_address laddr, void *buf, size_t len) {
	// we should consider paging
	bx_address kpage = laddr & ~0xfff;
	bx_address offset = laddr & 0xfff;
	for (; kpage < laddr + len; kpage += 0x1000) {
		bx_phy_address paddr =
			bx_kernel_translate_linear(cpu, kpage, BX_WRITE);
		size_t to_write = std::min((size_t)(0x1000 - offset), len);
		cpu_physical_memory_write(paddr + offset, (const char *)buf,
					  to_write);
		buf = (uint8_t *)buf + to_write;
		len -= to_write;
		offset = 0;
	}
}
