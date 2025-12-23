#include "fuzz.h"
#include "bochs.h"
#include "config.h"
#include "conveyor.h"
#include "virtio.h"
#include "cov.h"
#include "vendor/libfuzzer-ng/FuzzerInternal.h"
#include "vendor/libfuzzer-ng/FuzzerTracePC.h"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <tsl/robin_map.h>

#include <ctime>

namespace fuzzer {
	extern TracePC TPC;
	extern Fuzzer* F;
};

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
std::vector<std::pair<uint64_t, uint64_t>> ram_regions;

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
static int ingest_vring(bx_address addr, size_t len, void* data) {
	static void* replay = getenv("REPLAY");
	auto gpa = lookup_gpa_by_hpa(addr);
	const VRing *vring = get_vqueue_manager().get_belonging_vring(gpa);
	int rc;
	bx_address off_in_elem = 0;
	if (vring) {
		if (vring->queue && vring->queue->vdev && !vring->queue->vdev->to_fuzz) {
			// device is not being fuzzed
			// just ignore
			return 0;
		}
		uint16_t vring_idx = 0;
		uint8_t vring_elem[16] = {0};
		switch (vring->filed_type(gpa)) {
		case VRing::FILED_TYPE::FLAGS:
			return 0;
		case VRing::FILED_TYPE::INDEX:
			rc = vring->ingest_idx(&vring_idx);
			if (rc == -1) {  
				// -1, ingest error
				// -2, queue locates at page 0
				// if (rc == -1) // ingest error
				/* here we should not call fuzz_emu_stop_unhealthy */
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
			BX_MEM(0)->writePhysicalPage(BX_CPU(id), addr, len, (void*)&vring_idx);
			memcpy(data, &vring_idx, len);
			return 0;
		case VRing::FILED_TYPE::VRING_ELEM:
			rc = vring->ingest_elem((void*)vring_elem, vring->element_index(gpa));
			off_in_elem = gpa - (vring->start() + vring->ring_offset() + vring->element_index(gpa) * vring->element_size());
			if (rc == -1) {
				/* here we should not call fuzz_emu_stop_unhealthy */
				// fuzz_emu_stop_unhealthy();
				return -1;
			} else if (rc == -2) {
				fuzz_emu_stop_polling();
				return -2;
			} else if (rc == 0) {
				vring->write_elem(vring->element_index(gpa), vring_elem);
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
			static char* no_double_fetch = getenv("NO_DOUBLE_FETCH");
			auto overlapped_size = get_vqueue_manager().overlapped_size(gpa, len);
			auto* queue = get_vqueue_manager().get_queue_by_id(desc_with_info->desc_info.queue_id);
			assert(overlapped_size <= len);
			
			size_t offset = queue->desc_chain_fsm.get_request_offset(gpa);
			bool is_out = desc_with_info->desc_info.is_out;
			bool possible_switch = (offset == 0 && is_out && desc_with_info->desc_info.desc_idx == 0);
			
			if (offset > 0x100) 
				return 0;

			/* ingest random data */
			bool overwrite = (replay == NULL);
			uint8_t* buf = dma_data_get()->ingest_data(len, possible_switch, overwrite);
			if (!buf)
				return -1;
			/* fetch overlapped data */
			if (no_double_fetch && overlapped_size) 
				BX_MEM(0)->readPhysicalPage(BX_CPU(id), addr, overlapped_size, buf);
			
			if (queue->vdev->is_scsi && is_out) {
				const uint8_t valid_lun[8] = {1, 1, 0, 0, 0, 0, 0, 0};
				if (queue->type == VQueue::QUEUE_NORMAL) {
					// lun should be [0, 8), if [offset, offset+8) covers lun, fix it
					if (offset < 8 && offset + len <= 8) {
						memcpy(buf, valid_lun + offset, len);
					} else if (offset < 8 && offset + len > 8) {
						memcpy(buf, valid_lun + offset, 8 - offset);
					} 
					for (int i = 0; i < len; i++) {
						printf("%.2x ", buf[i]);
					}
					printf("\n");
					fflush(stdout);
				} else if (queue->type == VQueue::QUEUE_CTRL) {
					// lun should be [8, 16) or [4, 12)
				}
			}
			
			/* adjust addr = addr + len - remaining_len to avoid duplicated region */
			BX_MEM(0)->writePhysicalPage(BX_CPU(id), addr, len, (void *)buf);
			memcpy(data, buf, len);
			get_vqueue_manager().add_seen_buffer(gpa, len);
			update_virtio_req_counter(desc_with_info->desc_info.queue_id,
									  desc_with_info->desc_info.desc_idx,
									  is_out);
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

void fuzz_dma_read_cb(bx_phy_address addr, unsigned len, void *data) {
	static char* bypass_virtio_core = getenv("VIRTIO_CORE");
	uint8_t *buf;
	int rc;
	bx_phy_address origin_addr = addr;
	bx_phy_address origin_len = len;

	if (!fuzzing)
		return;

	/* we should not ignore polling */
	if (!bypass_virtio_core && seen_dma[addr + len - 1] == len) {
		printf("DMA at %lx len %x already handled\n", addr, len);
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
		int rc = ingest_vring(addr, len, data);
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
		BX_MEM(0)->writePhysicalPage(BX_CPU(id), addr, l, (void *)buf);
		memcpy(data, buf, l);
	} else if (sectionlen > 0x1000) {
	} else {
		uint8_t buf[100];
		size_t source = addr + len + 1 - sectionlen;
		if ((source + len) >> 12 != (source >> 12))
			source -= len;
		BX_MEM(0)->readPhysicalPage(BX_CPU(id), source, len, buf);

		// if (BX_CPU(id)->fuzztrace || log_ops) {
		// 	printf("!(medium size)dma inject: [HPA: %lx, GPA: %lx] len: %lx data: ",
		// 	       addr, lookup_gpa_by_hpa(addr), len);
		// 	for (int i = 0; i < len; i++)
		// 		printf("%02x ", buf[i]);
		// 	printf("\n");
		// }
		BX_MEM(0)->writePhysicalPage(BX_CPU(id), addr, len, buf);
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

bool inject_halt() {
	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, VMX_VMEXIT_HLT);
	BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, 0);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 1);
	cpu_physical_memory_write(phy, "\xf4", 1);
	return true;
}

// INJECTORS
bool inject_write(bx_address addr, int size, uint64_t val) {
	enum Sizes { Byte, Word, Long, Quad, end_sizes };
	BX_CPU(id)->VMwrite64(VMCS_64BIT_GUEST_PHYSICAL_ADDR, addr);
	uint32_t exit_reason = vmcs_translate_guest_physical_ept(addr, NULL, NULL);
	/* printf("Exit reason: %lx\n", exit_reason); */
	if (!exit_reason)
		return false;
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, exit_reason);

	if (exit_reason == VMX_VMEXIT_EPT_VIOLATION)
		BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, 2);
	else
		BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, 0);

	BX_CPU(id)->set_reg64(BX_64BIT_REG_RDX, addr);
	BX_CPU(id)->set_reg64(BX_64BIT_REG_RAX, val);

	if (BX_CPU(id)->fuzztrace || log_ops) {
		printf("!write inject: [GPA: %lx] len: %d data: ", addr, 1<<size);
		for (int i = 0; i < (1 << size); i++)
			printf("%02x", ((uint8_t *)&val)[i]);
		printf(" (reason: %d)\n", exit_reason);
	}
	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	switch (size) {
	case Byte:
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		cpu_physical_memory_write(phy, "\x88\x02", 2);
		break;
	case Word:
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		cpu_physical_memory_write(phy, "\x66\x89\x02", 3);
		break;
	case Long:
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		cpu_physical_memory_write(phy, "\x89\x02", 2);
		break;
	case Quad:
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		cpu_physical_memory_write(phy, "\x48\x89\x02", 3);
		break;
	}
	return true;
}

bool inject_read(bx_address addr, int size) {
	enum Sizes { Byte, Word, Long, Quad, end_sizes };

	uint32_t exit_reason =
		vmcs_translate_guest_physical_ept(addr, NULL, NULL);
	if (!exit_reason)
		return false;
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, exit_reason);

	BX_CPU(id)->VMwrite32(VMCS_64BIT_GUEST_PHYSICAL_ADDR, addr);

	if (exit_reason == VMX_VMEXIT_EPT_VIOLATION)
		BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, 1);
	else
		BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, 0);

	BX_CPU(id)->set_reg64(BX_64BIT_REG_RCX, addr);

	if (BX_CPU(id)->fuzztrace || log_ops) {
		printf("!read inject: [GPA: %lx] len: %d\n", addr, 1<<size);
	}
	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	switch (size) {
	case Byte:
		cpu_physical_memory_write(phy,
					  "\x67\x8a\x01", // mov al,BYTE PTR
							  // [ecx]
					  3);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		break;
	case Word:
		cpu_physical_memory_write(phy,
					  "\x67\x66\x8b\x01", // mov ax,WORD PTR
							      // [ecx]
					  4);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 4);
		break;
	case Long:
		cpu_physical_memory_write(phy,
					  "\x67\x8b\x01", // mov eax,DWORD PTR
							  // [ecx]
					  3);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		break;
	case Quad:
		cpu_physical_memory_write(phy,
					  "\x48\x8b\x01", // mov rax,QWORD PTR
							  // [rcx]
					  3);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		break;
	}
	return true;
}

bool inject_in(uint16_t addr, uint16_t size) {
	enum Sizes { Byte, Word, Long, end_sizes };
	uint64_t field_64 = 0;
	if (BX_CPU(id)->fuzztrace || log_ops) {
		printf("!in inject: [GPA: %x] len: %d\n", addr, size);
	}
	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
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
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 1);
		break;
	case Word:
		cpu_physical_memory_write(phy, "\x66\xed", 2);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		field_64 |= 1; // access size
		break;
	case Long:
		cpu_physical_memory_write(phy, "\xed", 1);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 1);
		field_64 |= 3; // access size
		break;
	}
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON,
			      VMX_VMEXIT_IO_INSTRUCTION);

	field_64 |= (addr << 16); // port number
	field_64 |= (1 << 3); // //IN
	BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, field_64);
	BX_CPU(id)->set_reg64(BX_64BIT_REG_RDX, addr);
	return true;
}

bool inject_out(uint16_t addr, uint16_t size, uint32_t value) {
	enum Sizes { Byte, Word, Long, end_sizes };
	uint64_t field_64 = 0;
	if (BX_CPU(id)->fuzztrace || log_ops) {
		printf("!out inject: [GPA: %x] len: %d data: ", addr, size);
		for (int i = 0; i < size; i++)
			printf("%02x", ((uint8_t *)&value)[i]);
		printf("\n");
	}
	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	switch (size) {
	case Byte:
		cpu_physical_memory_write(phy, "\xee", 1);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 1);
		break;
	case Word:
		cpu_physical_memory_write(phy, "\x66\xef", 2);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		field_64 |= 1; // access size
		break;
	case Long:
		cpu_physical_memory_write(phy, "\xef", 1);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 1);
		field_64 |= 3; // access size
		break;
	}

	BX_CPU(id)->set_reg64(BX_64BIT_REG_RDX, addr);

	// write value for out
	BX_CPU(id)->set_reg64(BX_64BIT_REG_RAX, value);

	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON,
			      VMX_VMEXIT_IO_INSTRUCTION);

	field_64 |= (addr << 16);
	BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, field_64);
	return true;
}

uint32_t inject_pci_read(uint8_t device, uint8_t function, uint8_t offset) {
	uint32_t value;
	inject_out(0xcf8, 2,
		   (1U << 31) | (device << 11) | (function << 8) | offset);
	start_cpu();
	inject_in(0xcfc, 2);
	start_cpu();
	uint32_t val = BX_CPU(id)->gen_reg[BX_64BIT_REG_RAX].rrx;
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
	BX_CPU(id)->set_reg64(BX_64BIT_REG_RAX, value & 0xFFFFFFFF);
	BX_CPU(id)->set_reg64(BX_64BIT_REG_RDX, value >> 32);

	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	cpu_physical_memory_write(phy, "\x0f\x30", 2);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, VMX_VMEXIT_WRMSR);

	BX_CPU(id)->set_reg64(BX_64BIT_REG_RCX, msr);
	start_cpu();
	return true;
}

uint64_t inject_rdmsr(bx_address msr) {
	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	cpu_physical_memory_write(phy, "\x0f\x32", 2);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, VMX_VMEXIT_RDMSR);

	BX_CPU(id)->set_reg64(BX_64BIT_REG_RCX, msr);
	start_cpu();
	return (BX_CPU(id)->get_reg64(BX_64BIT_REG_RDX) << 32) |
	       (BX_CPU(id)->get_reg64(BX_64BIT_REG_RAX) & 0xFFFFFFFF);
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
	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
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

	if (BX_CPU(id)->fuzztrace || log_ops) {
		printf("!wrmsr inject: %x = %lx\n", msr, value);
	}
	return inject_wrmsr(msr, value);
}

static bx_gen_reg_t vmcall_gpregs[16 + 4];
static __typeof__(BX_CPU(id)->vmm) vmcall_xmmregs BX_CPP_AlignN(64);
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
	static uint8_t local_dma[4096]; // Used to make a copy of dma data
					// before rewriting regs
	size_t local_dma_len; // Used to make a copy of dma data before
			      // rewriting regs
	const uint64_t fuzzable_regs_bitmap = (0b11111111111111001110);
	if (ic_ingest32(&vmcall_enabled_regs, 0, -1, true))
		return false;

	static bx_gen_reg_t gen_reg_snap[BX_GENERAL_REGISTERS + 4];

	static uint8_t xmm_reg_snap[sizeof(BX_CPU(id)->vmm)];

	// If the op was skipped, we need to reset the register state
	memcpy(vmcall_gpregs, BX_CPU(id)->gen_reg, sizeof(BX_CPU(id)->gen_reg));
	memcpy(vmcall_xmmregs, BX_CPU(id)->vmm, sizeof(BX_CPU(id)->vmm));
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
				ic_ingest_len(sizeof(BX_CPU(id)->vmm[i]));
			if (!value) {
				return false;
			}
			memcpy(&vmcall_xmmregs[i], value,
			       sizeof(BX_CPU(id)->vmm[i]));
		}
	}

	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, VMX_VMEXIT_VMCALL);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);

	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	cpu_physical_memory_write(phy, "\x0f\x01\xc1", 3);

	memcpy(BX_CPU(id)->gen_reg, vmcall_gpregs, sizeof(BX_CPU(id)->gen_reg));
	memcpy(BX_CPU(id)->vmm, vmcall_xmmregs, sizeof(BX_CPU(id)->vmm));

	uint8_t *dma_start = ic_get_cursor();

	if (BX_CPU(id)->fuzztrace || log_ops) {
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
				       sizeof(BX_CPU(id)->vmm[i])))
                fuzz_emu_stop_unhealthy();
		}
	}

	if (!ic_append(local_dma, local_dma_len))
        fuzz_emu_stop_unhealthy();
	return true;
}

bool op_notify() {
	/* inject an mmio write to notify cfg */
	/*
	  1. select a random virtio device
	  2. select a random queue 
	  3. set queue_sel to that queue
	  4. set queue_enable to that queue
	  5. inject write to notify start + multiplier * index
	*/
	uint16_t vdev_idx;
	uint16_t vqueue_idx;
	if (get_vqueue_manager().get_num_virtio_dev() < 1) {
		return false;
	}
	if (ic_ingest16(&vdev_idx, 0, get_vqueue_manager().get_num_virtio_dev()-1) < 0) {
		return false;
	}
	auto* vdev = get_vqueue_manager().get_virtio_dev(vdev_idx);
	if (vdev->queue_num < 1) {
		return false;
	}
	if (ic_ingest16(&vqueue_idx, 0, vdev->queue_num-1) < 0) {
		return false;
	}
	if (!vdev->common_cfg.set_queue_enable(vqueue_idx)) {
		return false;
	}
	bx_address addr = vdev->notify_cfg.address + vdev->multiplier * vqueue_idx; // make it mis-aligned
	assert(addr < vdev->notify_cfg.address + vdev->notify_cfg.size);
	if (!inject_write(addr, 2, vqueue_idx)) { //should be set according multiplier
		printf("failed to inject notify at %lx (base %lx)!\n", addr, vdev->notify_cfg.address);
		return false;
	}
	start_cpu();
	return true;
}

bool op_trigger_aio() {
	if (!inject_out(0x80, 0x1, 0x0))
		return false;
	start_cpu();
	return true;
}

extern bool fuzz_unhealthy_input, fuzz_do_not_continue, fuzz_should_abort;
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
	static const int nr_ops = sizeof(ops) / sizeof((ops)[0]);
	uint8_t op;

	static void *fuzz_legacy, *fuzz_hypercalls;
	static void *virtio_core;
	static int inited;
	if (!inited) {
		inited = 1;
		fuzz_legacy = getenv("FUZZ_LEGACY");
		fuzz_hypercalls = getenv("FUZZ_HYPERCALLS");
		log_ops = getenv("LOG_OPS") || BX_CPU(id)->fuzztrace;
		virtio_core = getenv("VIRTIO_CORE");
	}

	if (virtio_core) {
		reset_input_output();
		input_deserialize(Data, Size, input_get(), input_len_get(), dma_data_get(), desc_pool_get());
	} else {
		ic_new_input(Data, Size);
	}
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
			if (ic_ingest8(&op, 0, OP_NOTIFY, true)) {
				ic_erase_backwards_until_token();
				ic_subtract(4);
				continue;
			}
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
		// if (new_op(op, start, ic_get_cursor() - input_start, dma_start,
		// 	   dma_len) >= 8)
		// 	break;
	} while (ic_advance_until_token(SEPARATOR, 4));
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
	ram_regions.push_back({addr, size});
}
void init_regions(const char *path) {
	open_db(path);
	if (getenv("FUZZ_ENUM")) {
		enum_pio_regions();
		enum_mmio_regions();
        exit(0);
	}
	if (getenv("MANUAL_RANGES")) {
		load_manual_ranges(getenv("MANUAL_RANGES"),
				   getenv("RANGE_REGEX"), pio_regions,
				   mmio_regions);
		load_ram_regions_from_iomem(getenv("IOMEM"));
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