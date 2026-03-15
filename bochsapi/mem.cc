#include <sys/mman.h>
#include "config.h"
#include <cstdint>

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <vector>
#include <zstd.h>

#include <tsl/robin_set.h>
#include <tsl/robin_map.h>
#include "../fuzz.h"
#include "../option.h"
#include <openssl/md5.h>

BX_MEM_C::BX_MEM_C() {
}
BX_MEM_C::~BX_MEM_C() {
}

size_t maxaddr = 0;

static uint8_t watch_level = 0;
static uint8_t *overlays[3];
uint8_t *is_l2_page_bitmap; /* Page is in L2 */
uint8_t *is_l2_pagetable_bitmap; /* Page is in L2 */
size_t guest_mem_size;

int shfd; // for overlay[0]
char md5sum_chr[33]; // for overlay[0]
int shm_open(const char *name, int oflag, mode_t mode);

uint8_t *cow_bitmap;
uint8_t *overlay_map; // 0: from shadowmem 1: from workershadowmem

tsl::robin_set<bx_phy_address> dirtyset;
tsl::robin_set<bx_phy_address> guest_page_table;

typedef std::vector<uint64_t> persist_range_vec;
tsl::robin_map<bx_phy_address, persist_range_vec> persist_ranges;
tsl::robin_map<bx_phy_address, bx_phy_address> hpa_to_gpa;

std::vector<std::tuple<bx_address, uint8_t, uint8_t> >
	fuzzed_guest_pages; // <
			    // HPA,
			    // pagetable_level,
			    // original_val
			    // >

static int memory_commit_level;

size_t ndirty = 0;
static const size_t kDirtyPageLimit = nocov_enabled() ? 10000 * nocov_scale() :
							      10000;

static bx_address prioraccess;
void fuzz_hook_memory_access(unsigned cpu, bx_address phy, unsigned len,
			     unsigned memtype, unsigned rw, void *data) {
	static bool kernel_dma = kernel_dma_enabled();
	bx_address aligned = phy & (~0xFFFLL);

	/* printf("Memory access to %lx\n", phy); */
	// Sometimes we might run instructions during initialization and we
	// want them to be part of the snapshot.
	if (watch_level <= 1 || phy >= maxaddr)
		return;

	if (aligned == prioraccess)
		return;

	if (rw == BX_WRITE || rw == BX_RW) {
		prioraccess = aligned;
		// This stores the addr in the dirtyset (reset for each input)
		// and makes a copy of the corresponding page in
		// shadowset/shadowmem (persistent). Otherwise I run out of RAM
		// on my machine :') When we do the actual fuzzing runs on
		// beefier hardware, we should just make a complete shadow-copy
		// on startup.
		if (dirtyset.emplace(aligned).second) {
			// if there is an infinite loop, we need to stop since
			// it will cause a libfuzzer timeout and stop fuzzing.
			if (ndirty++ > kDirtyPageLimit) {
				printf("Too many dirty pages. Early stop\n");
				fuzz_emu_stop_unhealthy();
			}
		}
	}

	// used to identify DMA accesses in the guest
	// contains a mapping for each host physical page, for whether it
	// corresponds to a guest page if an access uses such an address, it is
	// likely a DMA
	if (rw == BX_READ && is_l2_page_bitmap[phy >> 12] &&
	    !guest_page_table.contains(phy >> 12)) {
		if (BX_CPU(cpu)->fuzztrace) {
			/* printf(".dma inject: %lx +%lx ",phy, len); */
		}
		static bool hv = hyperv_enabled();
		if (BX_CPU(cpu)->user_pl || hv || kernel_dma) {
			Task *current_task = task_manager.get_current_task(cpu);
			if (!current_task)
				return;
			if (current_task->CPU_KVM)
				return;
			if (!current_task->is_hypervisor_task()) {
				current_task->hypervisor_task = 1;
				printf("DMA read by task %d (%s) at %lx\n",
				       current_task->pid, current_task->comm,
				       phy);
			}
			fuzz_dma_read_cb(cpu, phy, len, data);
			// if (log_ops) {
			//     uint8_t buf[len];
			//     BX_MEM_C::readPhysicalPage(BX_CPU(cpu), phy, len,
			//     buf); bx_address gpa = lookup_gpa_by_hpa(phy);
			//     const VRing* vring =
			//     get_vqueue_manager().get_belonging_vring(gpa); if
			//     (vring && vring->queue->vdev->to_fuzz)
			//         printf("!dma inject: [HPA: %lx, GPA: %lx,
			//         vring: %s, start: %lx, end: %lx, type: %d]
			//         len: %x data: ",
			//                 phy, gpa, vring->type_str(),
			//                 vring->start(), vring->end(),
			//                 vring->filed_type(gpa), len);
			//     else
			//         printf("!dma inject: [HPA: %lx, GPA: %lx]
			//         len: %x data: ",
			//                 phy, gpa, len);
			//     for (int i = 0; i < len; i++)
			//         printf("%02x", buf[i]);
			//     printf("\n");
			// }
		}

		prioraccess = -1;
	}
}

void fuzz_clear_dirty() {
	ndirty = 0;
	dirtyset.clear();
}

void fuzz_watch_memory_inc() {
	watch_level++;
}

uint64_t lookup_gpa_by_hpa(uint64_t hpa) {
	uint64_t page = hpa;
	uint64_t offset;
	int i = 0;
	while (hpa_to_gpa.find(page) == hpa_to_gpa.end() && page) {
		i++;
		page = ((page >> i) << i);
	}
	if (!page)
		printf("Error looking up GPA for HPA: %lx\n", hpa);
	return hpa_to_gpa[page] | (hpa & (~(((uint64_t)(-1) >> i) << i)));
}
/**
 * During fuzzing, there is a chance that new guest addresses get paged in.
 * The corresponding HPAs have not been marked as guest pages, so we mark them.
 * However, the EPT is reset across fuzz iterations, so have to unmark
 * the pages that have been marked during the current fuzz iteration
 */
void fuzz_mark_l2_guest_page(uint64_t paddr, uint64_t len) {
	uint64_t pg_entry;
	cpu_physical_memory_read(paddr, &pg_entry, sizeof(pg_entry));
	bx_phy_address new_addr = pg_entry & 0x3fffffffff000ULL;
	uint8_t new_pgtable_lvl = is_l2_pagetable_bitmap[paddr >> 12] - 1;
	uint8_t pg_present = pg_entry & PG_PRESENT_MASK;

	if (!pg_present || new_addr >= maxaddr)
		return;

	// store all updates made for the current fuzzing iteration
	fuzzed_guest_pages.push_back(
		std::make_tuple(new_addr, new_pgtable_lvl,
				is_l2_pagetable_bitmap[new_addr >> 12]));
	// printf("!fuzz_mark_l2_guest_page Mark 0x%lx lvl %x as tmp guest
	// page\n", new_addr, new_pgtable_lvl);
	if (new_pgtable_lvl) {
		mark_l2_guest_pagetable(new_addr, len, new_pgtable_lvl - 1);
	} else {
		mark_l2_guest_page(new_addr, len, 0);
	}
}

void fuzz_reset_watched_pages() {
	// printf("[fuzz_reset_watched_pages] reset 0x%lx watched pages\n",
	// fuzzed_guest_pages.size());;
	for (auto &page : fuzzed_guest_pages) {
		bx_address addr = std::get<0>(page);
		uint8_t is_pgtable = std::get<1>(page);
		uint8_t saved_val = std::get<2>(page);
		if (is_pgtable)
			is_l2_pagetable_bitmap[addr >> 12] = saved_val;
		else // normal guest page
			is_l2_page_bitmap[addr >> 12] = saved_val;
	}
	fuzzed_guest_pages.clear();
}

void add_persistent_memory_range(bx_phy_address start, bx_phy_address len) {
	/* printf("Add persistent memory range: %lx %lx\n", start, len); */
	bx_phy_address page = (start >> 12) << 12;
	bx_phy_address startend;
	assert(((start + len - 1) >> 12) == (page >> 12));

	startend = start - page;
	startend |= (start + len - page) << 12;
	if (persist_ranges.find(page) == persist_ranges.end()) {
		persist_ranges[page] = persist_range_vec();
	}
	// merge if possible
	for (auto se : persist_ranges[page]) {
		bx_phy_address s = se & 0xFFF;
		bx_phy_address e = se >> 12;
		if (!((startend & 0xFFF) >= e || (startend >> 12) <= s)) {
			// merge
			bx_phy_address new_start =
				std::min(startend & 0xFFF, s);
			bx_phy_address new_end = std::max(startend >> 12, e);
			startend = new_start | (new_end << 12);
			persist_ranges[page].erase(
				std::remove(persist_ranges[page].begin(),
					    persist_ranges[page].end(), se),
				persist_ranges[page].end());
		}
	}
	// insert sort
	for (auto it = persist_ranges[page].begin();
	     it != persist_ranges[page].end(); ++it) {
		bx_phy_address s = (*it) & 0xFFF;
		if ((startend & 0xFFF) < s) {
			persist_ranges[page].insert(it, startend);
			return;
		}
	}
	persist_ranges[page].push_back(startend);

	// sanity-check for persistent_ranges[page], no overlap and keep in
	// order
	bx_phy_address last_end = 0;
	for (auto se : persist_ranges[page]) {
		bx_phy_address s = se & 0xFFF;
		bx_phy_address e = se >> 12;
		assert(s >= last_end && e > s);
		last_end = e;
	}
}

void add_persistent_kernel_memory_range(bx_address start, size_t len) {
	/* start, len is continuous in kernel space but not in physical address
	 * space */
	Bit32u lpf_mask = 0xfff; // 4K pages
	Bit32u pkey = 0;
	bx_phy_address region_start, region_end;

	bx_address page_start = (start >> 12) << 12;
	bx_address page_end = ((start + len - 1) >> 12) << 12;
	if (page_start == page_end) {
		region_start = BX_CPU(bx_kernel_cpu())
				       ->translate_linear_long_mode(
					       start, lpf_mask, pkey, 0, BX_RW);
		region_start = (region_start & ~((Bit64u)lpf_mask)) |
			       (start & lpf_mask);
		region_end = region_start + len;
		add_persistent_memory_range(region_start, len);
		return;
	}
	for (bx_address page = page_start; page <= page_end; page += 0x1000) {
		if (start > page) {
			region_start = BX_CPU(bx_kernel_cpu())
					       ->translate_linear_long_mode(
						       start, lpf_mask, pkey, 0,
						       BX_RW);
			region_start = (region_start & ~((Bit64u)lpf_mask)) |
				       (start & lpf_mask);
			region_end = (page + 0x1000);
			assert((region_start & lpf_mask) != 0);
			assert((region_end & lpf_mask) == 0);
			add_persistent_memory_range(region_start,
						    region_end - start);
			continue;
		}
		if (page + 0x1000 > start + len) {
			region_start =
				BX_CPU(bx_kernel_cpu())
					->translate_linear_long_mode(
						page, lpf_mask, pkey, 0, BX_RW);
			region_start = (region_start & ~((Bit64u)lpf_mask));
			region_end = region_start + (start + len - page);
			assert((region_start & lpf_mask) == 0);
			assert((region_end & lpf_mask) != 0);
			add_persistent_memory_range(region_start,
						    region_end - region_start);
			continue;
		}
		region_start = BX_CPU(bx_kernel_cpu())
				       ->translate_linear_long_mode(
					       page, lpf_mask, pkey, 0, BX_RW);
		region_start = (region_start & ~((Bit64u)lpf_mask));
		region_end = region_start + 0x1000;
		assert((region_start & lpf_mask) == 0);
		assert((region_end & lpf_mask) == 0);
		add_persistent_memory_range(region_start,
					    region_end - region_start);
	}
}

static void notify_write(uint64_t addr) {
	size_t page = addr >> 12;
	size_t aligned_addr = page << 12;
	if (cow_bitmap[page] != watch_level) {
		cow_bitmap[page] = watch_level;
		memcpy(overlays[cow_bitmap[page]] + aligned_addr,
		       overlays[overlay_map[page]] + aligned_addr, 0x1000);
		if (watch_level < 2) {
			overlay_map[page] = watch_level;
		}
	}
	/* printf("Page %lx now lives at %lx and is backed by %lx\n", page,
	 * cow_bitmap[page], overlay_map[page]); */
}

uint8_t *addr_conv(uint64_t addr) {
	/* printf("ADDR_CONV: %lx -> %lx [%d]\n",
	 * addr,overlays[cow_bitmap[addr>>12]]+addr, cow_bitmap[addr>>12]); */
	return overlays[cow_bitmap[addr >> 12]] + addr;
}
uint8_t *backing_addr(uint64_t addr) {
	return overlays[overlay_map[addr >> 12]] + addr;
}

void fuzz_reset_memory() {
	if (watch_level <= 1)
		return;
	prioraccess = 0;
	for (const auto &page : dirtyset) {
		size_t page_number = page >> 12;
		if (persist_ranges.find(page) != persist_ranges.end()) {
			bx_phy_address last_end = 0;
			for (auto startend : persist_ranges[page]) {
				bx_phy_address s = startend & 0xFFF;
				bx_phy_address e = startend >> 12;
				memcpy(addr_conv(page + last_end),
				       backing_addr(page + last_end),
				       s - last_end);
				last_end = e;
			}
			memcpy(addr_conv(page + last_end),
			       backing_addr(page + last_end),
			       0x1000 - last_end);
		} else {
			memcpy(addr_conv(page), backing_addr(page), 0x1000);
		}
	}
	fuzz_clear_dirty();
	fuzz_reset_watched_pages();
}

void BX_MEM_C::writePhysicalPage(BX_CPU_C *cpu, bx_phy_address addr,
				 unsigned len, void *data, bool hook_access) {
	notify_write(addr);
	if (hook_access)
		fuzz_hook_memory_access(cpu ? cpu->which_cpu() : 0, addr, len,
					0, BX_WRITE, NULL);

	memcpy(addr_conv(addr), data, len);

	if (is_l2_pagetable_bitmap[addr >> 12] && watch_level > 1) {
		fuzz_mark_l2_guest_page(addr, 0x1000);
	}

	return;
}

void BX_MEM_C::readPhysicalPage(BX_CPU_C *cpu, bx_phy_address addr,
				unsigned len, void *data) {
	memcpy(data, addr_conv(addr), len);
	return;
}

void mark_page_not_guest(bx_phy_address addr, int level) {
	printf("Mark page not present: %lx\n", addr);
	is_l2_page_bitmap[addr >> 12] = 0;
	guest_page_table.insert(addr >> 12);
}

bool frame_is_guest(bx_phy_address addr) {
	return is_l2_page_bitmap[addr >> 12];
}

Bit8u *BX_MEM_C::getHostMemAddr(BX_CPU_C *cpu, bx_phy_address addr,
				unsigned rw) {
	if (rw != BX_READ)
		notify_write(addr);
	return addr_conv(addr);
}

bool BX_MEM_C::dbg_fetch_mem(BX_CPU_C *cpu, bx_phy_address addr, unsigned len,
			     Bit8u *buf) {
	readPhysicalPage(cpu, addr, len, buf);
	return true;
}

#if (BX_DEBUGGER || BX_GDBSTUB)
bool BX_MEM_C::dbg_set_mem(BX_CPU_C *cpu, bx_phy_address addr, unsigned len,
			   Bit8u *buf) {
	notify_write(addr);
	memcpy(addr_conv(addr), buf, len);
	return true;
}
#endif

#if defined(__LP64__)
#define ElfW(type) Elf64_##type
#else
#define ElfW(type) Elf32_##type
#endif

namespace
{

const uint8_t kElfMagic[] = { 0x7f, 'E', 'L', 'F' };
const uint8_t kZstdMagic[] = { 0x28, 0xb5, 0x2f, 0xfd };
const size_t kSnapshotCopyChunk = 16 * 1024 * 1024;

struct SnapshotProgress {
	const char *stage;
	size_t total;
	int last_percent;
	bool active;
	bool tty;
};

SnapshotProgress snapshot_progress = { NULL, 0, -1, false, false };

void snapshot_progress_break_line() {
	if (!snapshot_progress.active)
		return;
	if (snapshot_progress.tty)
		fputc('\n', stderr);
	snapshot_progress.active = false;
}

void snapshot_progress_update(size_t done) {
	char bar[41];
	int percent;
	int filled;

	if (!snapshot_progress.active)
		return;
	if (done > snapshot_progress.total)
		done = snapshot_progress.total;

	percent = (int)((done * 100) / snapshot_progress.total);
	if (percent == snapshot_progress.last_percent &&
	    done != snapshot_progress.total)
		return;

	if (!snapshot_progress.tty) {
		if (done == snapshot_progress.total) {
			fprintf(stderr, ".%s done\n", snapshot_progress.stage);
			snapshot_progress.active = false;
		}
		snapshot_progress.last_percent = percent;
		return;
	}

	filled = (percent * 40) / 100;
	for (int i = 0; i < 40; i++)
		bar[i] = i < filled ? '#' : '-';
	bar[40] = '\0';

	fprintf(stderr, "\r.%s [%s] %3d%%", snapshot_progress.stage, bar,
		percent);
	fflush(stderr);
	snapshot_progress.last_percent = percent;
}

void snapshot_progress_start(const char *stage, size_t total) {
	snapshot_progress_break_line();
	snapshot_progress.stage = stage;
	snapshot_progress.total = total ? total : 1;
	snapshot_progress.last_percent = -1;
	snapshot_progress.active = true;
	snapshot_progress.tty = isatty(STDERR_FILENO);

	if (!snapshot_progress.tty)
		fprintf(stderr, ".%s...\n", stage);
	snapshot_progress_update(0);
}

void snapshot_progress_finish() {
	if (!snapshot_progress.active)
		return;
	snapshot_progress_update(snapshot_progress.total);
	if (snapshot_progress.tty)
		snapshot_progress.active = false;
}

[[noreturn]] void snapshot_load_fail(const char *filename,
				     const char *message) {
	snapshot_progress_break_line();
	fprintf(stderr, "snapshot load failed for %s: %s\n", filename, message);
	exit(1);
}

[[noreturn]] void snapshot_load_perror(const char *filename,
				       const char *message) {
	snapshot_progress_break_line();
	fprintf(stderr, "snapshot load failed for %s: %s: %s\n", filename,
		message, strerror(errno));
	exit(1);
}

bool has_magic(const uint8_t *data, size_t size, const uint8_t *magic,
	       size_t magic_size) {
	return size >= magic_size && memcmp(data, magic, magic_size) == 0;
}

int open_tmp_shm_fd(const char *filename) {
	char shm_name[128];

	for (unsigned int attempt = 0; attempt < 1024; attempt++) {
		snprintf(shm_name, sizeof(shm_name), "/hyperpill-mem-%d-%u",
			 getpid(), attempt);
		int fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL,
				  S_IRUSR | S_IWUSR);
		if (fd >= 0) {
			if (shm_unlink(shm_name) == -1) {
				close(fd);
				snapshot_load_perror(
					filename, "shm_unlink temp snapshot");
			}
			return fd;
		}
		if (errno != EEXIST)
			snapshot_load_perror(filename,
					     "shm_open temp snapshot");
	}

	snapshot_load_fail(filename, "failed to allocate temp snapshot shm");
}

size_t write_all(int fd, const uint8_t *buf, size_t len, const char *filename,
		 const char *message) {
	size_t written = 0;

	while (written < len) {
		ssize_t ret = write(fd, buf + written, len - written);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			snapshot_load_perror(filename, message);
		}
		if (ret == 0)
			snapshot_load_fail(filename, message);
		written += ret;
	}

	return written;
}

void decompress_zstd_snapshot_to_fd(const uint8_t *compressed,
				    size_t compressed_size,
				    const char *filename,
				    unsigned char *md5sum_hex, int fd,
				    size_t *decompressed_size) {
	std::vector<uint8_t> out_chunk;
	ZSTD_DCtx *dctx;
	ZSTD_inBuffer in_buf;
	MD5_CTX md5_ctx;
	size_t out_chunk_size;
	size_t remaining = 1;
	size_t total_size = 0;
	bool hash_snapshot = md5sum_hex != NULL;

	dctx = ZSTD_createDCtx();
	if (!dctx) {
		snapshot_load_fail(filename, "failed to create zstd context");
	}
	if (hash_snapshot)
		MD5_Init(&md5_ctx);

	out_chunk_size = ZSTD_DStreamOutSize();
	out_chunk.resize(out_chunk_size);
	in_buf = { compressed, compressed_size, 0 };
	snapshot_progress_start("decompressing memory snapshot",
				compressed_size);

	while (in_buf.pos < in_buf.size || remaining != 0) {
		ZSTD_outBuffer out_buf = { out_chunk.data(), out_chunk_size,
					   0 };

		remaining = ZSTD_decompressStream(dctx, &out_buf, &in_buf);
		if (ZSTD_isError(remaining)) {
			const char *err = ZSTD_getErrorName(remaining);
			ZSTD_freeDCtx(dctx);
			fprintf(stderr,
				"snapshot load failed for %s: zstd decompression: %s\n",
				filename, err);
			exit(1);
		}
		if (out_buf.pos == 0)
			continue;
		if (SIZE_MAX - total_size < out_buf.pos) {
			ZSTD_freeDCtx(dctx);
			snapshot_load_fail(
				filename, "decompressed snapshot is too large");
		}
		if (hash_snapshot)
			MD5_Update(&md5_ctx, out_chunk.data(), out_buf.pos);
		write_all(fd, out_chunk.data(), out_buf.pos, filename,
			  "write decompressed snapshot");
		total_size += out_buf.pos;
		snapshot_progress_update(in_buf.pos);
	}

	ZSTD_freeDCtx(dctx);
	snapshot_progress_finish();
	if (hash_snapshot)
		MD5_Final(md5sum_hex, &md5_ctx);
	if (lseek(fd, 0L, SEEK_SET) == -1) {
		snapshot_load_perror(filename, "seek decompressed snapshot");
	}
	*decompressed_size = total_size;
}

void validate_elf_snapshot(const uint8_t *elf, size_t elf_size,
			   const char *filename) {
	const ElfW(Ehdr) * ehdr;
	const ElfW(Phdr) * phdr;

	if (elf_size < sizeof(ElfW(Ehdr)))
		snapshot_load_fail(filename,
				   "snapshot is smaller than ELF header");
	if (!has_magic(elf, elf_size, kElfMagic, sizeof(kElfMagic)))
		snapshot_load_fail(filename, "snapshot is not an ELF image");

	ehdr = (const ElfW(Ehdr) *)elf;
	if (ehdr->e_phentsize != sizeof(ElfW(Phdr)))
		snapshot_load_fail(filename,
				   "unexpected ELF program header size");
	if (ehdr->e_phoff > elf_size)
		snapshot_load_fail(filename,
				   "ELF program header table is out of bounds");
	if (ehdr->e_phnum > (elf_size - ehdr->e_phoff) / sizeof(ElfW(Phdr)))
		snapshot_load_fail(filename,
				   "ELF program header table is truncated");

	phdr = (const ElfW(Phdr) *)(elf + ehdr->e_phoff);
	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type != 1)
			continue;
		if (phdr[i].p_memsz < phdr[i].p_filesz)
			snapshot_load_fail(
				filename,
				"ELF PT_LOAD segment filesz exceeds memsz");
		if (phdr[i].p_offset > elf_size)
			snapshot_load_fail(
				filename,
				"ELF PT_LOAD segment offset is out of bounds");
		if (phdr[i].p_filesz > elf_size - phdr[i].p_offset)
			snapshot_load_fail(filename,
					   "ELF PT_LOAD segment is truncated");
		if (phdr[i].p_vaddr + phdr[i].p_memsz < phdr[i].p_vaddr)
			snapshot_load_fail(
				filename,
				"ELF PT_LOAD segment address overflows");
	}
}

uint8_t *mmap_snapshot_file(int fd, size_t size, const char *filename) {
	void *mapping;

	mapping = mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (mapping == MAP_FAILED)
		snapshot_load_perror(filename, "mmap");

	return (uint8_t *)mapping;
}

uint8_t *mmap_overlay(size_t size, int prot, int flags, int fd, off_t offset,
		      const char *name) {
	void *mapping;

	mapping = mmap(NULL, size, prot, flags, fd, offset);
	if (mapping == MAP_FAILED) {
		perror(name);
		exit(1);
	}

	return (uint8_t *)mapping;
}

size_t get_total_pt_load_bytes(const ElfW(Ehdr) * ehdr, const ElfW(Phdr) * phdr,
			       const char *filename) {
	size_t total = 0;

	for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type != 1)
			continue;
		if (SIZE_MAX - total < phdr[i].p_filesz)
			snapshot_load_fail(
				filename,
				"ELF PT_LOAD bytes overflow progress counter");
		total += phdr[i].p_filesz;
	}

	return total;
}

void copy_snapshot_bytes(uint8_t *dst, const uint8_t *src, size_t len,
			 size_t *copied, size_t total) {
	size_t offset = 0;

	while (offset < len) {
		size_t chunk = len - offset;

		if (chunk > kSnapshotCopyChunk)
			chunk = kSnapshotCopyChunk;
		memcpy(dst + offset, src + offset, chunk);
		offset += chunk;
		*copied += chunk;
		snapshot_progress_update(*copied > total ? total : *copied);
	}
}

} // namespace

void _shm_unlink(void) {
	if (shm_unlink(md5sum_chr) == -1) {
		perror("shm_unlink");
	} else {
		printf("shm '%s' has been unlinked.\n", md5sum_chr);
	}
	close(shfd);
}

void icp_init_mem(const char *filename) {
	// Either Elf64_Ehdr or Elf32_Ehdr depending on architecture.
	struct stat statbuf;
	const char *saved_md5sum_chr = icp_mem_md5sum();
	bool have_computed_md5 = false;
	bool have_cached_backing_store = false;
	const uint8_t *elf = NULL;
	size_t elf_size = 0;
	uint8_t *elf_mapping = NULL;
	size_t elf_mapping_size = 0;
	int temp_fd = -1;
	uint8_t *mapped_file = NULL;
	const ElfW(Ehdr) * ehdr;
	const ElfW(Phdr) * phdr;
	size_t total_pt_load_bytes;
	off_t shfd_size = -1;
	unsigned char md5sum_hex[MD5_DIGEST_LENGTH];
	FILE *file;

	file = fopen(filename, "rb");
	if (!file)
		snapshot_load_perror(filename, "fopen");
	if (fstat(fileno(file), &statbuf) == -1) {
		fclose(file);
		snapshot_load_perror(filename, "fstat");
	}
	if (statbuf.st_size <= 0) {
		fclose(file);
		snapshot_load_fail(filename, "snapshot file is empty");
	}

	if (saved_md5sum_chr) {
		memcpy(md5sum_chr, saved_md5sum_chr, 32);
		md5sum_chr[32] = '\0';
		shfd = shm_open((const char *)md5sum_chr, O_CREAT | O_RDWR,
				S_IRUSR | S_IWUSR);
		if (shfd == -1) {
			fclose(file);
			perror("shm_open");
			exit(1);
		}
		shfd_size = lseek(shfd, 0L, SEEK_END);
		if (shfd_size == -1) {
			fclose(file);
			perror("snapshot backing store");
			exit(1);
		}
		if (shfd_size > 0) {
			maxaddr = shfd_size;
			have_cached_backing_store = true;
			verbose_printf("Max Addr: %lx\n", maxaddr);
			assert(maxaddr % 4096 == 0);
		}
	}

	mapped_file =
		mmap_snapshot_file(fileno(file), statbuf.st_size, filename);
	if (!have_cached_backing_store &&
	    has_magic(mapped_file, statbuf.st_size, kZstdMagic,
		      sizeof(kZstdMagic))) {
		unsigned char *md5_dst = NULL;

		temp_fd = open_tmp_shm_fd(filename);
		if (!saved_md5sum_chr)
			md5_dst = md5sum_hex;

		decompress_zstd_snapshot_to_fd(mapped_file, statbuf.st_size,
					       filename, md5_dst, temp_fd,
					       &elf_size);
		have_computed_md5 = md5_dst != NULL;
		if (elf_size == 0)
			snapshot_load_fail(filename,
					   "decompressed snapshot is empty");
		elf_mapping =
			mmap_snapshot_file(temp_fd, elf_size, filename);
		elf_mapping_size = elf_size;
		close(temp_fd);
		temp_fd = -1;
		elf = elf_mapping;
	} else if (!have_cached_backing_store) {
		elf = mapped_file;
		elf_size = statbuf.st_size;
	}

	if (!have_cached_backing_store) {
		validate_elf_snapshot(elf, elf_size, filename);
		ehdr = (const ElfW(Ehdr) *)elf;
		phdr = (const ElfW(Phdr) *)(elf + ehdr->e_phoff);
		total_pt_load_bytes = get_total_pt_load_bytes(ehdr, phdr,
							      filename);
		maxaddr = 0;
		for (int i = 0; i < ehdr->e_phnum; i++) {
			if (phdr[i].p_type != 1)
				continue;
			if (phdr[i].p_vaddr + phdr[i].p_memsz > maxaddr)
				maxaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
		}
		if (maxaddr == 0)
			snapshot_load_fail(
				filename,
				"ELF snapshot contains no PT_LOAD segments");
		verbose_printf("Max Addr: %lx\n", maxaddr);
		assert(maxaddr % 4096 == 0);

		if (!saved_md5sum_chr) {
			if (have_computed_md5) {
				for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
					sprintf(md5sum_chr + (i * 2),
						"%02x", md5sum_hex[i]);
			} else {
				MD5((unsigned char *)elf, elf_size, md5sum_hex);
				for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
					sprintf(md5sum_chr + (i * 2), "%02x",
						md5sum_hex[i]);
			}
			md5sum_chr[32] = '\0';
			shfd = shm_open((const char *)md5sum_chr,
					O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
			if (shfd == -1) {
				if (elf_mapping)
					munmap(elf_mapping, elf_mapping_size);
				if (mapped_file)
					munmap(mapped_file, statbuf.st_size);
				if (temp_fd != -1)
					close(temp_fd);
				fclose(file);
				perror("shm_open");
				exit(1);
			}
			shfd_size = lseek(shfd, 0L, SEEK_END);
			if (shfd_size == -1) {
				if (elf_mapping)
					munmap(elf_mapping, elf_mapping_size);
				if (mapped_file)
					munmap(mapped_file, statbuf.st_size);
				if (temp_fd != -1)
					close(temp_fd);
				fclose(file);
				perror("snapshot backing store");
				exit(1);
			}
		}

		if (shfd_size > 0 && shfd_size != (off_t)maxaddr) {
			if (elf_mapping)
				munmap(elf_mapping, elf_mapping_size);
			if (mapped_file)
				munmap(mapped_file, statbuf.st_size);
			if (temp_fd != -1)
				close(temp_fd);
			fclose(file);
			snapshot_load_fail(filename,
					   "cached memory snapshot size mismatch");
		}
	}

	// Now that we know how much memory we need, do THREE mmaps:
	// 3 layers 3 mmaps
	// The first layer is shadowmem: this will contain the verbatim
	// contents of the snapshot. This is mmapped from a shared file which
	// is shared by all the workers. It is mapped read-only and should
	// never be changed.
	// The second layer is workershadowmem: this is the per-worker memory
	// that differs from shadowmem (i.e. dirtied by writes) but which
	// should be persisted between writes.
	// The third layer is mem: this is the per-worker dirty memory which
	// is used during fuzzing and should be reset after each input.
	overlays[2] = mmap_overlay(maxaddr, PROT_READ | PROT_WRITE,
				   MAP_SHARED | MAP_ANONYMOUS, -1, 0,
				   "mmap overlay[2]");
	overlays[1] = mmap_overlay(maxaddr, PROT_READ | PROT_WRITE,
				   MAP_SHARED | MAP_ANONYMOUS, -1, 0,
				   "mmap overlay[1]");

	if (shfd_size == 0) {
		if (lseek(shfd, 0L, SEEK_SET) == -1 ||
		    ftruncate(shfd, maxaddr) == -1) {
			if (elf_mapping)
				munmap(elf_mapping, elf_mapping_size);
			if (mapped_file)
				munmap(mapped_file, statbuf.st_size);
			if (temp_fd != -1)
				close(temp_fd);
			fclose(file);
			perror("snapshot backing store");
			exit(1);
		}
		overlays[0] = mmap_overlay(maxaddr, PROT_READ | PROT_WRITE,
					   MAP_SHARED, shfd, 0,
					   "mmap overlay[0]");
		snapshot_progress_start("loading memory snapshot",
					total_pt_load_bytes);

		size_t copied = 0;
		for (int i = 0; i < ehdr->e_phnum; i++) {
			if (phdr[i].p_type != 1)
				continue;
			copy_snapshot_bytes(overlays[0] + phdr[i].p_vaddr,
					    elf + phdr[i].p_offset,
					    phdr[i].p_filesz, &copied,
					    total_pt_load_bytes);
		}
		snapshot_progress_finish();
	} else {
		if (lseek(shfd, 0L, SEEK_SET) == -1) {
			if (elf_mapping)
				munmap(elf_mapping, elf_mapping_size);
			if (mapped_file)
				munmap(mapped_file, statbuf.st_size);
			if (temp_fd != -1)
				close(temp_fd);
			fclose(file);
			perror("snapshot backing store");
			exit(1);
		}
		overlays[0] = mmap_overlay(maxaddr, PROT_READ | PROT_WRITE,
					   MAP_SHARED, shfd, 0,
					   "mmap overlay[0]");
		fprintf(stderr,
			".reusing cached memory snapshot backing store\n");
	}

	cow_bitmap = (uint8_t *)malloc(maxaddr >> 12);
	memset(cow_bitmap, 0, maxaddr >> 12);

	overlay_map = (uint8_t *)malloc(maxaddr >> 12);
	memset(overlay_map, 0, maxaddr >> 12);

	is_l2_page_bitmap = (uint8_t *)malloc(maxaddr >> 12);
	memset(is_l2_page_bitmap, 0, maxaddr >> 12);

	is_l2_pagetable_bitmap = (uint8_t *)malloc(maxaddr >> 12);
	memset(is_l2_pagetable_bitmap, 0, maxaddr >> 12);

	if (mapped_file)
		munmap(mapped_file, statbuf.st_size);
	if (elf_mapping)
		munmap(elf_mapping, elf_mapping_size);
	if (temp_fd != -1)
		close(temp_fd);
	fclose(file);
}

void mark_l2_guest_page(uint64_t paddr, uint64_t len, uint64_t addr) {
	hpa_to_gpa[paddr] = addr;
	while (paddr < maxaddr && len) {
		is_l2_page_bitmap[paddr >> 12]++;
		len -= 0x1000;
		paddr += 0x1000;
		guest_mem_size += 0x1000;
	}
}

void mark_l2_guest_pagetable(uint64_t paddr, uint64_t len, uint8_t level) {
	if (paddr < maxaddr) {
		// we use page level values of >=1 to facilitate checking the
		// bitmap bitmap value of 0 will indicate that the page is not
		// present a non-zero bitmap value will indicate the page level,
		// with level 1 mapped to BX_LEVEL_PTE and level 4 mapped to
		// BX_LEVEL_PML4
		is_l2_pagetable_bitmap[paddr >> 12] = level + 1;
		assert(level >= 0 && level <= 3);
	}
}

void cpu_physical_memory_read(uint64_t addr, void *dest, size_t len) {
	memcpy(dest, addr_conv(addr), len);
}

void cpu_physical_memory_write(uint64_t addr, const void *src, size_t len) {
	notify_write(addr);
	memcpy(addr_conv(addr), src, len);
}

BOCHSAPI BX_MEM_C bx_mem;
