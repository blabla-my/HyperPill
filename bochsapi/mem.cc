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
#include <sys/ucontext.h>
#include <unistd.h>


#include <tsl/robin_set.h>
#include <tsl/robin_map.h>
#include "../fuzz.h"
#include "../option.h"
#include <openssl/md5.h>

BX_MEM_C::BX_MEM_C() {}
BX_MEM_C::~BX_MEM_C() {}

size_t maxaddr = 0;

static uint8_t watch_level = 0;
static uint8_t* overlays[3];
uint8_t* is_l2_page_bitmap; /* Page is in L2 */
uint8_t* is_l2_pagetable_bitmap; /* Page is in L2 */
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

std::vector<std::tuple<bx_address, uint8_t, uint8_t>> fuzzed_guest_pages; // < HPA, pagetable_level, original_val >

static int memory_commit_level;

size_t ndirty=0;
static const size_t kDirtyPageLimit =
    nocov_enabled() ? 10000 * nocov_scale() : 10000;

static bx_address prioraccess;
void fuzz_hook_memory_access(unsigned cpu, bx_address phy, unsigned len,
                             unsigned memtype, unsigned rw, void* data) {
    static bool kernel_dma = kernel_dma_enabled();
    bx_address aligned = phy&(~0xFFFLL);

    /* printf("Memory access to %lx\n", phy); */
    // Sometimes we might run instructions during initialization and we
    // want them to be part of the snapshot.
    if(watch_level<=1 || phy >= maxaddr)
        return;

    if(aligned == prioraccess)
        return;

    if(rw == BX_WRITE || rw == BX_RW) {
        prioraccess = aligned;
      // This stores the addr in the dirtyset (reset for each input) and makes a
      // copy of the corresponding page in shadowset/shadowmem (persistent).
      // Otherwise I run out of RAM on my machine :')
      // When we do the actual fuzzing runs on beefier hardware, we should just
      // make a complete shadow-copy on startup.
      if (dirtyset.emplace(aligned).second) {
          // if there is an infinite loop, we need to stop since it will cause a libfuzzer timeout and stop fuzzing.
          if(ndirty++>kDirtyPageLimit){
              printf("Too many dirty pages. Early stop\n");
              fuzz_emu_stop_unhealthy();
          }
      }
    }

    // used to identify DMA accesses in the guest
    // contains a mapping for each host physical page, for whether it corresponds to a guest page
    // if an access uses such an address, it is likely a DMA
    if (rw == BX_READ && is_l2_page_bitmap[phy >> 12] && !guest_page_table.contains(phy>>12)) {
        if(BX_CPU(cpu)->fuzztrace) {
            /* printf(".dma inject: %lx +%lx ",phy, len); */
        }
        static bool hv = hyperv_enabled();
        if(BX_CPU(cpu)->user_pl || hv || kernel_dma) {
            Task* current_task = task_manager.get_current_task(cpu);
            if (!current_task) 
                return;
            if (current_task->CPU_KVM)
                return;
            if (!current_task->is_hypervisor_task()) {
                current_task->hypervisor_task = 1;
                printf("DMA read by task %d (%s) at %lx\n",
                       current_task->pid, current_task->comm, phy);
            }
            fuzz_dma_read_cb(cpu, phy, len, data);
            if (log_ops) {
                uint8_t buf[len];
                BX_MEM_C::readPhysicalPage(BX_CPU(cpu), phy, len, buf);
                bx_address gpa = lookup_gpa_by_hpa(phy);
                const VRing* vring = get_vqueue_manager().get_belonging_vring(gpa);
                if (vring && vring->queue->vdev->to_fuzz)
                    printf("!dma inject: [HPA: %lx, GPA: %lx, vring: %s, start: %lx, end: %lx, type: %d] len: %x data: ",
                            phy, gpa, vring->type_str(), vring->start(), vring->end(), vring->filed_type(gpa), len);
                else
                    printf("!dma inject: [HPA: %lx, GPA: %lx] len: %x data: ",
                            phy, gpa, len);
                for (int i = 0; i < len; i++)
                    printf("%02x", buf[i]);
                printf("\n");
            }
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


uint64_t lookup_gpa_by_hpa(uint64_t hpa){
    uint64_t page = hpa;
    uint64_t offset;
    int i = 0;
    while (hpa_to_gpa.find(page) == hpa_to_gpa.end() && page){
        i++;
        page = ((page >> i) << i);
    }
    if(!page)
        printf("Error looking up GPA for HPA: %lx\n", hpa);
    return hpa_to_gpa[page] | (hpa&(~(((uint64_t)(-1)>>i)<<i)));
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
    fuzzed_guest_pages.push_back(std::make_tuple(new_addr, new_pgtable_lvl, is_l2_pagetable_bitmap[new_addr>>12]));
    //printf("!fuzz_mark_l2_guest_page Mark 0x%lx lvl %x as tmp guest page\n", new_addr, new_pgtable_lvl);
    if (new_pgtable_lvl) {
        mark_l2_guest_pagetable(new_addr, len, new_pgtable_lvl - 1);
    } else {
        mark_l2_guest_page(new_addr, len, 0);
    }
}

void fuzz_reset_watched_pages() {
    // printf("[fuzz_reset_watched_pages] reset 0x%lx watched pages\n", fuzzed_guest_pages.size());;
    for (auto& page : fuzzed_guest_pages) {
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
    assert(((start+len-1)>>12) == (page >> 12));

    startend = start-page;
    startend |= (start+len - page) << 12;
    if (persist_ranges.find(page) == persist_ranges.end()){
        persist_ranges[page] = persist_range_vec();
    }
    // merge if possible
    for (auto se : persist_ranges[page]){
        bx_phy_address s = se & 0xFFF;
        bx_phy_address e = se >> 12;
        if (!((startend & 0xFFF) >= e || (startend >> 12) <= s)){
            // merge
            bx_phy_address new_start = std::min(startend & 0xFFF, s);
            bx_phy_address new_end = std::max(startend >> 12, e);
            startend = new_start | (new_end << 12);
            persist_ranges[page].erase(std::remove(persist_ranges[page].begin(), persist_ranges[page].end(), se), persist_ranges[page].end());
        } 
    }
    // insert sort 
    for (auto it = persist_ranges[page].begin(); it != persist_ranges[page].end(); ++it){
        bx_phy_address s = (*it) & 0xFFF;
        if ((startend & 0xFFF) < s){
            persist_ranges[page].insert(it, startend);
            return;
        }
    }
    persist_ranges[page].push_back(startend);

    // sanity-check for persistent_ranges[page], no overlap and keep in order
    bx_phy_address last_end = 0;
    for (auto se : persist_ranges[page]){
        bx_phy_address s = se & 0xFFF;
        bx_phy_address e = se >> 12;
        assert(s >= last_end && e > s);
        last_end = e;
    }
}

void add_persistent_kernel_memory_range(bx_address start, size_t len) {
    /* start, len is continuous in kernel space but not in physical address space */
    Bit32u lpf_mask = 0xfff; // 4K pages
    Bit32u pkey = 0;
    bx_phy_address region_start, region_end;

    bx_address page_start = (start >> 12) << 12;
    bx_address page_end = ((start + len - 1) >> 12) << 12;
    if (page_start == page_end) {
        region_start = BX_CPU(bx_kernel_cpu())->translate_linear_long_mode(start, lpf_mask, pkey, 0, BX_RW);
        region_start = (region_start & ~((Bit64u) lpf_mask)) | (start & lpf_mask);
        region_end = region_start + len;
        add_persistent_memory_range(region_start, len);
        return;
    }
    for (bx_address page = page_start; page <= page_end; page += 0x1000) {
        if (start > page) {
            region_start = BX_CPU(bx_kernel_cpu())->translate_linear_long_mode(start, lpf_mask, pkey, 0, BX_RW);
            region_start = (region_start & ~((Bit64u) lpf_mask)) | (start & lpf_mask);
            region_end = (page + 0x1000);
            assert((region_start & lpf_mask) != 0);
            assert((region_end & lpf_mask) == 0);
            add_persistent_memory_range(region_start, region_end - start);
            continue;
        }
        if (page + 0x1000 > start + len) {
            region_start = BX_CPU(bx_kernel_cpu())->translate_linear_long_mode(page, lpf_mask, pkey, 0, BX_RW);
            region_start = (region_start & ~((Bit64u) lpf_mask));
            region_end = region_start + (start + len - page);
            assert((region_start & lpf_mask) == 0);
            assert((region_end & lpf_mask) != 0);
            add_persistent_memory_range(region_start, region_end - region_start);
            continue;
        }
        region_start = BX_CPU(bx_kernel_cpu())->translate_linear_long_mode(page, lpf_mask, pkey, 0, BX_RW);
        region_start = (region_start & ~((Bit64u) lpf_mask));
        region_end = region_start + 0x1000;
        assert((region_start & lpf_mask) == 0);
        assert((region_end & lpf_mask) == 0);
        add_persistent_memory_range(region_start, region_end - region_start);
    }
}

static void notify_write(uint64_t addr){
    size_t page = addr >> 12;
    size_t aligned_addr = page << 12;
    if(cow_bitmap[page] != watch_level) {
        cow_bitmap[page] = watch_level;
        memcpy(overlays[cow_bitmap[page]] + aligned_addr, overlays[overlay_map[page]]+aligned_addr, 0x1000);
        if(watch_level < 2){
            overlay_map[page] = watch_level;
        }
    }
    /* printf("Page %lx now lives at %lx and is backed by %lx\n", page, cow_bitmap[page], overlay_map[page]); */
}

uint8_t* addr_conv(uint64_t addr){
    /* printf("ADDR_CONV: %lx -> %lx [%d]\n", addr,overlays[cow_bitmap[addr>>12]]+addr, cow_bitmap[addr>>12]); */
    return overlays[cow_bitmap[addr>>12]]+addr;
}
uint8_t* backing_addr(uint64_t addr){
    return overlays[overlay_map[addr>>12]]+addr;
}

void fuzz_reset_memory() {
    if(watch_level<=1)
        return;
    prioraccess=0;
    for(const auto& page : dirtyset) {
        size_t page_number = page >> 12;
        if (persist_ranges.find(page) != persist_ranges.end()){
            bx_phy_address last_end = 0;
            for (auto startend : persist_ranges[page]){
                bx_phy_address s = startend & 0xFFF;
                bx_phy_address e = startend >> 12;
                memcpy(addr_conv(page + last_end), backing_addr(page + last_end), s - last_end);
                last_end = e;
            }
            memcpy(addr_conv(page + last_end), backing_addr(page + last_end), 0x1000 - last_end);
        } else {
            memcpy(addr_conv(page), backing_addr(page), 0x1000);
        }
    }
    fuzz_clear_dirty();
    fuzz_reset_watched_pages();
}


void BX_MEM_C::writePhysicalPage(BX_CPU_C *cpu, bx_phy_address addr,
    unsigned len, void *data, bool hook_access)
{

    notify_write(addr);
    if (hook_access)
        fuzz_hook_memory_access(cpu ? cpu->which_cpu() : 0, addr, len, 0, BX_WRITE, NULL) ;

    memcpy(addr_conv(addr), data, len);

    if (is_l2_pagetable_bitmap[addr >> 12] && watch_level > 1) {
      fuzz_mark_l2_guest_page(addr, 0x1000);
    }

    return;
}

void BX_MEM_C::readPhysicalPage(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, void *data)
{
    memcpy(data, addr_conv(addr), len);
    return;
}

void mark_page_not_guest(bx_phy_address addr, int level) {
    printf("Mark page not present: %lx\n", addr);
    is_l2_page_bitmap[addr>>12] = 0;
    guest_page_table.insert(addr>>12);
}

bool frame_is_guest(bx_phy_address addr) {
    return is_l2_page_bitmap[addr>>12] ;
}

Bit8u *BX_MEM_C::getHostMemAddr(BX_CPU_C *cpu, bx_phy_address addr, unsigned rw)
{
    if(rw!=BX_READ)
        notify_write(addr);
    return addr_conv(addr);
}

bool BX_MEM_C::dbg_fetch_mem(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, Bit8u *buf)
{
    readPhysicalPage(cpu, addr, len , buf);
    return true;
}

#if (BX_DEBUGGER || BX_GDBSTUB)
bool BX_MEM_C::dbg_set_mem(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, Bit8u *buf)
{
    notify_write(addr);
    memcpy(addr_conv(addr), buf, len);
    return true;
}
#endif

#if defined(__LP64__)
#define ElfW(type) Elf64_ ## type
#else
#define ElfW(type) Elf32_ ## type
#endif

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
  ElfW(Ehdr) * ehdr;
  ElfW(Phdr) *phdr = 0;
  ElfW(Nhdr) *nhdr = 0;
  unsigned char md5sum_hex[MD5_DIGEST_LENGTH];

  FILE *file = fopen(filename, "rb");
  if (file) {
    fstat(fileno(file), &statbuf);

    ehdr = (ElfW(Ehdr) *)mmap(0, statbuf.st_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE, fileno(file), 0);

    phdr = (ElfW(Phdr) *)(ehdr->e_phoff + (size_t)ehdr);
    for (int i = 0; i < ehdr->e_phnum; i++) {
      if (phdr->p_vaddr + phdr->p_memsz > maxaddr && phdr->p_type == 1) {
        maxaddr = phdr->p_vaddr + phdr->p_memsz;
      }
      ++phdr;
    }
    verbose_printf("Max Addr: %lx\n", maxaddr);
    assert(maxaddr % 4096 == 0);

    // Now that we know how much memory we need, do THREE mmaps:
    // 3 layers 3 mmaps
    // The first layer is shadowmem: this will contain the verbatim contents of the snapshot. This is mmapped from a shared file which is shared by all the workers. It is mapped read-only and should never be changed
    // The second layer is workershadowmem: this is the per-worker memory that differs from shadowmem (i.e. dirtied by writes) but which should be persisted between writes
    // The third layer is mem: this is the per-worker dirty memory which is used during fuzzing and should be reset after each input
    overlays[2] = (uint8_t *)mmap(NULL, maxaddr, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    overlays[1]= (uint8_t *)mmap(NULL, maxaddr, PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    const char *saved_md5sum_chr = icp_mem_md5sum();
    if (saved_md5sum_chr) {
        memcpy(md5sum_chr, saved_md5sum_chr, 32);
    } else {
        MD5((unsigned char*)ehdr, statbuf.st_size, md5sum_hex);
        for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
            sprintf(md5sum_chr + (i * 2), "%02x", md5sum_hex[i]);
        }
    }
    md5sum_chr[32] = '\0';
    shfd = shm_open((const char*)md5sum_chr, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    
    if(lseek(shfd, 0L, SEEK_END) == 0){
        lseek(shfd, 0L, SEEK_SET);
        ftruncate(shfd, maxaddr);
        overlays[0]= (uint8_t *)mmap(NULL, maxaddr, PROT_READ | PROT_WRITE,
                MAP_SHARED, shfd, 0);

        phdr = (ElfW(Phdr) *)(ehdr->e_phoff + (size_t)ehdr);
        for (int i = 0; i < ehdr->e_phnum; i++) {
            if (phdr->p_type == 1) {
                memcpy(overlays[0] + phdr->p_vaddr, (uint8_t *)ehdr + phdr->p_offset,
                        phdr->p_filesz);
            }
            ++phdr;
        }
    } else {
        lseek(shfd, 0L, SEEK_SET);
        overlays[0] = (uint8_t *)mmap(NULL, maxaddr, PROT_READ|PROT_WRITE,
                MAP_SHARED, shfd, 0);
    }

    cow_bitmap = (uint8_t *)malloc(maxaddr >> 12);
    memset(cow_bitmap, 0, maxaddr >> 12);
    
    overlay_map = (uint8_t *)malloc(maxaddr >> 12);
    memset(overlay_map, 0, maxaddr >> 12);

    is_l2_page_bitmap = (uint8_t *)malloc(maxaddr >> 12);
    memset(is_l2_page_bitmap, 0, maxaddr >> 12);

    is_l2_pagetable_bitmap = (uint8_t *)malloc(maxaddr >> 12);
    memset(is_l2_pagetable_bitmap, 0, maxaddr >> 12);

    munmap(ehdr, statbuf.st_size);
    // finally close the file
    fclose(file);

  }
}

void mark_l2_guest_page(uint64_t paddr, uint64_t len, uint64_t addr){
    hpa_to_gpa[paddr] = addr;
    while(paddr < maxaddr && len) {
        is_l2_page_bitmap[paddr>>12]++;
        len -= 0x1000;
        paddr += 0x1000;
        guest_mem_size += 0x1000;
    }
}

void mark_l2_guest_pagetable(uint64_t paddr, uint64_t len, uint8_t level) {
    if(paddr < maxaddr) {
        // we use page level values of >=1 to facilitate checking the bitmap
        // bitmap value of 0 will indicate that the page is not present
        // a non-zero bitmap value will indicate the page level, with
        // level 1 mapped to BX_LEVEL_PTE and level 4 mapped to BX_LEVEL_PML4
        is_l2_pagetable_bitmap[paddr>>12] = level + 1;
        assert(level >= 0 && level <= 3);
    }
}

void cpu_physical_memory_read(uint64_t addr, void* dest, size_t len){
    memcpy(dest, addr_conv(addr), len);
}

void cpu_physical_memory_write(uint64_t addr, const void* src, size_t len){
    notify_write(addr);
    memcpy(addr_conv(addr), src, len);
}

BOCHSAPI BX_MEM_C bx_mem;
