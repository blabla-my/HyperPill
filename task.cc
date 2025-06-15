#include "task.h"
#include "config.h"
#include "cpu/tlb.h"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <sys/types.h>

tsl::robin_map<unsigned long, struct fuzz_task_struct*> task_map;
tsl::robin_set<struct fuzz_task_struct*> hypervisor_tasks;

int read_task_struct(bx_address task_struct, void* buf, size_t len) {
    if (task_struct == 0){
        return -1;
    }
    if (len < TASK_SIZE) {
        return -1; // Buffer too small
    }
    BX_CPU(x)->access_read_linear(task_struct, TASK_SIZE, 0, BX_READ, 0, buf);
    return 0; // Success
}

int read_mm_struct(bx_address mm_struct, void* buf, size_t len){
    if (mm_struct == 0) {
        return -1; // Invalid mm_struct address
    }
    if (len < MM_SIZE) {
        return -1; // Buffer too small
    }
    BX_CPU(x)->access_read_linear(mm_struct, MM_SIZE, 0, BX_READ, 0, buf);
    return 0; // Success
}

int task_buf_to_fuzz_task(const uint8_t* task_buf, struct fuzz_task_struct* fuzz_task_ptr) {
    if (!task_buf || !fuzz_task_ptr) {
        return -1; // Invalid buffer
    }
    memset(fuzz_task_ptr, 0, sizeof(struct fuzz_task_struct)); // Clear the struct
    fuzz_task_ptr->pid = task_pid(task_buf);
    fuzz_task_ptr->kernel_thread = (task_mm(task_buf) == 0);
    memcpy(fuzz_task_ptr->comm, task_comm(task_buf), sizeof(fuzz_task_ptr->comm));

    unsigned long mm = task_mm(task_buf);
    if (mm == 0) {
        mm = task_active_mm(task_buf);
    }

    if (mm == 0) {
        fuzz_task_ptr->pgd = 0; // Kernel threads do not have a user space memory
        fuzz_task_ptr->cr3 = 0; // Kernel threads do not have a user space memory
    }
    else {
        // fuzz_task_ptr->pgd = task_mm(task_buf);
        // fuzz_task_ptr->cr3 = pgd2cr3(fuzz_task_ptr->pgd);
        uint8_t mm_buf[MM_SIZE];
        if (read_mm_struct(mm, mm_buf, sizeof(mm_buf)) < 0) {
            return -1; // Failed to read mm_struct
        }
        fuzz_task_ptr->pgd = mm_pgd(mm_buf);
        fuzz_task_ptr->cr3 = pgd2cr3(fuzz_task_ptr->pgd);
    }

    // check if task->comm contains a hypervisor signature
    std::string comm_str(fuzz_task_ptr->comm);
    for (const auto& signature : hypervisor_signatures) {
        if (comm_str.find(signature) != std::string::npos) {
            fuzz_task_ptr->hypervisor_thread = 1;
            break;
        }
    }
    return 0; // Success
}

unsigned long pgd2cr3(unsigned long pgd) {
    bx_phy_address cr3;
    BX_CPU(x)->dbg_xlate_linear2phy(pgd, &cr3);
    return cr3;
}

void iterate_tasks(bx_address task_struct_head) {
    uint8_t task_buf[TASK_SIZE];
    uint8_t mm_buf[MM_SIZE];
    bx_address task = task_struct_head;
    bx_address mm;
    do {
        struct fuzz_task_struct* fuzz_task_ptr = (struct fuzz_task_struct*)malloc(sizeof(struct fuzz_task_struct));
        if (read_task_struct(task, task_buf, sizeof(task_buf)) < 0) {
            printf("Failed to read task_struct at %lx\n", task);
            return;
        }
        if (task_buf_to_fuzz_task(task_buf, fuzz_task_ptr) < 0) {
            printf("Failed to convert task buffer to fuzz_task\n");
            return;
        }

        task_map[fuzz_task_ptr->cr3 >> PAGE_SHIFT] = fuzz_task_ptr;
        
        if (fuzz_task_ptr->hypervisor_thread){
            hypervisor_tasks.insert(fuzz_task_ptr);
        }

        printf("Task PID: %d, Kernel Thread: %d, Hypervisor Thread: %d, Comm: %s, CR3: %lx, PGD: %lx\n",
               fuzz_task_ptr->pid, fuzz_task_ptr->kernel_thread, fuzz_task_ptr->hypervisor_thread, fuzz_task_ptr->comm,
               fuzz_task_ptr->cr3, fuzz_task_ptr->pgd);

        task = task_next(task_buf);
    } while (task != task_struct_head);
}

bool is_hypervisor_task(unsigned long cr3) {
    return task_map.find(cr3>>PAGE_SHIFT) != task_map.end() &&
           task_map[cr3>>PAGE_SHIFT]->hypervisor_thread;
}

struct fuzz_task_struct* get_task_by_cr3(unsigned long cr3) {
    if (task_map.find(cr3>>PAGE_SHIFT) == task_map.end()) {
        return NULL;
    }
    return task_map[cr3>>PAGE_SHIFT];
}