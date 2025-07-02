#include "task.h"
#include "bochs.h"
#include "config.h"
#include "cpu/cpu.h"
#include "cpu/decoder/decoder.h"
#include "cpu/tlb.h"
#include "fuzz.h"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <sys/types.h>

tsl::robin_map<unsigned long, struct task*> cr3_task_map;
tsl::robin_set<struct task*> hypervisor_tasks;

TaskManager task_manager;

static std::string hypervisor_task_signatures[] = {
    "qemu-system",
    "vbox",
    "kvm",
    "vhost"
};

static std::string userspace_vmm_task_signatures[] = {
    "qemu-system",
    "vbox",
};

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

int task_buf_to_task(const uint8_t* task_buf, task* task_ptr) {
    if (!task_buf || !task_ptr) {
        return -1; // Invalid buffer
    }
    memset(task_ptr, 0, sizeof(struct task)); // Clear the struct
    memcpy(task_ptr->comm, task_comm(task_buf), sizeof(task_ptr->comm));

    task_ptr->pid = task_pid(task_buf);
    // task_ptr->kernel_task = (task_mm(task_buf) == 0);
    task_ptr->next = task_next(task_buf);
    task_ptr->prev = task_prev(task_buf);
    task_ptr->flags = task_flags(task_buf);
    task_ptr->kernel_task = !!(task_ptr->flags & (PF_KTHREAD|PF_VCPU));
    task_ptr->stack = task_stack(task_buf);

    unsigned long mm = task_mm(task_buf);
    if (mm == 0) {
        mm = task_active_mm(task_buf);
    }

    if (mm == 0) {
        task_ptr->pgd = 0; // Kernel threads do not have a user space memory
        task_ptr->cr3 = 0; // Kernel threads do not have a user space memory
    }
    else {
        // fuzz_task_ptr->pgd = task_mm(task_buf);
        // fuzz_task_ptr->cr3 = pgd2cr3(fuzz_task_ptr->pgd);
        uint8_t mm_buf[MM_SIZE];
        if (read_mm_struct(mm, mm_buf, sizeof(mm_buf)) < 0) {
            return -1; // Failed to read mm_struct
        }
        task_ptr->pgd = mm_pgd(mm_buf);
        task_ptr->cr3 = pgd2cr3(task_ptr->pgd);
    }

    // check if task->comm contains a hypervisor signature
    std::string comm_str(task_ptr->comm);
    for (const auto& signature : hypervisor_task_signatures) {
        if (comm_str.find(signature) != std::string::npos) {
            task_ptr->hypervisor_task = 1;
            break;
        }
    }
    for (const auto& signature : userspace_vmm_task_signatures) {
        if (comm_str.find(signature) != std::string::npos) {
            task_ptr->userspace_vmm_task = 1;
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
    bx_address task = task_struct_head;
    do {
        struct task* task_ptr = task_manager.add_task(task);

        printf("Task at %lx PID: %d, Kernel Thread: %d, Hypervisor Thread: %d, Userspace VMM: %d, Comm: %s, CR3: %lx, PGD: %lx, flags: %x, stack: %lx\n",
               task, task_ptr->pid, task_ptr->kernel_task, task_ptr->hypervisor_task, task_ptr->userspace_vmm_task, task_ptr->comm,
               task_ptr->cr3, task_ptr->pgd, task_ptr->flags, task_ptr->stack);

        task = task_ptr->next;
    } while (task != task_struct_head);
}

bool is_hypervisor_task(unsigned long cr3) {
    auto* task = get_task_by_cr3(cr3);
    if (task == NULL)
        return false;
    if (!task->hypervisor_task)
        return false;
    if (task->cr3 == 0)
        return false;
    return true;
}

bool is_hypervisor_task(task* task) {
    if (!task) return false;
    return task->hypervisor_task;
}

bool is_userspace_vmm_task(unsigned long cr3) {
    auto* task = get_task_by_cr3(cr3);
    if (task == NULL)
        return false;
    return task->userspace_vmm_task;
}

bool is_userspace_vmm_task(task* task){
    if (!task) return false;
    return task->userspace_vmm_task;
}

bool set_hypervisor_task_by_cr3(unsigned long cr3) {
    if (cr3_task_map.find(cr3>>PAGE_SHIFT) == cr3_task_map.end()) {
        return false;
    }
    cr3_task_map[cr3>>PAGE_SHIFT]->hypervisor_task = true;
    return true;
}

struct task* get_task_by_cr3(unsigned long cr3) {
    if (cr3_task_map.find(cr3>>PAGE_SHIFT) == cr3_task_map.end()) {
        return NULL;
    }
    return cr3_task_map[cr3>>PAGE_SHIFT];
}

TaskManager::TaskManager(){
    // current_task = sym_to_addr("vmlinux", "current_task");
    current_task = 0;
}

TaskManager::~TaskManager(){
    return;
}

task* TaskManager::get_task(bx_address task_addr){
    if (!task_addr) return NULL;
    if (task_map.contains(task_addr)){
        return task_map[task_addr];
    }
    return NULL;
}

bx_address TaskManager::get_current_task_bx_addr(){
    if (!current_task) {
        current_task = sym_to_addr("vmlinux", "current_task");
        printf("TaskManager: set current_task: %lx\n", current_task);
    }

    bx_address taskpp = BX_CPU(id)->get_laddr(BX_SEG_REG_GS, current_task);
    // check whether GS==0
    if (taskpp == current_task) return 0;

    bx_address taskp;
    if (BX_CPU(id)->access_read_linear(taskpp, sizeof(bx_address), 0, BX_READ, 0, &taskp) < 0){
        printf("Error: failed to read task pointer at current_task %lx\n", taskpp);
        return 0;
    }
    return taskp;
}

task* TaskManager::get_current_task(){
    // only in kernel mode, GS is not 0
    if (BX_CPU(id)->get_cpl() == 0){
        bx_address current_task_bx_addr = get_current_task_bx_addr();
        if (!current_task_bx_addr) return NULL;
        task* current_task_fuzz = get_task(current_task_bx_addr);
        if (!current_task_fuzz) {
            return add_task(current_task_bx_addr);
        } else {
            return current_task_fuzz;
        }
    }
    else {
        if (user_task_map.contains(BX_CPU(id)->cr3 >> PAGE_SHIFT))
            return user_task_map[BX_CPU(id)->cr3 >> PAGE_SHIFT];
        else
            return NULL;
    }
}

task* TaskManager::get_hypervisor_task(bx_address task_addr){
    if (hypervisor_task_map.contains(task_addr)){
        return hypervisor_task_map.at(task_addr);
    }
    return NULL;
}

task* TaskManager::add_task(bx_address task_addr){
    task* already_in = get_task(task_addr);
    if (!already_in){
        task* new_task = alloca_task(task_addr);
        if (!new_task) return NULL;
        if (!new_task->kernel_task){
            // if new_task is a userspace task, index it by CR3 as well
            bx_address index = new_task->cr3 >> PAGE_SHIFT;
            user_task_map[index] = new_task;
            printf("add_task: index task %s by %lx, flags %x\n", new_task->comm, index, new_task->flags);
        } 
        task_map[task_addr] = new_task;
        return new_task;
    }
    return already_in;
}

task* TaskManager::add_task(task* task_addr){
    // assume task_addr->vaddr != 0
    if (!task_addr->vaddr){
        return NULL;
    }
    if (has_task(task_addr->vaddr)){
        return get_task(task_addr->vaddr);
    }
    task_map[task_addr->vaddr] = task_addr;
    return task_addr;
}

task* TaskManager::add_hypervisor_task(bx_address task_addr){
    task* already_in = get_hypervisor_task(task_addr);
    if (!already_in){
        task* new_task = add_task(task_addr);
        hypervisor_task_map[task_addr] = new_task;
        return new_task;
    }
    return already_in;
}

bool TaskManager::has_task(bx_address task_addr){
    return task_map.contains(task_addr);
}

bool TaskManager::del_task(bx_address task_addr){
    // Not implemeneted yet
    return true;
}

bool TaskManager::has_hypervisor_task(bx_address task_addr){
    return hypervisor_task_map.contains(task_addr);
}

task* TaskManager::alloca_task(bx_address task_addr){
    uint8_t *task_buf = (uint8_t*)malloc(TASK_SIZE);
    if (!task_buf){
        printf("Error: failed to allocate task_buf\n");
        return NULL;
    };
    if (read_task_struct(task_addr, task_buf, TASK_SIZE) < 0){
        printf("Error: failed to read task struct from guest memory\n");
        free(task_buf);
        return NULL;
    }
    task* new_task = (task*)malloc(sizeof(task));
    if (task_buf_to_task(task_buf, new_task) < 0){
        printf("Error: failed to convert task buf to task\n");
        return NULL;
    }
    new_task->vaddr = task_addr;
    return new_task;
}
