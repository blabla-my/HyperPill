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

int read_task_struct(unsigned cpu, bx_address task_struct, void* buf, size_t len) {
    if (task_struct == 0){
        return -1;
    }
    if (len < TASK_SIZE) {
        return -1; // Buffer too small
    }
    bx_kernel_read(cpu, task_struct, buf, TASK_SIZE);
    return 0; // Success
}

int read_mm_struct(unsigned cpu, bx_address mm_struct, void* buf, size_t len){
    if (mm_struct == 0) {
        return -1; // Invalid mm_struct address
    }
    if (len < MM_SIZE) {
        return -1; // Buffer too small
    }
    bx_kernel_read(cpu, mm_struct, buf, MM_SIZE);
    return 0; // Success
}

int read_pt_regs(unsigned cpu, bx_address pt_regs_addr, struct pt_regs *regs){
    if (pt_regs_addr == 0) {
        return -1; // Invalid pt_regs address
    }
    bx_kernel_read(cpu, pt_regs_addr, regs, sizeof(struct pt_regs));
    return 0; // Success
}

int task_buf_to_task(unsigned cpu, const uint8_t* task_buf, Task* task_ptr) {
    if (!task_buf || !task_ptr) {
        return -1; // Invalid buffer
    }
    // memset(task_ptr, 0, sizeof(Task)); // Clear the struct
    memcpy(task_ptr->comm, task_comm(task_buf), sizeof(task_ptr->comm));

    task_ptr->pid = task_pid(task_buf);
    // task_ptr->kernel_task = (task_mm(task_buf) == 0);
    task_ptr->next = task_next(task_buf);
    task_ptr->prev = task_prev(task_buf);
    task_ptr->flags = task_flags(task_buf);
    task_ptr->kernel_task = !!(task_ptr->flags & (PF_KTHREAD|PF_VCPU));
    task_ptr->stack = task_stack(task_buf);
    task_ptr->hypervisor_task = 0;
    task_ptr->CPU_KVM = false;

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
        if (read_mm_struct(cpu, mm, mm_buf, sizeof(mm_buf)) < 0) {
            return -1; // Failed to read mm_struct
        }
        task_ptr->pgd = mm_pgd(mm_buf);
        task_ptr->cr3 = pgd2cr3(cpu, task_ptr->pgd);
    }
    
    bx_address task_pt_regs_addr = (bx_address)task_pt_regs(task_buf);
    if (read_pt_regs(cpu, task_pt_regs_addr, &task_ptr->regs) < 0) {
        return -1; // Failed to read pt_regs
    }

    return 0; // Success
}

unsigned long pgd2cr3(unsigned cpu, unsigned long pgd) {
    bx_phy_address cr3;
    BX_CPU(cpu)->dbg_xlate_linear2phy(pgd, &cr3);
    return cr3;
}

void iterate_tasks(bx_address task_struct_head) {
    if (task_struct_head == 0UL) return; 
    bx_address task = task_struct_head;
    do {
        Task* task_ptr = task_manager.add_task(0, task);

        printf("Task at %lx PID: %d, Kernel Thread: %d, Hypervisor Thread: %d, Userspace VMM: %d, Comm: %s, CR3: %lx, PGD: %lx, flags: %x, stack: %lx, RIP: %lx\n",
               task, task_ptr->pid, task_ptr->kernel_task, task_ptr->hypervisor_task, task_ptr->userspace_vmm_task, task_ptr->comm,
               task_ptr->cr3, task_ptr->pgd, task_ptr->flags, task_ptr->stack, task_ptr->get_pt_regs_rip());

        task = task_ptr->next;
    } while (task != task_struct_head);
}

TaskManager::TaskManager(){
    current_task = 0;
}

TaskManager::~TaskManager(){
    return;
}

Task* TaskManager::get_task(bx_address task_addr){
    if (!task_addr) return NULL;
    if (task_map.contains(task_addr)){
        return task_map[task_addr];
    }
    return NULL;
}

bx_address TaskManager::get_current_task_bx_addr(unsigned cpu){
    if (!current_task) {
        current_task = sym_to_addr("vmlinux", "current_task");
    }

    bx_address taskpp = BX_CPU(cpu)->get_laddr(BX_SEG_REG_GS, current_task);
    // check whether GS==0
    if (taskpp == current_task) return 0;

    bx_address taskp;
    bx_kernel_read(cpu, taskpp, &taskp, sizeof(taskp));
    return taskp;
}

Task* TaskManager::get_current_task(unsigned cpu){
    // only in kernel mode, GS is not 0
    if (BX_CPU(cpu)->get_cpl() == 0){
        bx_address current_task_bx_addr = get_current_task_bx_addr(cpu);
        if (!current_task_bx_addr) return NULL;
        Task* current_task_fuzz = get_task(current_task_bx_addr);
        if (!current_task_fuzz) {
            return add_task(cpu, current_task_bx_addr);
        } else {
            return current_task_fuzz;
        }
    }
    else {
        if (user_task_map.contains(BX_CPU(cpu)->cr3 >> PAGE_SHIFT))
            return user_task_map[BX_CPU(cpu)->cr3 >> PAGE_SHIFT];
        else
            return NULL;
    }
}

Task* TaskManager::get_hypervisor_task(bx_address task_addr){
    if (hypervisor_task_map.contains(task_addr)){
        return hypervisor_task_map.at(task_addr);
    }
    return NULL;
}

Task* TaskManager::add_task(unsigned cpu, bx_address task_addr){
    Task* already_in = get_task(task_addr);
    if (!already_in){
        Task* new_task = alloca_task(cpu, task_addr);
        if (!new_task) return NULL;
        if (!new_task->kernel_task){
            // if new_task is a userspace task, index it by CR3 as well
            bx_address index = new_task->cr3 >> PAGE_SHIFT;
            if (user_task_map.find(index) == user_task_map.end()) {
                user_task_map[index] = new_task;
                printf("add_task: index task %s by %lx, flags %x\n", new_task->comm, index, new_task->flags);
            }
        } 
        if (strstr(new_task->comm, "/KVM") != NULL) {
            new_task->CPU_KVM = true;
            new_task->kernel_task = 1;
        }
        for (auto sig : hypervisor_task_signatures) {
            if (strstr(new_task->comm, sig.c_str()) != NULL) {
                new_task->hypervisor_task = 1;
                printf("add_task: mark hypervisor task %s\n", new_task->comm);
                break;
            }
        }
        task_map[task_addr] = new_task;
        return new_task;
    }
    return already_in;
}

Task* TaskManager::add_task(Task* task_addr){
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

Task* TaskManager::add_hypervisor_task(bx_address task_addr){
    Task* already_in = get_hypervisor_task(task_addr);
    if (!already_in){
        Task* new_task = add_task(0, task_addr);
        hypervisor_task_map[task_addr] = new_task;
        return new_task;
    }
    return already_in;
}

void Task::dump_regs() {
    struct pt_regs* regs = get_regs();
    printf("RIP: %lx, CS: %lx, EFLAGS: %lx, RSP: %lx, SS: %lx\n",
           regs->rip, regs->cs, regs->eflags, regs->rsp, regs->ss);
    printf("RAX: %lx, RBX: %lx, RCX: %lx, RDX: %lx\n",
           regs->rax, regs->rbx, regs->rcx, regs->rdx);
    printf("RDI: %lx, RSI: %lx, RBP: %lx\n",
           regs->rdi, regs->rsi, regs->rbp);
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

Task* TaskManager::alloca_task(unsigned cpu, bx_address task_addr){
    uint8_t *task_buf = (uint8_t*)malloc(TASK_SIZE);
    if (!task_buf){
        printf("Error: failed to allocate task_buf\n");
        return NULL;
    };
    if (read_task_struct(cpu, task_addr, task_buf, TASK_SIZE) < 0){
        printf("Error: failed to read task struct from guest memory\n");
        free(task_buf);
        return NULL;
    }
    Task* new_task = new Task();
    if (task_buf_to_task(cpu, task_buf, new_task) < 0){
        printf("Error: failed to convert task buf to task\n");
        free(task_buf);
        delete new_task;
        return NULL;
    }
    new_task->vaddr = task_addr;
    free(task_buf);
    return new_task;
}

Task* TaskManager::get_task_by_cr3(bx_address CR3) {
    auto index = CR3 >> PAGE_SHIFT;
    if (user_task_map.contains(index)) {
        return user_task_map[index];
    } else {
        return nullptr;
    }
}

int TaskManager::get_pid(bx_address CR3) {
    auto index = CR3 >> PAGE_SHIFT;
    if (user_task_map.contains(index)) {
        return user_task_map[index]->pid;
    } else {
        return 0;
    }
}

unsigned long TaskManager::get_cr3(int pid) {
    for (auto it : task_map){
        if (it.second->pid == pid) {
            return it.second->cr3;
        }
    }
    return 0;
}
