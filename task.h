#ifndef TASK_H
#define TASK_H

#include <cstdint>
#include <string>
#include <tsl/robin_map.h>
#include <tsl/robin_set.h>
#include "bochs.h"
#include "cpu/cpu.h"

struct fuzz_task_struct {
    int pid;             /* Process ID */
    int kernel_thread; /* Is this a kernel thread? */
    int hypervisor_thread; /* Is this a hypervisor thread? */
    char comm[16];       /* Process name */
    unsigned long cr3;  /* CR3 register */
    unsigned long pgd;  /* Page Global Directory */
};

static std::string hypervisor_signatures[] = {
    "qemu-system",
    "vbox",
    "kvm",
    "vhost"
};

extern tsl::robin_map<unsigned long, struct fuzz_task_struct*> task_map;
extern tsl::robin_set<struct fuzz_task_struct*> hypervisor_tasks;

/* functions to read structures from bx VM */
int read_task_struct(bx_address task_struct, void* buf, size_t len);
int read_mm_struct(bx_address mm_struct, void* buf, size_t len);
int task_buf_to_fuzz_task(const uint8_t* task_buf, fuzz_task_struct& fuzz_task);
unsigned long pgd2cr3(unsigned long pgd);

void iterate_tasks(bx_address task_struct_head);

bool is_hypervisor_task(unsigned long cr3);
struct fuzz_task_struct* get_task_by_cr3(unsigned long cr3);

/* macros for operating struct task_struct */
/* kernel version 6.0.32 */
#define PAGE_SHIFT 12

#define TASK_SIZE 0x2640
#define TASK_OFFSET_MM 0x8e0
#define TASK_OFFSET_ACTIVE_MM 0x8e8
#define TASK_OFFSET_TASKS 0x890
#define TASK_OFFSET_PID 0x970
#define TASK_OFFSET_COMM 0xba0
#define TASK_OFFSET_NEXT (TASK_OFFSET_TASKS + 0x0)
#define TASK_OFFSET_PREV (TASK_OFFSET_TASKS + sizeof(unsigned long))

#define task_next(ts) (*(unsigned long*)((unsigned long)ts + TASK_OFFSET_NEXT) - TASK_OFFSET_TASKS)
#define task_prev(ts) (*(unsigned long*)((unsigned long)ts + TASK_OFFSET_PREV) - TASK_OFFSET_TASKS)
#define task_mm(ts) (*(unsigned long*)((unsigned long)ts + TASK_OFFSET_MM))
#define task_active_mm(ts) (*(unsigned long*)((unsigned long)ts + TASK_OFFSET_ACTIVE_MM))
#define task_pid(ts) (*(int*)((unsigned long)ts + TASK_OFFSET_PID))
#define task_comm(ts) ((char*)((unsigned long)ts + TASK_OFFSET_COMM))

/* macros for operating struct mm */
#define MM_SIZE 0x440
#define MM_OFFSET_PGD 0x48
#define MM_OFFSET_ARG_START 0x130
#define MM_OFFSET_ARG_END 0x138

#define mm_pgd(mm) (*(unsigned long*)((unsigned long)mm + MM_OFFSET_PGD))
#define mm_arg_start(mm) (*(unsigned long*)((unsigned long)mm + MM_OFFSET_ARG_START))
#define mm_arg_end(mm) (*(unsigned long*)((unsigned long)mm + MM_OFFSET_ARG_END))

#endif