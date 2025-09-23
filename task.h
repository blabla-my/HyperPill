#ifndef TASK_H
#define TASK_H

#include "config.h"
#include "vendor/include/config.h"
#include <cstdint>
#include <string>
#include <tsl/robin_map.h>
#include <tsl/robin_set.h>
#include "bochs.h"
#include "cpu/cpu.h"
#include <asm/ptrace.h>

class Task {
public:
    Task() : vaddr(0), pid(0), kernel_task(false), hypervisor_task(false), userspace_vmm_task(false) {
        memset(comm, 0, sizeof(comm));
        cr3 = 0;
        pgd = 0;
        next = 0;
        prev = 0;
        stack = 0;
        flags = 0;
    }

    int pid;             /* Process ID */
    int kernel_task; /* Is this a kernel task? */
    int hypervisor_task; /* Is this a hypervisor task? */
    int userspace_vmm_task; /* Is this a userspace VMM task? E.g., QEMU, VirtualBox, etc. */
    char comm[16];       /* Process name */
    unsigned long cr3;  /* CR3 register */
    unsigned long pgd;  /* Page Global Directory */
    bx_address vaddr;   /* Kernel space address of the task */
    bx_address next;
    bx_address prev;
    bx_address stack;
    unsigned int flags;

    bool CPU_KVM;
    
    struct pt_regs regs;
    
    bool is_hypervisor_task() const {
        return this->hypervisor_task!=0;
    }
    bool is_userspace_vmm_task() const {
        return this->hypervisor_task && not this->kernel_task;
    }
    struct pt_regs* get_regs() {
        return &this->regs;
    }
    bx_address get_pt_regs_rip() {
        return this->regs.rip;
    }
    void dump_regs();
};

/* functions to read structures from bx VM */
int read_task_struct(bx_address task_struct, void* buf, size_t len);
int read_mm_struct(bx_address mm_struct, void* buf, size_t len);
int read_pt_regs(bx_address pt_regs_addr, struct pt_regs* regs);
int task_buf_to_task(const uint8_t* task_buf, Task* task);
unsigned long pgd2cr3(unsigned long pgd);

void iterate_tasks(bx_address task_struct_head);

/* macros for operating struct task_struct */
/* kernel version 6.0.32 */
#define PAGE_SHIFT 12
#define PAGE_NUM(x) (x>>PAGE_SHIFT)

/* copied from linx/sched.h */
/*
 * Per process flags
 */
#define PF_KTHREAD		0x00200000	/* I am a kernel thread */
#define PF_VCPU			0x00000001	/* I'm a virtual CPU */
#define PF_IDLE			0x00000002	/* I am an IDLE thread */
#define PF_EXITING		0x00000004	/* Getting shut down */
#define PF_POSTCOREDUMP		0x00000008	/* Coredumps should ignore this task */
#define PF_IO_WORKER		0x00000010	/* Task is an IO worker */
#define PF_WQ_WORKER		0x00000020	/* I'm a workqueue worker */
#define PF_FORKNOEXEC		0x00000040	/* Forked but didn't exec */
#define PF_MCE_PROCESS		0x00000080      /* Process policy on mce errors */
#define PF_SUPERPRIV		0x00000100	/* Used super-user privileges */
#define PF_DUMPCORE		0x00000200	/* Dumped core */
#define PF_SIGNALED		0x00000400	/* Killed by a signal */
#define PF_MEMALLOC		0x00000800	/* Allocating memory to free memory. See memalloc_noreclaim_save() */
#define PF_NPROC_EXCEEDED	0x00001000	/* set_user() noticed that RLIMIT_NPROC was exceeded */
#define PF_USED_MATH		0x00002000	/* If unset the fpu must be initialized before use */
#define PF_USER_WORKER		0x00004000	/* Kernel thread cloned from userspace thread */
#define PF_NOFREEZE		0x00008000	/* This thread should not be frozen */
#define PF_KCOMPACTD		0x00010000	/* I am kcompactd */
#define PF_KSWAPD		0x00020000	/* I am kswapd */
#define PF_MEMALLOC_NOFS	0x00040000	/* All allocations inherit GFP_NOFS. See memalloc_nfs_save() */
#define PF_MEMALLOC_NOIO	0x00080000	/* All allocations inherit GFP_NOIO. See memalloc_noio_save() */
#define PF_LOCAL_THROTTLE	0x00100000	/* Throttle writes only against the bdi I write to,
						 * I am cleaning dirty pages from some other bdi. */
#define PF_KTHREAD		0x00200000	/* I am a kernel thread */
#define PF_RANDOMIZE		0x00400000	/* Randomize virtual address space */
#define PF__HOLE__00800000	0x00800000
#define PF__HOLE__01000000	0x01000000
#define PF__HOLE__02000000	0x02000000
#define PF_NO_SETAFFINITY	0x04000000	/* Userland is not allowed to meddle with cpus_mask */
#define PF_MCE_EARLY		0x08000000      /* Early kill for mce process policy */
#define PF_MEMALLOC_PIN		0x10000000	/* Allocations constrained to zones which allow long term pinning.
						 * See memalloc_pin_save() */
#define PF_BLOCK_TS		0x20000000	/* plug has ts that needs updating */
#define PF__HOLE__40000000	0x40000000
#define PF_SUSPEND_TASK		0x80000000      /* This thread called freeze_processes() and should not be frozen */

/* task_struct member offset */
#define TASK_SIZE 0x2640
#define TASK_OFFSET_MM 0x8e0
#define TASK_OFFSET_ACTIVE_MM 0x8e8
#define TASK_OFFSET_TASKS 0x890
#define TASK_OFFSET_PID 0x970
#define TASK_OFFSET_COMM 0xba0
#define TASK_OFFSET_NEXT (TASK_OFFSET_TASKS + 0x0)
#define TASK_OFFSET_PREV (TASK_OFFSET_TASKS + sizeof(unsigned long))
#define TASK_OFFSET_FLAGS 0x2c //unsigned int
#define TASK_OFFSET_STACK 0x20 //void *

#define task_field(ts,_off,_type) *(_type*)((unsigned long)ts+_off)

#define task_next(ts) (*(unsigned long*)((unsigned long)ts + TASK_OFFSET_NEXT) - TASK_OFFSET_TASKS)
#define task_prev(ts) (*(unsigned long*)((unsigned long)ts + TASK_OFFSET_PREV) - TASK_OFFSET_TASKS)
// #define task_mm(ts) (*(unsigned long*)((unsigned long)ts + TASK_OFFSET_MM))
// #define task_active_mm(ts) (*(unsigned long*)((unsigned long)ts + TASK_OFFSET_ACTIVE_MM))
// #define task_pid(ts) (*(int*)((unsigned long)ts + TASK_OFFSET_PID))
#define task_comm(ts) ((char*)((unsigned long)ts + TASK_OFFSET_COMM))

#define task_mm(ts) task_field(ts,TASK_OFFSET_MM,unsigned long)
#define task_active_mm(ts) task_field(ts,TASK_OFFSET_ACTIVE_MM,unsigned long)
#define task_pid(ts) task_field(ts,TASK_OFFSET_PID,int)
#define task_flags(ts) task_field(ts,TASK_OFFSET_FLAGS,unsigned int)
#define task_stack(ts) task_field(ts,TASK_OFFSET_STACK,unsigned long)
#define PAGE_SIZE (0x1000)
#define THREAD_SIZE (PAGE_SIZE << 2)
#define TOP_OF_KERNEL_STACK_PADDING 0
#define task_pt_regs(task) \
({									\
	unsigned long __ptr = (unsigned long)task_stack(task);	\
	__ptr += THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;		\
	((struct pt_regs *)__ptr) - 1;					\
})

/* macros for operating struct mm */
#define MM_SIZE 0x440
#define MM_OFFSET_PGD 0x48
#define MM_OFFSET_ARG_START 0x130
#define MM_OFFSET_ARG_END 0x138

#define mm_pgd(mm) (*(unsigned long*)((unsigned long)mm + MM_OFFSET_PGD))
#define mm_arg_start(mm) (*(unsigned long*)((unsigned long)mm + MM_OFFSET_ARG_START))
#define mm_arg_end(mm) (*(unsigned long*)((unsigned long)mm + MM_OFFSET_ARG_END))


/* Class for task */
class TaskManager {
public:
    TaskManager();
    ~TaskManager();
    
    Task* get_task(bx_address task_addr);
    Task* get_task_by_cr3(unsigned long CR3);
    Task* get_current_task();
    bx_address get_current_task_bx_addr();
    Task* get_hypervisor_task(bx_address task_addr);
    Task* add_task(bx_address task_addr);
    Task* add_task(Task* task_addr); //we should never allocate a task out of TaskManager.
    Task* add_hypervisor_task(bx_address task_addr);
    bool has_task(bx_address task_addr);
    bool del_task(bx_address task_addr);
    bool has_hypervisor_task(bx_address task_addr);
    int get_pid(unsigned long CR3);
    unsigned long get_cr3(int pid);
    // bool hypervisor_task(Task* task_addr);

private:
    tsl::robin_map<bx_address, Task*> task_map;
    tsl::robin_map<bx_address, Task*> user_task_map;
    tsl::robin_map<bx_address, Task*> hypervisor_task_map;
    bx_address current_task;

    Task* alloca_task(bx_address task_addr);
    // bool add_hypervisor_task(Task* task_addr);
    // bool has_task(Task* task_addr);
};

extern TaskManager task_manager;

#endif
