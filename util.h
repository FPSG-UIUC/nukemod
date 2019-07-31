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

struct nuke_info_t {
	uint64_t nuke_virtual_addr; // virtual address of the data we are monitoring
	struct mm_struct *nuke_mm;  // mm_struct of the victim
	pte_t *nuke_pte;			      // pte of the nuke virtual address
	struct nuke_info_t *next;
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

static void append(struct nuke_info_t **head, struct nuke_info_t *new_node);
int do_page_walk(struct mm_struct *mm, uint64_t address, pte_t **ptepp, spinlock_t **ptlp);
void store_nuked_address(struct nuke_info_t **head, uint64_t address);
void clean_up_stored_addresses(struct nuke_info_t **head);

/******************************************************/
#endif
