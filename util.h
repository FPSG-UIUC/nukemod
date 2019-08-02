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

void append(struct nuke_info_t **head, struct nuke_info_t *new_node);
void arbitrarily_cause_page_fault(pte_t **ptepp, unsigned long addr);
int do_page_walk(struct mm_struct *mm, uint64_t address, pte_t **ptepp, spinlock_t **ptlp);
void store_nuked_address(struct nuke_info_t **head, uint64_t address);
void clean_up_stored_addresses(struct nuke_info_t **head);

#define RESERVED_BIT (1UL<<50)

#endif
