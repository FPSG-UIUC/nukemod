#include <asm/apic.h>
#include <asm/cache.h>
#include <asm/cacheflush.h>
#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include <asm/uv/uv.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hrtimer.h>
#include <linux/hugetlb.h>
#include <linux/init.h>
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
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/syscalls.h>
#include <linux/timer.h>

#include "util.h"

MODULE_LICENSE("GPL v2");

//region List utility functions
//---------------------------------------------------------------------------------------

void append(struct nuke_info_t **head, struct nuke_info_t *new_node)
{
	struct nuke_info_t *cursor;
	new_node->next = NULL; // important

	/* new_node becomes head if head is empty */
	if (*head == NULL) {
		*head = new_node;
		return;
	}

	/* go to the last node */
	cursor = *head;
	while(cursor->next != NULL)
		cursor = cursor->next;

	/* append new node */
	cursor->next = new_node;
}

//---------------------------------------------------------------------------------------
//endregion

//region Nukemod utility functions
//---------------------------------------------------------------------------------------

static inline void my_flush_tlb_singlepage(unsigned long addr)
{
    asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
}

void arbitrarily_cause_page_fault(pte_t **ptepp, unsigned long addr)
{
	pte_t pte, temp_pte;
    pte = **ptepp;
    if((pte_flags(pte) & _PAGE_PRESENT)) {
        temp_pte = pte_clear_flags(pte, _PAGE_PRESENT);
        temp_pte = pte_set_flags(temp_pte, _PAGE_PROTNONE);
        set_pte(*ptepp, temp_pte);
        my_flush_tlb_singlepage(addr);
    }
}

int do_page_walk(struct mm_struct *mm, uint64_t address, pte_t **ptepp, spinlock_t **ptlp)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
		pr_info("do_page_walk: pgd_offset failed\n");
		goto out;
	}

	pud = pud_offset(pgd, address);
	if (pud_none(*pud) || unlikely(pud_bad(*pud))) {
		pr_info("do_page_walk: pud_offset failed\n");
		goto out;
	}

	pmd = pmd_offset(pud, address);
	VM_BUG_ON(pmd_trans_huge(*pmd)); // We do not handle huge pages for now

    if (!pmd_none(*pmd) && (pmd_val(*pmd) & (_PAGE_PRESENT|_PAGE_PSE)) != _PAGE_PRESENT) {
		pr_info("HUGE PAGE!\n");
	}

	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) {
		pr_info("do_page_walk: pmd_offset failed\n");
		goto out;
	}

	*ptepp = pte_offset_map_lock(mm, pmd, address, ptlp);
	if (!(*ptepp)) {
		pr_info("do_page_walk: pte_offset_map_lock failed\n");
		goto out;
	}

	if (!pte_present(**ptepp)) {
		pr_info("do_page_walk: page is not present, aborting.\n");
		goto unlock;
	}

    arbitrarily_cause_page_fault(ptepp, address);

	pte_unmap_unlock(*ptepp, *ptlp);

	return 0;
unlock:
	pte_unmap_unlock(*ptepp, *ptlp);
out:
	return -EINVAL;
}

void store_nuked_address(struct nuke_info_t **head, uint64_t address)
{
	spinlock_t *ptlp;

	// Fill the struct with the information about the address
	struct nuke_info_t *node = kmalloc(sizeof(*node), GFP_KERNEL);

	node->nuke_virtual_addr = address;
	node->next = NULL;
	node->nuke_mm = current->mm;

	// Flush the item from the TLB
	// Clear the present bit so that we know we will have a page fault
	do_page_walk(node->nuke_mm, address, &(node->nuke_pte), &ptlp);
	
	// Append the struct to the list
	append(head, node);
}

void clean_up_stored_addresses(struct nuke_info_t **head)
{
	// Clean up
	struct nuke_info_t *curr, *tmp;
	curr = *head;
	while(curr != NULL) {
		tmp = curr;
		curr = curr->next;
		kfree(tmp);
	}
}

//---------------------------------------------------------------------------------------
//endregion
