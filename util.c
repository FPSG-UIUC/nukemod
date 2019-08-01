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

//region Microscope utility functions
//---------------------------------------------------------------------------------------

int do_page_walk(struct mm_struct *mm, uint64_t address, pte_t **ptepp, spinlock_t **ptlp)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	pr_info("A");

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
		pr_info("do_page_walk: pgd_offset failed");
		goto out;
	}

	pr_info("B");

	pud = pud_offset(pgd, address);
	if (pud_none(*pud) || unlikely(pud_bad(*pud))) {
		pr_info("do_page_walk: pud_offset failed");
		goto out;
	}

	pr_info("C");

	pmd = pmd_offset(pud, address);
	VM_BUG_ON(pmd_trans_huge(*pmd)); // We do not handle huge pages for now
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) {
		pr_info("do_page_walk: pmd_offset failed");
		goto out;
	}

	pr_info("D");

	*ptepp = pte_offset_map_lock(mm, pmd, address, ptlp);
	if (!(*ptepp)) {
		pr_info("do_page_walk: pte_offset_map_lock failed");
		goto out;
	}

	pr_info("E");

	if (!pte_present(**ptepp)) {
		pr_info("do_page_walk: page is not present, aborting.");
		goto unlock;
	}

	pr_info("F");

	**ptepp = pte_clear_flags(**ptepp, _PAGE_PRESENT);
	__flush_tlb_single(address);

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

	pr_info("1");

	// Fill the struct with the information about the address
	struct nuke_info_t *node = kmalloc(sizeof(*node), GFP_KERNEL);

	pr_info("2");

	node->nuke_virtual_addr = address;
	node->next = NULL;
	node->nuke_mm = current->mm;

	pr_info("3");

	// Flush the item from the TLB
	// Clear the present bit so that we know we will have a page fault
	do_page_walk(node->nuke_mm, address, &(node->nuke_pte), &ptlp);

	pr_info("4");
	
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
