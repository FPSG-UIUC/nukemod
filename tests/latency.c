/**
 * Compile with:
 * gcc -m64 -O0 latency.c -o latency
 */

#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <time.h>
#include <unistd.h>
#define CYCLES uint64_t

#include "../nuke_mod.h"
#include <linux/ioctl.h>
#include <sys/ioctl.h>

/*
 * ioctl_set_msg is the interface to the kernel module
 * @file_desc is the file descriptor for the char device
 * @message is the buffer holding the message to transfer
 * @type is the type of ioctl
 */
void ioctl_set_msg(int file_desc, char *message, enum call_type type)
{
	int ret_val;

	switch (type) {
	case MSG:
		ret_val = ioctl(file_desc, IOCTL_SET_MSG, message);
		break;
	case NUKE_ADDR:
		ret_val = ioctl(file_desc, IOCTL_SET_NUKE_ADDR, message);
		break;
	case MONITOR_ADDR:
		ret_val = ioctl(file_desc, IOCTL_SET_MONITOR_ADDR, message);
		break;
	case PF:
		ret_val = ioctl(file_desc, IOCTL_PREP_PF, message);
		break;
	case LONG_LATENCY:
		ret_val = ioctl(file_desc, IOCTL_LONG_LATENCY, message);
		break;
	default:
		printf("ioctl type not found\n");
		ret_val = -1;
		break;
	}

	if (ret_val < 0) {
		printf("ioctl failed:%d\n", ret_val);
		exit(-1);
	}
}

/**
 * This function is modified from:
 *  https://github.com/google/highwayhash/blob/master/highwayhash/tsc_timer.h
 */
CYCLES start_time(void)
{
	CYCLES t;
	asm volatile(
		"lfence\n\t"
		"rdtsc\n\t"
		"shl $32, %%rdx\n\t"
		"or %%rdx, %0\n\t"
		"lfence"
		: "=a"(t) /*output*/
		:
		: "rdx", "memory", "cc");
	return t;
}

/**
 * This function is modified from:
 *  https://github.com/google/highwayhash/blob/master/highwayhash/tsc_timer.h
 */
CYCLES stop_time(void)
{
	CYCLES t;
	asm volatile(
		"rdtscp\n\t"
		"shl $32, %%rdx\n\t"
		"or %%rdx, %0\n\t"
		"lfence"
		: "=a"(t) /*output*/
		:
		: "rcx", "rdx", "memory", "cc");
	return t;
}

/**
 * victim.c uses shared memory to communicate with attack.c so
 * part of this code is to set that up and is not related to the
 * microscope kernel framework.
 */
int main(int argc, char *argv[])
{
	volatile uint64_t *nuke_addr = NULL;
	uint64_t i = 0, nuke_size = 512;
	int ret = 0;
	char buffer[80], *msg = NULL;
	int file_desc = 0;
	const int repetitions = 100;
	CYCLES begin, end;

	printf("Preparing nuke_addr\n");

	// Allocate the memory of nuke_addr so that it is aligned to the page size.
	// That is, the start address of nuke_addr is guaranteed to be a multiple of 4096.
	// This would be to make cache side channels easier.
	ret = posix_memalign((void **)&nuke_addr, 4096, nuke_size * sizeof(uint64_t));
	if (ret < 0) {
		printf("Can't allocate nuke memory: %d\n", ret);
		exit(-1);
	}

	// Initialize values in the nuke array
	for (i = 0; i < nuke_size; i++) {
		nuke_addr[i] = i;
	}

	printf("&nuke_addr[0] = %p\n", &nuke_addr[0]);
	printf("Measuring latencies\n");

	// Measure the measurement latency without any load
	CYCLES total_latency = 0;
	for (i = 0; i < repetitions; i++) {
		begin = start_time();
		end = stop_time();
		total_latency += end - begin;
	}

	// Report the latency
	printf("Latency of just measurement: %" PRIu64 " cycles\n", total_latency / repetitions);

	// Measure the load latency without microscope
	total_latency = 0;
	for (i = 0; i < repetitions; i++) {
		begin = start_time();
		*nuke_addr;
		end = stop_time();
		total_latency += end - begin;
	}

	// Report the latency
	printf("Latency of load without Microscope: %" PRIu64 " cycles\n", total_latency / repetitions);

	// Open microscope ioctl device from kernel
	file_desc = open(DEVICE_FILE_NAME_PATH, 0);
	if (file_desc < 0) {
		printf("Can't open device file: %s\n", DEVICE_FILE_NAME_PATH);
		exit(-1);
	}

	// Write the start of nuke_addr into the buffer
	sprintf(buffer, "%p", &nuke_addr[0]);
	msg = buffer;

	// Send nuke_addr to ioctl device in the kernel
	ioctl_set_msg(file_desc, msg, NUKE_ADDR);

	// Measure the load latency with microscope
	total_latency = 0;
	for (i = 0; i < repetitions; i++) {

		// Tell the kernel to make this load take a longer time
		ioctl_set_msg(file_desc, NULL, LONG_LATENCY);

		begin = start_time();
		*nuke_addr;
		end = stop_time();
		total_latency += end - begin;
	}

	// Report the latency
	printf("Latency of load with Microscope: %" PRIu64 " cycles\n", total_latency / repetitions);

	return 0;
}
