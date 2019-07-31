/**
 * Compile with:
 * gcc -m64  -O3 victim.c -o victim -lrt
 */

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <time.h>
#include <unistd.h>
#define CYCLES_64 uint64_t

#include "nuke_mod.h"
#include <linux/ioctl.h>
#include <sys/ioctl.h>

#define SHMSZ 4096

volatile char *shared_mem;
int shmid;

int comm_init_shared_memory()
{
	key_t key;
	key = 1313;

	shmid = shmget(key, SHMSZ, SHM_R | SHM_W);
	if (shmid < 0) {
		printf("Victim: shmget failed\n");
		return -1;
	}

	shared_mem = shmat(shmid, NULL, 0);
	if (shared_mem == (char *)-1) {
		perror("Victim: Shared memory attach failure");
		shmctl(shmid, IPC_RMID, NULL);
		return -1;
	}
	return 0;
}

int comm_shutdown_shared_memory()
{
	if (shmdt((const void *)shared_mem) != 0) {
		perror("Victim: Detach failure");
		shmctl(shmid, IPC_RMID, NULL);
		return -1;
	}

	shmctl(shmid, IPC_RMID, NULL);
}

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

CYCLES_64 read_timer();
void busy_fp(double *, double *);
void busy_int(uint64_t *, uint64_t *);
void busy_simd_div(double *, double *);
void busy_fp_noisy(double *, double *);
void busy_int_noisy(uint64_t *, uint64_t *);
void busy_simd_add(double *, double *);

double subnormalfp;
double normalfpa = 100.0;
double normalfpb = 12.0;
uint64_t inta = 100;
uint64_t intb = 45;

double *subnormalfp_ptr = &subnormalfp;
double *normalfpa_ptr = &normalfpa;
double *normalfpb_ptr = &normalfpb;
uint64_t *inta_ptr = &inta;
uint64_t *intb_ptr = &intb;

uint64_t dummy[1000];
uint64_t *dummy_ptr = &dummy[0];

/**
 * victim.c uses shared memory to communicate with attack.c so
 * part of this code is to set that up and is not related to the
 * microscope kernel framework.
 */
int main(int argc, char *argv[])
{
	uint64_t *nuke_addr = NULL;
	volatile char *comm_buffer;
	uint64_t i = 0, nuke_size = 512;
	int ret = 0;
	char buffer[80], *msg = NULL;
	int file_desc = 0;

	if (argc < 2) {
		printf("please provide 1 argument: <mode> [sub_fp, normal_fp, int]\n");
		exit(1);
	}

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

    // Set up a shared memory segment for communication with attack.c
	ret = comm_init_shared_memory();
	if (ret) {
		exit(-1);
	}
	
    comm_buffer = shared_mem;
	// printf("Victim: comm_buffer[0]=%c\n", comm_buffer[0]);

    // Open microscope ioctl device from kernel
	file_desc = open(DEVICE_FILE_NAME_PATH, 0);
	if (file_desc < 0) {
		printf("Can't open device file: %s\n", DEVICE_FILE_NAME_PATH);
		exit(-1);
	}

    // Write the start of nuke_addr into the buffer
	sprintf(buffer, "%p", &nuke_addr[0]);
	msg = buffer;
	//  printf("Nuke addr %s -- %p\n", msg, &nuke_addr[0]);

    // Send nuke_addr to ioctl device in the kernel
	ioctl_set_msg(file_desc, msg, NUKE_ADDR);

	// Construct subnormal floating point integer
	const unsigned long lnDEN[2] = {0x0000001, 0x00000000};
	const double A_DENORMAL = *(double *)lnDEN;
	subnormalfp = A_DENORMAL;

    // Tell the kernel to prepare the page fault for nuke_addr
	ioctl_set_msg(file_desc, msg, PF);

    // Tell attack.c that I am ready
	comm_buffer[0] = 'b';

    // Perform the operations with replay handle and vulnerable code
    // NOTE: This is old commented code
	// if (strcmp("sub_fp", argv[1]) == 0) {
	// 	while (1) {
	// 		busy_fp(subnormalfp_ptr, normalfpa_ptr);
	// 		nuke_addr[0]++; // replay handle
	// 	}

	// } else if (strcmp("normal_fp", argv[1]) == 0) {
	// 	while (1) {
	// 		busy_fp(normalfpb_ptr, normalfpa_ptr);
	// 		nuke_addr[1]++; // replay handle
	// 	}

	// } else if (strcmp("sub_div", argv[1]) == 0) {
	// 	while (1) {
	// 		busy_simd_div(subnormalfp_ptr, normalfpa_ptr);
	// 		nuke_addr[2]++; // replay handle
	// 	}

	// } else 
    if (strcmp("normal_div", argv[1]) == 0) {
		nuke_addr[3]++; // replay handle
		busy_simd_div(normalfpb_ptr, normalfpa_ptr);

	} else if (strcmp("int", argv[1]) == 0) {
		nuke_addr[4]++; // replay handle
		busy_int(inta_ptr, intb_ptr);

	} else if (strcmp("idle", argv[1]) == 0) {
		while (1) {
			nuke_addr[5]++; // replay handle
		}

	} else {
		printf("please provide argument: <mode> [sub_fp, normal_fp, int]; <number of it\n");
		exit(1);
	}

	printf("replay handle %lu,%lu,%lu,%lu,%lu,%lu\n", nuke_addr[0], nuke_addr[1], nuke_addr[2], nuke_addr[3], nuke_addr[4], nuke_addr[5]);

	return 0;
}

inline void busy_fp(double *fpa_ptr, double *fpb_ptr)
{
	asm __volatile__(
		"mov %0, %%rax\n"
		"mov %1, %%rbx\n"
		"movsd (%%rax), %%xmm0\n"
		"movsd (%%rbx), %%xmm1\n"
		"movsd %%xmm1, %%xmm2\n"
		// mulsd: Multiply Scalar Double-Precision Floating-Point Value
		// 128-bit Legacy SSE version: The first source operand
		// and the destination operand are the same.
		// NOTE: Here I make all the destinations differently.
		// While this is unneccessary, since they are false dependency
		"mulsd %%xmm0, %%xmm2\n" // mul_1
		"movsd %%xmm1, %%xmm3\n"
		"mulsd %%xmm0, %%xmm3\n" // mul_2
		"movsd %%xmm1, %%xmm4\n"
		"mulsd %%xmm0, %%xmm4\n" // mul_3
		"movsd %%xmm1, %%xmm5\n"
		"mulsd %%xmm0, %%xmm5\n" // mul_4
		"movsd %%xmm1, %%xmm6\n"
		"mulsd %%xmm0, %%xmm6\n" // mul_5
		"movsd %%xmm1, %%xmm7\n"
		"mulsd %%xmm0, %%xmm7\n" // mul_6
		"movsd %%xmm1, %%xmm8\n"
		"mulsd %%xmm0, %%xmm8\n" // mul_7
		"movsd %%xmm1, %%xmm9\n"
		"mulsd %%xmm0, %%xmm9\n" // mul_8
		"movsd %%xmm1, %%xmm10\n"
		"mulsd %%xmm0, %%xmm10\n" // mul_9
		"movsd %%xmm1, %%xmm11\n"
		"mulsd %%xmm0, %%xmm11\n" // mul_10
		:
		: "m"(fpa_ptr), "m"(fpb_ptr)
		: "%xmm0", "%xmm1", "%xmm2", "memory", "%xmm3", "%xmm4", "%xmm5", "%xmm6",
		  "%xmm7", "%xmm8", "%xmm9", "%xmm10", "%xmm11", "%rax", "%rbx");
}

inline void busy_fp_noisy(double *fpa_ptr, double *fpb_ptr)
{
	asm __volatile__(
		"mov %0, %%rax\n"
		"mov %1, %%rbx\n"
		"mov %2, %%rcx\n"
		"movsd (%%rax), %%xmm0\n"
		"movsd (%%rbx), %%xmm1\n"
		"movsd %%xmm1, %%xmm2\n"
		// mulsd: Multiply Scalar Double-Precision Floating-Point Value
		// 128-bit Legacy SSE version: The first source operand
		// and the destination operand are the same.
		// NOTE: Here I make all the destinations differently.
		// While this is unneccessary, since they are false dependency
		"mulsd %%xmm0, %%xmm2\n" // mul_1
		"movsd %%xmm1, %%xmm3\n"
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"mulsd %%xmm0, %%xmm3\n" // mul_2
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"movsd %%xmm1, %%xmm4\n"
		"mulsd %%xmm0, %%xmm4\n" // mul_3
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"movsd %%xmm1, %%xmm5\n"
		"mulsd %%xmm0, %%xmm5\n" // mul_4
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"movsd %%xmm1, %%xmm6\n"
		"mulsd %%xmm0, %%xmm6\n" // mul_5
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"movsd %%xmm1, %%xmm7\n"
		"mulsd %%xmm0, %%xmm7\n" // mul_6
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"movsd %%xmm1, %%xmm8\n"
		"mulsd %%xmm0, %%xmm8\n" // mul_7
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"movsd %%xmm1, %%xmm9\n"
		"mulsd %%xmm0, %%xmm9\n" // mul_8
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"movsd %%xmm1, %%xmm10\n"
		"mulsd %%xmm0, %%xmm10\n" // mul_9
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"movsd %%xmm1, %%xmm11\n"
		"mulsd %%xmm0, %%xmm11\n" // mul_10
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		"mov (%%rcx), %%rdx\n"
		"inc %%rcx\n"
		:
		: "m"(fpa_ptr), "m"(fpb_ptr), "m"(dummy_ptr)
		: "%xmm0", "%xmm1", "%xmm2", "memory", "%xmm3", "%xmm4", "%xmm5", "%xmm6",
		  "%xmm7", "%xmm8", "%xmm9", "%xmm10", "%xmm11", "%rax", "%rbx", "%rcx",
		  "%rdx");
}

// inline void busy_int(uint64_t *inta_ptr, uint64_t *intb_ptr) {
//
//   asm __volatile__("mov %0, %%rsi\n"
//                    "mov %1, %%rdi\n"
//                    "mov (%%rsi), %%rbx\n"
//                    "mov (%%rdi), %%rcx\n"
//                    // MUL — Unsigned Multiply
//                    // MUL r/m64
//                    // Operand Size Source 1    Source 2    Destination
//                    // Quadword     RAX         r/m64       RDX:RAX
//                    "mov %%rcx, %%rax\n"
//                    "mul %%rbx\n" // mul_2
//                    "mov %%rcx, %%rax\n"
//                    "mul %%rbx\n" // mul_3
//                    "mov %%rcx, %%rax\n"
//                    "mul %%rbx\n" // mul_4
//                    // "mov %%rcx, %%rax\n"
//                    // "mul %%rbx\n" // mul_5
//                    // "mov %%rcx, %%rax\n"
//                    // "mul %%rbx\n" // mul_6
//                    // "mov %%rcx, %%rax\n"
//                    // "mul %%rbx\n" // mul_7
//                    // "mov %%rcx, %%rax\n"
//                    // "mul %%rbx\n" // mul_8
//                    // "mov %%rcx, %%rax\n"
//                    // "mul %%rbx\n" // mul_9
//                    // "mov %%rcx, %%rax\n"
//                    // "mul %%rbx\n" // mul_10
//                    :
//                    : "m"(inta_ptr), "m"(intb_ptr)
//                    : "memory", "%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi");
// }
inline void busy_int(uint64_t *inta_ptr, uint64_t *intb_ptr)
{
	asm __volatile__("mov %0, %%rsi\n"
					 "mov %1, %%rdi\n"
					 "mov (%%rsi), %%rbx\n"
					 "mov (%%rdi), %%rcx\n"
					 // MUL — Unsigned Multiply
					 // MUL r/m64
					 // Operand Size Source 1    Source 2    Destination
					 // Quadword     RAX         r/m64       RDX:RAX
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_1
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_2
					 "mov %%rcx, %%rax\n"
					 // "mul %%rbx\n" // mul_3
					 // "mov %%rcx, %%rax\n"
					 // "mul %%rbx\n" // mul_4
					 // "mov %%rcx, %%rax\n"
					 // "mul %%rbx\n" // mul_5
					 // "mov %%rcx, %%rax\n"
					 // "mul %%rbx\n" // mul_6
					 // "mov %%rcx, %%rax\n"
					 // "mul %%rbx\n" // mul_7
					 // "mov %%rcx, %%rax\n"
					 // "mul %%rbx\n" // mul_8
					 // "mov %%rcx, %%rax\n"
					 // "mul %%rbx\n" // mul_9
					 // "mov %%rcx, %%rax\n"
					 // "mul %%rbx\n" // mul_10
					 :
					 : "m"(inta_ptr), "m"(intb_ptr)
					 : "memory", "%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi");
}

inline void busy_int_noisy(uint64_t *inta_ptr, uint64_t *intb_ptr)
{
	asm __volatile__("mov %0, %%rsi\n"
					 "mov %1, %%rdi\n"
					 "mov (%%rsi), %%rbx\n"
					 "mov (%%rdi), %%rcx\n"
					 "mov %2, %%rsi\n"
					 // MUL — Unsigned Multiply
					 // MUL r/m64
					 // Operand Size Source 1    Source 2    Destination
					 // Quadword     RAX         r/m64       RDX:RAX
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_1
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_2
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_3
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_4
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_5
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_6
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_7
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_8
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_9
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_10
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 "inc %%rsi\n"
					 "mov (%%rsi), %%rdi\n"
					 :
					 : "m"(inta_ptr), "m"(intb_ptr), "m"(dummy_ptr)
					 : "memory", "%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi");
}

inline CYCLES_64 read_timer()
{
	volatile uint64_t t;
	asm __volatile__("lfence\n"
					 // Guaranteed to clear the high-order 32 bits of RAX and RDX.
					 "rdtsc\n"
					 "shlq $32, %%rdx\n"
					 "orq %%rdx, %%rax\n"
					 : "=a"(t)
					 :
					 : "%rdx");
	return t;
}

inline void busy_simd_div(double *fpa_ptr, double *fpb_ptr)
{
	asm __volatile__(
		"mov %0, %%rax\n"
		"mov %1, %%rbx\n"
		"movsd (%%rax), %%xmm0\n"
		"movsd (%%rbx), %%xmm1\n"
		"movsd %%xmm1, %%xmm2\n"
		// divsd: Divide Scalar Double-Precision Floating-Point Value
		// 128-bit Legacy SSE version: The first source operand
		// and the destination operand are the same.
		// NOTE: Here I make all the destinations differently.
		// While this is unneccessary, since they are false dependency
		"divsd %%xmm0, %%xmm2\n" // mul_1
		"movsd %%xmm1, %%xmm3\n"
		"divsd %%xmm0, %%xmm3\n" // mul_2
		"movsd %%xmm1, %%xmm4\n"
		// "divsd %%xmm0, %%xmm4\n" // mul_3
		// "movsd %%xmm1, %%xmm5\n"
		// "divsd %%xmm0, %%xmm5\n" // mul_4
		// "movsd %%xmm1, %%xmm6\n"
		// "divsd %%xmm0, %%xmm6\n" // mul_5
		// "movsd %%xmm1, %%xmm7\n"
		// "divsd %%xmm0, %%xmm7\n" // mul_6
		// "movsd %%xmm1, %%xmm8\n"
		// "divsd %%xmm0, %%xmm8\n" // mul_7
		// "movsd %%xmm1, %%xmm9\n"
		// "divsd %%xmm0, %%xmm9\n" // mul_8
		// "movsd %%xmm1, %%xmm10\n"
		// "divsd %%xmm0, %%xmm10\n" // mul_9
		// "movsd %%xmm1, %%xmm11\n"
		// "divsd %%xmm0, %%xmm11\n" // mul_10
		:
		: "m"(fpa_ptr), "m"(fpb_ptr)
		: "%xmm0", "%xmm1", "%xmm2", "memory", "%xmm3", "%xmm4", "%xmm5",
		  "%xmm6",
		  "%xmm7", "%xmm8", "%xmm9", "%xmm10", "%xmm11", "%rax", "%rbx");
	// : "m"(fpa_ptr), "m"(fpb_ptr)
	// : "%xmm0", "%xmm1", "%xmm2", "memory", "%xmm3", "%rax", "%rbx");
	// : "m"(fpa_ptr), "m"(fpb_ptr)
	// : "%xmm0", "%xmm1", "%xmm2", "memory", "%xmm3", "%rax", "%rbx");
}

inline void busy_simd_add(double *fpa_ptr, double *fpb_ptr)
{
	asm __volatile__(
		"mov %0, %%rax\n"
		"mov %1, %%rbx\n"
		"movsd (%%rax), %%xmm0\n"
		"movsd (%%rbx), %%xmm1\n"
		"movsd %%xmm1, %%xmm2\n"
		// divsd: Divide Scalar Double-Precision Floating-Point Value
		// 128-bit Legacy SSE version: The first source operand
		// and the destination operand are the same.
		// NOTE: Here I make all the destinations differently.
		// While this is unneccessary, since they are false dependency
		"addsd %%xmm0, %%xmm2\n" // mul_1
		"movsd %%xmm1, %%xmm3\n"
		"addsd %%xmm0, %%xmm3\n" // mul_2
		// "movsd %%xmm1, %%xmm4\n"
		// "divsd %%xmm0, %%xmm4\n" // mul_3
		// "movsd %%xmm1, %%xmm5\n"
		// "divsd %%xmm0, %%xmm5\n" // mul_4
		// "movsd %%xmm1, %%xmm6\n"
		// "divsd %%xmm0, %%xmm6\n" // mul_5
		// "movsd %%xmm1, %%xmm7\n"
		// "divsd %%xmm0, %%xmm7\n" // mul_6
		// "movsd %%xmm1, %%xmm8\n"
		// "divsd %%xmm0, %%xmm8\n" // mul_7
		// "movsd %%xmm1, %%xmm9\n"
		// "divsd %%xmm0, %%xmm9\n" // mul_8
		// "movsd %%xmm1, %%xmm10\n"
		// "divsd %%xmm0, %%xmm10\n" // mul_9
		// "movsd %%xmm1, %%xmm11\n"
		// "divsd %%xmm0, %%xmm11\n" // mul_10
		:
		: "m"(fpa_ptr), "m"(fpb_ptr)
		: "%xmm0", "%xmm1", "%xmm2", "memory", "%xmm3", "%xmm4", "%xmm5",
		  "%xmm6",
		  "%xmm7", "%xmm8", "%xmm9", "%xmm10", "%xmm11", "%rax", "%rbx");
	// : "m"(fpa_ptr), "m"(fpb_ptr)
	// : "%xmm0", "%xmm1", "%xmm2", "memory", "%xmm3", "%rax", "%rbx");
	// : "m"(fpa_ptr), "m"(fpb_ptr)
	// : "%xmm0", "%xmm1", "%xmm2", "memory", "%xmm3", "%rax", "%rbx");
}
