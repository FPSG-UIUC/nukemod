#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

static bool debug = true;

void print(const char *fmt, ...)
{
	if (debug == true) {
		char buf[BUFSIZ] = {'\0'};
		va_list ap;
		va_start(ap, fmt);
		vsnprintf(buf, BUFSIZ, fmt, ap);
		va_end(ap);
		ocall_print_string(buf);
	}
}

void ecall_test_latencies(void)
{
	volatile uint64_t *nuke_addr = NULL;
	uint64_t i = 0, nuke_size = 512;
	const int repetitions = 100;

	print("Preparing nuke_addr\n");

	// Allocate the memory of nuke_addr so that it is aligned to the page size.
	// That is, the start address of nuke_addr is guaranteed to be a multiple of 4096.
	// This would be to make cache side channels easier.
	nuke_addr = (uint64_t *)memalign(4096, nuke_size * sizeof(uint64_t));

	// Initialize values in the nuke array
	for (i = 0; i < nuke_size; i++) {
		nuke_addr[i] = i;
	}

	print("&nuke_addr[0] = %p\n", &nuke_addr[0]);
	print("Measuring latencies\n");

	// Measure the measurement latency without any load
	ocall_setup_timing();

	for (i = 0; i < repetitions; i++) {
		ocall_begin_measurement();
		ocall_finish_measurement();
	}

	// Report the latency
	ocall_print_result(repetitions);

	// Measure the load latency without microscope
	ocall_setup_timing();

	for (i = 0; i < repetitions; i++) {
		ocall_begin_measurement();
		*nuke_addr;
		ocall_finish_measurement();
	}

	// Report the latency
	ocall_print_result(repetitions);

	// Open microscope ioctl device from kernel
	ocall_setup_nuke(&nuke_addr[0]);

	// Measure the load latency with microscope
	ocall_setup_timing();
	for (i = 0; i < repetitions; i++) {

		// Tell the kernel to make this load take a longer time
		ocall_nuke_and_begin_measurement();
		*nuke_addr;
		ocall_finish_measurement();
	}

	// Report the latency
	// ocall_print_result(repetitions);
}