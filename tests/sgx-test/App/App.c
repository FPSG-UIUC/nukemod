#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <pwd.h>

#define MAX_PATH FILENAME_MAX
#define CYCLES uint64_t

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include "../../../nuke_mod.h"

//region SGX setup functions
//---------------------------------------------------------------------------------------

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

//---------------------------------------------------------------------------------------
//endregion

//region Microscope functions
//---------------------------------------------------------------------------------------

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

//---------------------------------------------------------------------------------------
//endregion

//region Ocalls
//---------------------------------------------------------------------------------------

int file_desc = 0;
CYCLES begin, end;
CYCLES total_latency = 0;

/* OCall setup */
void ocall_setup_timing(void)
{
    total_latency = 0;
}

/* OCall setup nuke */
void ocall_setup_nuke(void* addr)
{
    char buffer[80], *msg = NULL;

    // Write the start of nuke_addr into the buffer
	sprintf(buffer, "%p", addr);
	msg = buffer;

	// Send nuke_addr to ioctl device in the kernel
	ioctl_set_msg(file_desc, msg, NUKE_ADDR);
}

/* OCall start timing */
void ocall_begin_measurement(void)
{
    begin = start_time();
}

/* OCall nuke and start timing */
void ocall_nuke_and_begin_measurement(void)
{
    // Tell the kernel to make this load take a longer time
	ioctl_set_msg(file_desc, NULL, LONG_LATENCY);
    begin = start_time();
}

/* OCall end timing */
void ocall_finish_measurement(void)
{
    end = stop_time();
    total_latency += end - begin;
}

/* OCall print result */
void ocall_print_result(int repetitions)
{
    printf("Latency: %" PRIu64 " cycles\n", total_latency / repetitions);
}

/* OCall print string */
void ocall_print_string(const char *str)
{
    printf("%s", str);
}

//---------------------------------------------------------------------------------------
//endregion

int main(int argc, char *argv[])
{
    /* Avoid warning about unused argc argv */
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

    /* Open microscope ioctl device from kernel */
	file_desc = open(DEVICE_FILE_NAME_PATH, 0);
	if (file_desc < 0) {
		printf("Can't open device file: %s\n", DEVICE_FILE_NAME_PATH);
		exit(-1);
	}

    /* Do stuff */
    sgx_status_t ret = ecall_test_latencies(global_eid);
    if (ret != SGX_SUCCESS)
        abort();

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    return 0;
}

