#ifndef __TPM2_DRIVER_H__
#define __TPM2_DRIVER_H__

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/list.h>
#include <linux/sched/signal.h>
#include <linux/timer.h>

#include <tpm2_axiado.h> // Include our custom header

// Structs for driver queues
typedef struct tpm2_op_driver_request {
    struct tpm2_op_request op_request;
    struct list_head list;
} tpm2_op_driver_request;

typedef struct tpm2_op_driver_response {
    struct tpm2_op_response op_response;
    struct list_head list;
} tpm2_op_driver_response;

// Helper methods for dealing with these structs
int build_driver_request(char *buf, size_t len, tpm2_op_driver_request *request);
int build_driver_get_random_response(tpm2_op_driver_request *request, TPM2B_DIGEST *digest, tpm2_op_driver_response *response);

uint8_t* create_command_buffer_from_driver_request(tpm2_op_driver_request *request);
uint8_t* create_command_buffer_from_driver_response(tpm2_op_driver_response *response);

void dump_driver_request(tpm2_op_driver_request *request);
void dump_op_request(tpm2_op_request *op_request);

void dump_driver_response(tpm2_op_driver_response *response);
void dump_op_response(tpm2_op_response *op_response);

uint16_t get_command_tag(tpm2_op_driver_request *request);
uint32_t get_command_size(tpm2_op_driver_request *request);
uint32_t get_command_code(tpm2_op_driver_request *request);
uint32_t get_post_header_request_bytes(tpm2_op_driver_request *request);
uint32_t get_post_header_response_bytes(tpm2_op_driver_response *response);

// Command handlers
uint32_t handle_tpm20_request_locked(tpm2_op_driver_request *request);
uint32_t handle_tpm20_cc_get_random_locked(tpm2_op_driver_request *request);
uint32_t handle_tpm20_cc_get_capability_locked(tpm2_op_driver_request *request);
uint32_t handle_tpm20_cc_get_capability_algorithms_locked(tpm2_op_driver_request *request, uint32_t property_count_cpu);
uint32_t handle_tpm20_cc_start_auth_session_locked(tpm2_op_driver_request *request);

uint32_t handle_tpm20_cc_failure_locked(tpm2_op_driver_request *request, uint32_t response_code);

// TPM20 read handler
ssize_t handle_tpm20_read_locked(char *data_buf, size_t len);
ssize_t handle_tpm20_write_locked(char *data_buf, size_t len);

// Axiado-specific read (client request) handler
ssize_t handle_ax_tpm20_read_locked(char *data_buf, size_t len);
ssize_t handle_ax_tpm20_write_locked(char *data_buf, size_t len);

#endif
