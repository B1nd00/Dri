#ifndef __TPM2_AXIADO_H__
#define __TPM2_AXIADO_H__

// We need copies of these files
#include "tss2_tpm2_types.h"
#ifndef AXIADO_KERNEL
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "tss2_endian.h"
# else
#include <linux/kernel.h>
#include <linux/module.h>
#endif

// Invent a 2-byte tag that is special for Axiado
#define TPM2_ST_AXIADO  ((TPM2_ST) 0xEEEE) // BE and cpu values are the same

// Invent a few new codes beyond the defined range for our own purposes.
// We'll use the same TPM20_Header_In struct as the preamble for TCU commands
#define TPM2_CC_INVALID               ((TPM2_CC) TPM2_CC_Vendor_TCG_Test + 1)
#define TPM2_CC_AX_TCU_PRIV_READ      ((TPM2_CC) TPM2_CC_Vendor_TCG_Test + 2)
#define TPM2_CC_AX_TCU_PRIV_WRITE     ((TPM2_CC) TPM2_CC_Vendor_TCG_Test + 3)

// Invent special return values so we can signal whether to put a calling process to sleep
#define MUST_SLEEP 0xCCCC

// Key structs
#pragma pack(push, 1)
 typedef struct _tpm20_header_in {
   TPM2_ST tag;
   UINT32 command_size;
   UINT32 command_code;
 } tpm20_header_in;

 typedef struct _tpm20_header_out {
   TPM2_ST tag;
   UINT32 response_size;
   UINT32 response_code;
 } tpm20_header_out;

typedef struct tpm2_op_request {
    tpm20_header_in header;
    pid_t owner_pid;
    uint8_t *buf;
} tpm2_op_request;

typedef struct tpm2_op_response {
    tpm20_header_out header;
    pid_t owner_pid;
    uint32_t command_code_cpu;
    uint32_t bytes_consumed; // Support partial reads
    uint8_t *buf;
} tpm2_op_response;
#pragma pack(pop)

#ifndef AXIADO_KERNEL
#define tpm2_be16_to_cpu BE_TO_HOST_16
#define tpm2_be32_to_cpu BE_TO_HOST_32
#define tpm2_be64_to_cpu BE_TO_HOST_64

#define tpm2_cpu_to_be16 HOST_TO_BE_16
#define tpm2_cpu_to_be32 HOST_TO_BE_32
#define tpm2_cpu_to_be64 HOST_TO_BE_64
#else
#define tpm2_be16_to_cpu be16_to_cpu
#define tpm2_be32_to_cpu be32_to_cpu
#define tpm2_be64_to_cpu be64_to_cpu

#define tpm2_cpu_to_be16 cpu_to_be16
#define tpm2_cpu_to_be32 cpu_to_be32
#define tpm2_cpu_to_be64 cpu_to_be64
#endif

// Shared common routines used in kernel driver and userspace utilities
uint16_t get_op_request_command_tag(tpm2_op_request *op_request);
uint32_t get_op_request_command_size(tpm2_op_request *op_request);
uint32_t get_op_request_command_code(tpm2_op_request *op_request);
uint32_t get_op_request_post_header_request_bytes(tpm2_op_request *op_request);

uint16_t get_op_response_command_tag(tpm2_op_response *op_response);
uint32_t get_op_response_response_size(tpm2_op_response *op_response);
uint32_t get_op_response_response_code(tpm2_op_response *op_response);
uint32_t get_op_response_post_header_response_bytes(tpm2_op_response *op_response);


// Common routines for marshalling and unmarshalling. We're writing our own instead of using macros in tpm2_mu.h
// mainly because as macros they are:
// 1) hard to debug and
// 2) they don't provide clear examples of how to parse complex types.
// Moreover, we need a library that we can link and reuse from userspace programs and our kernel driver

// Read base types
uint32_t read_uint8(char *buf, uint32_t buf_len, uint32_t *offset, uint8_t *ret_val);
uint32_t read_uint16(char *buf, uint32_t buf_len, uint32_t *offset, uint16_t *ret_val);
uint32_t read_uint32(char *buf, uint32_t buf_len, uint32_t *offset, uint32_t *ret_val);
uint32_t read_uint64(char *buf, uint32_t buf_len, uint32_t *offset, uint64_t *ret_val);

// read aliases for uint8 defined as macros
#define read_tpma_session read_uint8

// reads for all the aliases of uint16_t but defined as macros
#define read_tpm2_alg_id read_uint16
#define read_tpmi_alg_public read_uint16
#define read_tpmi_alg_hash read_uint16
#define read_tpmi_alg_public read_uint16
#define read_tpmi_alg_sym_object read_uint16
#define read_tpmi_alg_sym_mode read_uint16
#define read_tpmi_alg_rsa_scheme read_uint16
#define read_tpmi_rsa_key_bits read_uint16
#define read_tpmu_sym_key_bits read_uint16
#define read_tpmu_sym_mode read_uint16

// reads for all aliases of uint32_t but defined as macros
#define read_tpma_object read_uint32
#define read_handle read_uint32

uint32_t read_tpms_authorization_command(char *buf, uint32_t buf_len, uint32_t *offset, TPMS_AUTH_COMMAND *ret_val);
// Alias(es)
#define read_authorization_area read_tpms_authorization_command

// Alias as read_nonce and read_auth since these all resolve to the same type
uint32_t read_tpm2b_digest(char *buf, uint32_t buf_len, uint32_t *offset, TPM2B_DIGEST *ret_val);
// Alias(es): read_nonce, read_auth
#define read_nonce read_tpm2b_digest
#define read_auth read_tpm2b_digest

// Read handles
uint32_t read_handle(char *buf, uint32_t buf_len, uint32_t *offset, TPM2_HANDLE *ret_val);

// Read session
uint32_t read_tpma_session(char *buf, uint32_t buf_len, uint32_t *offset, TPMA_SESSION *ret_val);

// Read sensitive create
uint32_t read_tpm2b_sensitive_create(char *buf, uint32_t buf_len, uint32_t *offset, TPM2B_SENSITIVE_CREATE *ret_val);

// Read public
uint32_t read_tpm2b_public(char *buf, uint32_t buf_len, uint32_t *offset, TPM2B_PUBLIC *ret_val);

// Read rsa parms
uint32_t read_tpms_rsa_parms(char *buf, uint32_t buf_len, uint32_t *offset, TPMS_RSA_PARMS *ret_val);
uint32_t read_tpmt_sym_def_object(char *buf, uint32_t buf_len, uint32_t *offset, TPMT_SYM_DEF_OBJECT *ret_val);
uint32_t read_tpmt_rsa_scheme(char *buf, uint32_t buf_len, uint32_t *offset, TPMT_RSA_SCHEME *ret_val);
uint32_t read_tpm2b_public_key_rsa(char *buf, uint32_t buf_len, uint32_t *offset, TPM2B_PUBLIC_KEY_RSA *ret_val);

uint32_t read_tpm2b_data(char *buf, uint32_t buf_len, uint32_t *offset, TPM2B_DATA *ret_val);
uint32_t read_tpml_pcr_selection(char *buf, uint32_t buf_len, uint32_t *offset, TPML_PCR_SELECTION *ret_val);
uint32_t read_tpms_pcr_selection(char *buf, uint32_t buf_len, uint32_t *offset, TPMS_PCR_SELECTION *ret_val);

#endif
