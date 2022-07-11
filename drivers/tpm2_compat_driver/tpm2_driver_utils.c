#include <tpm2_driver.h>

void
dump_driver_request(tpm2_op_driver_request *request) {
    if (!request) {
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Empty driver op request");
    }
    dump_op_request(&request->op_request);
}

void
dump_driver_response(tpm2_op_driver_response *response) {
    if (!response) {
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Empty driver op response");
    }
    dump_op_response(&response->op_response);
}

void dump_op_request(tpm2_op_request *op_request) {
    uint32_t post_header_bytes = 0;

    if (!op_request) {
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Empty op request");
    }

    post_header_bytes = tpm2_be32_to_cpu(op_request->header.command_size) - sizeof(tpm20_header_in);
    printk(KERN_INFO "[AXIADO_TPM2_COMPAT] " \
           "[pid: %d] OP header tag: 0x%x, length: %d, command/ordinal: 0x%x, post-header bytes: %d", \
           op_request->owner_pid,
           tpm2_be16_to_cpu(op_request->header.tag),
           tpm2_be32_to_cpu(op_request->header.command_size),
           tpm2_be32_to_cpu(op_request->header.command_code),
           post_header_bytes);

    // Tag is 16 bits 0x0000
    // Length is 32 bits 0x00000000
    // Command code (ordinal) is 32 bits 0x00000000
}

void
dump_op_response(tpm2_op_response *op_response) {
    uint32_t post_header_bytes = 0;

    if (!op_response) {
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Empty op response");
    }

    post_header_bytes = tpm2_be32_to_cpu(op_response->header.response_size) - sizeof(tpm20_header_out);
    printk(KERN_INFO "[AXIADO_TPM2_COMPAT] " \
           "[pid: %d] OP header tag: 0x%x, length: %d, response code: 0x%x, original command/ordinal: 0x%x, post-header bytes: %d, consumed bytes: %d", \
           op_response->owner_pid,
           tpm2_be16_to_cpu(op_response->header.tag),
           tpm2_be32_to_cpu(op_response->header.response_size),
           tpm2_be32_to_cpu(op_response->header.response_code),
           op_response->command_code_cpu,
           post_header_bytes,
           op_response->bytes_consumed);

}

uint16_t
get_command_tag(tpm2_op_driver_request *request) {
    if (!request) {
        return TPM2_RC_BAD_TAG;
    }

    return tpm2_be16_to_cpu(request->op_request.header.tag);
}

uint32_t
get_command_size(tpm2_op_driver_request *request) {
    if (!request) {
        return 0;
    }
    return tpm2_be32_to_cpu(request->op_request.header.command_size);
}

uint32_t
get_command_code(tpm2_op_driver_request *request) {
    if (!request) {
        return TPM2_CC_INVALID;
    }

    return tpm2_be32_to_cpu(request->op_request.header.command_code);
}

uint32_t
get_post_header_request_bytes(tpm2_op_driver_request *request) {
    if (!request) {
        return 0;
    }
    return tpm2_be32_to_cpu(request->op_request.header.command_size) - sizeof(tpm20_header_in);
}

uint32_t
get_post_header_response_bytes(tpm2_op_driver_response *response) {
    if (!response) {
        return 0;
    }
    return tpm2_be32_to_cpu(response->op_response.header.response_size) - sizeof(tpm20_header_out);
}

int
build_driver_get_random_response(tpm2_op_driver_request *request, TPM2B_DIGEST *digest, tpm2_op_driver_response *response) {
    int ret = -EINVAL;
    uint32_t digest_bytes = 0;

    // We expect non-NULL pointers
    if (!request || !digest || !response) {
        goto exit_build_driver_get_random_response;
    }

    // Beyond the header we have a TPM2B_DIGEST struct
    // TPM2B_DIGEST => [size (16 bits)][bytes in digest which may be <= sizeof(TPMU_HA)]
    digest_bytes = sizeof(uint16_t) + tpm2_be16_to_cpu(digest->size);
    //printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Digest bytes: %d", digest_bytes);

    memset(response, 0, sizeof(*response));
    // 1) Copy the tag to match the incoming tag
    response->op_response.header.tag = request->op_request.header.tag;
    // 2) Copy the owner pid
    response->op_response.owner_pid = request->op_request.owner_pid;
    // Copy the command code from the request (in cpu not big endian)
    response->op_response.command_code_cpu = tpm2_be32_to_cpu(request->op_request.header.command_code);
    // 3) Set the response size (converting it to big endian)
    // [header][TPM2B_DIGEST]
    // header => [tag (16 bits)][response size (32 bits)][response code (32 bits)]
    // TPM2B_DIGEST => [size (16 bits)][bytes in digest which may be <= sizeof(TPMU_HA)]
    response->op_response.header.response_size = tpm2_cpu_to_be32(sizeof(tpm20_header_out) + digest_bytes);
    // 4) Set the response code
    response->op_response.header.response_code = tpm2_cpu_to_be32(TPM2_RC_SUCCESS);
    // 5) Allocate a buffer for the post-header bytes
    response->op_response.buf = kmalloc(digest_bytes, GFP_KERNEL);
    if (!response->op_response.buf) {
        ret = -ENOMEM;
        goto exit_build_driver_get_random_response;
    }
    // 6) Clear out newly allocated buffer
    memset(response->op_response.buf, 0, digest_bytes);
    // 7) Copy the bytes after the header
    memcpy(response->op_response.buf, digest, digest_bytes);
    // 8) Initialize the list member of the struct before we return and use it
    INIT_LIST_HEAD(&response->list);
    // 9) If we get here, everything worked so set the return value to 0
    ret = 0;
 exit_build_driver_get_random_response:
    return ret;
}

