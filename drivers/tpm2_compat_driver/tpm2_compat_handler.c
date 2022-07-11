#include <tpm2_driver.h>

extern struct list_head op_request_q;
extern struct list_head op_response_q;

uint8_t*
create_command_buffer_from_driver_request(tpm2_op_driver_request *request) {
    uint8_t *buf = NULL;
    size_t command_buffer_size = 0;
    if (!request) {
        return NULL;
    }

    command_buffer_size = sizeof(tpm20_header_in) + get_post_header_request_bytes(request);
    buf = kmalloc(command_buffer_size, GFP_KERNEL);
    if (!buf) {
        return NULL;
    }

    // Clear the buffer
    memset(buf, 0, command_buffer_size);
    // Copy the header
    memcpy(buf, &request->op_request.header, sizeof(tpm20_header_in));
    // Copy the post-header bytes
    memcpy(buf + sizeof(tpm20_header_in), request->op_request.buf, get_post_header_request_bytes(request));
    return buf;
}

uint8_t*
create_command_buffer_from_driver_response(tpm2_op_driver_response *response) {
    uint8_t *buf = NULL;
    size_t command_buffer_size = 0;
    if (!response) {
        return NULL;
    }

    command_buffer_size = sizeof(tpm20_header_out) + get_post_header_response_bytes(response);
    buf = kmalloc(command_buffer_size, GFP_KERNEL);
    if (!buf) {
        return NULL;
    }

    // Clear the buffer
    memset(buf, 0, command_buffer_size);
    // Copy the header
    memcpy(buf, &response->op_response.header, sizeof(tpm20_header_out));
    // Copy the post-header bytes
    memcpy(buf + sizeof(tpm20_header_out), response->op_response.buf, get_post_header_response_bytes(response));
    return buf;
}

int
build_driver_request(char *buf, size_t len, tpm2_op_driver_request *request) {
    int ret = -EINVAL;
    uint32_t user_id = -1;
    uint32_t group_id = -1;
    uint32_t command_bytes = len - sizeof(tpm20_header_in);

    int i = 0;

    const struct cred *user_cred = get_task_cred(current);
    if (user_cred) {
        user_id = user_cred->uid.val;
        group_id = user_cred->gid.val;
    }

    // We expect non-NULL pointers
    if (!buf || !request) {
        goto exit_build_driver_request;
    }

    // We at least expect to have enough bytes for a header
    if (len < sizeof(tpm20_header_in)) {
        goto exit_build_driver_request;
    }

    memset(request, 0, sizeof(*request));
    // 1) Copy the header
    memcpy(&request->op_request.header, buf, sizeof(tpm20_header_in));
    // 2) Set the owner_pid
    request->op_request.owner_pid = current->pid;
    // 3) Allocate a buffer & copy the bytes after the header into it
    if (command_bytes > 0) {
        request->op_request.buf = kmalloc(command_bytes, GFP_KERNEL);
        if (!request->op_request.buf) {
            ret = -ENOMEM;
            goto exit_build_driver_request;
        }
        // Clear out the newly allocated buffer
        memset(request->op_request.buf, 0, command_bytes);
        // Copy the bytes after the header
        memcpy(request->op_request.buf, buf + sizeof(tpm20_header_in), command_bytes);
    }

    if (get_command_code(request) == TPM2_CC_CreatePrimary) {
        for (i = 0; i < len; i++) {
            printk(KERN_INFO "%d -> 0x%x\n", i, *(buf+i));
        }
    }


    // 4) Initialize the list member of the struct before we return and use it
    INIT_LIST_HEAD(&request->list);
    // 5) If we get here, everything worked so set the return value to len
    ret = len;
 exit_build_driver_request:
    return ret;
}

ssize_t handle_tpm20_write_locked(char *data_buf, size_t len) {
    ssize_t ret = -EINVAL;
    tpm2_op_driver_request *request = NULL;

    request = kmalloc(sizeof(*request), GFP_KERNEL);
    if (!request) {
        ret = -ENOMEM;
        goto exit_handle_tpm20_write_locked;
    }
    // Zero out request structure
    memset(request, 0, sizeof(*request));

    // We expect to extract all the bytes from data_buf
    ret = build_driver_request(data_buf, len, request);
    if (ret != len) {
        kfree(request);
        request = NULL;
        ret = -EINVAL;
        goto exit_handle_tpm20_write_locked;
    }

    // TODO: remove later
    dump_driver_request(request);

    // Handle the request - this may include pushing it into the request queue or handling it and
    // pushing the response on the response queue
    handle_tpm20_request_locked(request);
    ret = len;
 exit_handle_tpm20_write_locked:
    return ret;
}

uint32_t
handle_tpm20_request_locked(tpm2_op_driver_request *request) {
    uint32_t ret = TPM2_RC_FAILURE;
    uint32_t command_code = get_command_code(request);

    // Immediatedly enqueue the request for the server component to handle
    switch(command_code) {
    case TPM2_CC_GetRandom:
        list_add_tail(&request->list, &op_request_q);
        //handle_tpm20_cc_get_random_locked(request);
        ret = TPM2_RC_SUCCESS;
        break;
    case TPM2_CC_GetCapability:
        list_add_tail(&request->list, &op_request_q);
        //handle_tpm20_cc_get_capability_locked(request);
        ret = TPM2_RC_SUCCESS;
        break;
    case TPM2_CC_StartAuthSession:
        list_add_tail(&request->list, &op_request_q);
        //handle_tpm20_cc_start_auth_session_locked(request);
        ret = TPM2_RC_SUCCESS;
        break;
    default:
        list_add_tail(&request->list, &op_request_q);
        //handle_tpm20_cc_failure_locked(request, TPM2_RC_COMMAND_CODE);
        ret = TPM2_RC_COMMAND_CODE; // Command code not supported/recognized
        break;
    }

    return ret;
}

uint32_t
handle_tpm20_cc_get_random_locked(tpm2_op_driver_request *request) {
    // Typically the command handler would simply enqueue a request so the
    // server component can read it and act on it. For get_random though we
    // won't enqueue it (for now). We'll just push a response onto the
    // response queue
    list_add_tail(&request->list, &op_request_q);

    /*
    // Get the number of random bytes requested - it should be enough to store a uint16_t (2 bytes)
    uint16_t bytes_requested_cpu = 0;
    uint16_t bytes_requested_be = 0;
    uint32_t post_header_bytes = get_post_header_request_bytes(request);
    TPM2B_DIGEST digest;
    tpm2_op_driver_response *response = NULL;

    // If we didn't get a request, just bail
    if (!request) {
        return TPM2_RC_NO_RESULT; // Bad parameters so nothing we can do
    }

    // Allocate a response object
    response = kmalloc(sizeof(*response), GFP_KERNEL);
    if (!response) {
        return TPM2_RC_FAILURE; // Internal error - we can't build a response because we're out of memory
    }

    if (post_header_bytes != sizeof(uint16_t)) {
        // TODO: We should write a response and push it onto the op_response_q
        handle_tpm20_cc_failure_locked(request, TPM2_RC_NO_RESULT);
        return TPM2_RC_NO_RESULT; // Bad parameters so nothing we can do
    }

    memcpy(&bytes_requested_be, request->op_request.buf, sizeof(uint16_t));
    bytes_requested_cpu = tpm2_be16_to_cpu(bytes_requested_be);
    //printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Random bytes requested: 0x%x (%d)", bytes_requested_cpu, bytes_requested_cpu);

    // When we write the response
    // header = 10 bytes followed by TPM2B_DIGEST (66 bytes)
    // header: [tag (16 bits)][response size (32 bits)][response code (32 bits)] => 2 bytes + 4 bytes + 4 bytes = 10 bytes
    // TPM2B_DIGEST: [size (16 bits)][sizeof(TPMU_HA)] where TPMU_HA is a union that between 20 bytes (SHA-1) and 64 bytes (SHA-512) => 2 bytes + 64 bytes

    // Tss2_Tcti_Device_Init is going to try to do a partial read (only 20 bytes total, which is smaller than header (10) + TPM2B_DIGEST (66) = 76 bytes
    // printk(KERN_INFO "[AXIADO_TPM2_COMPAT] sizeof(TPM2B_DIGEST): %ld", sizeof(TPM2B_DIGEST));
    // Set initial values for the digest
    memset(&digest, 0, sizeof(digest));
    // Fill in the digest structure with sensible values
    digest.size = bytes_requested_be;
    // Write the "random bytes" requested after the size field of the digest.
    // Don't forget the typecast to uint8_t* so the pointer arithmetic increments correctly (by byte)
    memset((uint8_t*)(&digest) + sizeof(uint16_t), 0xFE, bytes_requested_cpu);
    if (!build_driver_get_random_response(request, &digest, response)) {
        // Push this response onto the op response queue so the caller can read it later
        list_add_tail(&response->list, &op_response_q);
        // Dump the contents of the response (for debugging)
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] [pid: %d] Dumping get random response that we just enqueued for client", current->pid);
        dump_driver_response(response);
    }
    */
    return TPM2_RC_SUCCESS;
}

uint32_t
handle_tpm20_cc_failure_locked(tpm2_op_driver_request *request, uint32_t response_code) {
    // Just enqueue for the server component to handle
    list_add_tail(&request->list, &op_request_q);
    return TPM2_RC_SUCCESS;

    /*
    tpm2_op_driver_response *response = NULL;

    if (!request) {
        return TPM2_RC_NO_RESULT; // Bad parameters so nothing we can do
    }

    response = kmalloc(sizeof(*response), GFP_KERNEL);
    if (!response) {
        return TPM2_RC_FAILURE; // Internal error - we can't build a response because we're out of memory
    }

    memset(response, 0, sizeof(*response));
    // 1) Copy the tag from the incoming request
    response->op_response.header.tag = request->op_request.header.tag;
    // 2) Copy the owner pid
    response->op_response.owner_pid = request->op_request.owner_pid;
    // 3) Copy the command code from the request (in cpu not big endian)
    response->op_response.command_code_cpu = tpm2_be32_to_cpu(request->op_request.header.command_code);
    // 4) Set the response size (will just be the size of the header) in big endian
    response->op_response.header.response_size = tpm2_cpu_to_be32(sizeof(tpm20_header_out));
    // 5) Set the response code (in big endian)
    response->op_response.header.response_code = tpm2_cpu_to_be32(response_code);
    // 6) Initialize the list member of the struct before we return and use it
    INIT_LIST_HEAD(&response->list);
    // 7) Push the response onto the response q
    list_add_tail(&response->list, &op_response_q);
    return TPM2_RC_SUCCESS;
    */
}

uint32_t
handle_tpm20_cc_get_capability_locked(tpm2_op_driver_request *request) {
    //list_add_tail(&request->list, &op_request_q);
    //return TPM2_RC_SUCCESS;

    // Decode the request and parse the post-header-bytes
    TPM2_CAP capability_be = 0;
    uint32_t property_be = 0;
    uint32_t property_count_be = 0;
    TPM2_CAP capability_cpu = 0;
    uint32_t property_cpu = 0;
    uint32_t property_count_cpu = 0;

    uint32_t post_header_bytes = get_post_header_request_bytes(request);
    uint32_t offset = 0;

    // We expect the post header byes to include 3 32-bit elements
    // [TPM2_CAP capability  ]
    // [UINT32 property      ]
    // [UINT32 property count]

    if (post_header_bytes != 3 * sizeof(uint32_t)) {
        return handle_tpm20_cc_failure_locked(request, TPM2_RC_NO_RESULT);
    }

    memcpy(&capability_be, request->op_request.buf, sizeof(capability_be));
    offset += sizeof(capability_be);
    memcpy(&property_be, request->op_request.buf + offset, sizeof(property_be));
    offset += sizeof(property_be);
    memcpy(&property_count_be, request->op_request.buf + offset, sizeof(property_count_be));

    // Convert from big endian to CPU so we can continue parsing and processing this request
    capability_cpu = tpm2_be32_to_cpu(capability_be);
    property_cpu = tpm2_be32_to_cpu(property_be);
    property_count_cpu = tpm2_be32_to_cpu(property_count_be);

    // Dump these properties (for debugging)
    printk(KERN_INFO "[AXIADO_TPM2_COMPAT] [pid: %d] Get Capability details: capability 0x%x, property: 0x%x, property count: %d\n",
           current->pid,
           capability_cpu,
           property_cpu,
           property_count_cpu);

    switch(capability_cpu) {
    case TPM2_CAP_ALGS:
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] [pid: %d] Request for algorithm capabilities", current->pid);
        return handle_tpm20_cc_get_capability_algorithms_locked(request, property_count_cpu);
    case TPM2_CAP_HANDLES:
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Request for handle capabilities");
        break;
    case TPM2_CAP_COMMANDS:
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Request for command capabilities");
        break;
    case TPM2_CAP_PP_COMMANDS:
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Request for physical presence (PP) capabilities");
        break;
    case TPM2_CAP_AUDIT_COMMANDS:
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Request for physical audit capabilities");
        break;
    case TPM2_CAP_PCRS:
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Request for PCR capabilities (reserved)");
        break;
    case TPM2_CAP_TPM_PROPERTIES:
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Request for TPM property capabilities (reserved)");
        break;
    case TPM2_CAP_PCR_PROPERTIES:
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Request for PCR property capabilities (reserved)");
        break;
    case TPM2_CAP_ECC_CURVES:
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Request for ECC curve capabilities (reserved)");
        break;
    case TPM2_CAP_AUTH_POLICIES:
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Request for Auth policies capabilities (reserved)");
        break;
    case TPM2_CAP_ACT:
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Request for Authenticated countdown timer (ACT) capabilities (reserved)");
        break;
    case TPM2_CAP_VENDOR_PROPERTY:
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Request for vendor-specific capabilities (reserved)");
        break;
    default:
        break;
    }

    // Return a failure response for the caller
    return handle_tpm20_cc_failure_locked(request, TPM2_RC_COMMAND_CODE);
}

uint32_t
handle_tpm20_cc_get_capability_algorithms_locked(tpm2_op_driver_request *request, uint32_t property_count_cpu) {
    tpm2_op_driver_response *response = NULL;
    TPMS_CAPABILITY_DATA *capability_data = NULL;
    uint32_t post_header_bytes = sizeof(TPMI_YES_NO) + sizeof(*capability_data);
    TPMI_YES_NO more_data = TPM2_NO; // No more data after this capability reply
    uint32_t offset = 0;
    TPMS_ALG_PROPERTY rsa;
    TPMS_ALG_PROPERTY sha256;

    if (!request) {
        return TPM2_RC_NO_RESULT; // Bad parameters so nothing we can do
    }

    response = kmalloc(sizeof(*response), GFP_KERNEL);
    if (!response) {
        return TPM2_RC_FAILURE; // Internal error - we can't build a response because we're out of memory
    }

    capability_data = kmalloc(sizeof(*capability_data), GFP_KERNEL);
    if (!capability_data) {
        return TPM2_RC_FAILURE; // Internal error - we can't build a response because we're out of memory
    }

    memset(response, 0, sizeof(*response));
    memset(capability_data, 0, sizeof(*capability_data));
    printk(KERN_INFO "[AXIADO_TPM2_COMPAT] [pid: %d] Sizeof TPMS_CAPABILITY_DATA: %ld", current->pid, sizeof(*capability_data));

    // 1) Copy the tag from the incoming request
    response->op_response.header.tag = request->op_request.header.tag;
    // 2) Copy the owner pid
    response->op_response.owner_pid = request->op_request.owner_pid;
    // 3) Copy the command code
    response->op_response.command_code_cpu = tpm2_be32_to_cpu(request->op_request.header.command_code);
    // 4) Set the response size [header (10 bytes)][TPMI_YES_NO (1 byte)][TPMS_CAPABILITY_DATA (1032 bytes)]
    response->op_response.header.response_size = tpm2_cpu_to_be32(sizeof(tpm20_header_out) + post_header_bytes);
    // 5) Set the response code as success
    response->op_response.header.response_code = tpm2_cpu_to_be32(TPM2_RC_SUCCESS);
    // 6) Allocate a buffer for the post-header bytes
    response->op_response.buf = kmalloc(post_header_bytes, GFP_KERNEL);
    if (!response->op_response.buf) {
        // Free the other object we allocated and leave
        if (response) {
            kfree(response);
            response = NULL;
        }

        if (capability_data) {
            kfree(capability_data);
            capability_data = NULL;
        }
        return TPM2_RC_FAILURE;
    }
    // 7) Clear out newly allocated buffer
    memset(response->op_response.buf, 0, post_header_bytes);
    // 8) Fill out the post-header byte values [TPM2_YES_NO][TPMS_CAPABILITY_DATA]
    memcpy(response->op_response.buf, &more_data, sizeof(more_data));
    offset += sizeof(more_data);

    // If we're here we're focused on algorithm capbilities
    capability_data->capability = tpm2_cpu_to_be32(TPM2_CAP_ALGS);
    capability_data->data.algorithms.count = tpm2_cpu_to_be32(2); // Hard-code that we only support two algorithms

    // Assume 2 algorithms, one asymmetric and one hash (RSA and SHA256)
    memset(&rsa, 0, sizeof(rsa));
    memset(&sha256, 0, sizeof(sha256));

    // Values of algorithm properties based on:
    // https://github.com/microsoft/ms-tpm-20-ref/blob/master/TPMCmd/tpm/src/support/AlgorithmCap.c#L55 and
    // https://github.com/microsoft/ms-tpm-20-ref/blob/d7a7c200fae3ab947efef8902d219072de94cc3e/TPMCmd/tpm/include/TpmTypes.h#L781

    // Set the properties for RSA algorithm
    rsa.alg = tpm2_cpu_to_be16(TPM2_ALG_RSA); // 16 bit
    rsa.algProperties = tpm2_cpu_to_be32((1 << 0) +  (1 << 3)); // 32 bit

    // Set the properties for the SHA256 algorithm
    sha256.alg = tpm2_cpu_to_be16(TPM2_ALG_SHA256);
    sha256.algProperties = tpm2_cpu_to_be32(1 << 2);

    capability_data->data.algorithms.algProperties[0] = rsa;
    capability_data->data.algorithms.algProperties[1] = sha256;

    memcpy(response->op_response.buf + offset, capability_data, sizeof(*capability_data));

    // Initialize the list member of the struct before we return and use it
    INIT_LIST_HEAD(&response->list);

    dump_driver_response(response);

    // Push the response onto the response q
    list_add_tail(&response->list, &op_response_q);

    if (capability_data) {
        kfree(capability_data);
        capability_data = NULL;
    }
    return TPM2_RC_SUCCESS;
}


uint32_t
handle_tpm20_cc_start_auth_session_locked(tpm2_op_driver_request *request) {
    // Parse and dump the request so we tease out the post-header structure
    TPMI_DH_OBJECT tpm_key_be = 0; // 4 bytes
    TPMI_DH_ENTITY bind_be = 0; // 4 bytes
    TPM2B_NONCE nonce_caller;
    uint32_t offset = 0;
    //uint16_t digest_size_be = 0;
    TPM2B_ENCRYPTED_SECRET encrypted_salt;
    TPM2_SE session_type = 0; // 1 byte
    TPMT_SYM_DEF symmetric; // 6 bytes
    TPMI_ALG_HASH auth_hash; // 2 bytes
    tpm2_op_driver_response *response = NULL;
    TPM2B_NONCE nonce_tpm;
    uint32_t post_header_bytes = 0;
    uint32_t session_handle = 0x55555555;

    int i = 0;
    if (!request) {
        return TPM2_RC_NO_RESULT; // Bad parameters so nothing we can do, we should
    }

    // Allocate a response object
    response = kmalloc(sizeof(*response), GFP_KERNEL);
    if (!response) {
        return TPM2_RC_FAILURE; // Internal error - we can't build a response because we're out of memory
    }

    // 49 bytes post-header example
    // 4 (tpm_key) + 4 (bind) + 34 (size+nonce/digest) + 2 (size+salt) + 1 (session_type) + 2 (symmetric) + 2 (hash)

    memset(&nonce_caller, 0, sizeof(nonce_caller));
    memset(&encrypted_salt, 0, sizeof(encrypted_salt));
    memset(&symmetric, 0, sizeof(symmetric));
    memset(&nonce_tpm, 0, sizeof(nonce_tpm));

    memcpy(&tpm_key_be, request->op_request.buf, sizeof(tpm_key_be));
    offset += sizeof(tpm_key_be);
    memcpy(&bind_be, request->op_request.buf+offset, sizeof(bind_be));
    offset += sizeof(bind_be);

    // We're about to copy a digest but we don't know how many bytes we actually have
    memcpy(&nonce_caller, request->op_request.buf+offset, sizeof(nonce_caller.size));
    offset += sizeof(nonce_caller.size);
    // Convert the BE value to cpu
    nonce_caller.size = tpm2_be16_to_cpu(nonce_caller.size);
    // Now copy the nonce bytes
    memcpy(nonce_caller.buffer, request->op_request.buf+offset, nonce_caller.size);
    offset += nonce_caller.size;

    // Next up copy the encrypted salt but we don't know how many bytes we have
    memcpy(&encrypted_salt, request->op_request.buf+offset, sizeof(encrypted_salt.size));
    offset += sizeof(encrypted_salt.size);
    encrypted_salt.size = tpm2_be16_to_cpu(encrypted_salt.size);
    // Now copy the bytes
    memcpy(encrypted_salt.secret, request->op_request.buf+offset, encrypted_salt.size);
    offset += encrypted_salt.size;

    // Copy the session type (1 byte)
    // #define TPM2_SE_HMAC    ((TPM2_SE) 0x00)
    // #define TPM2_SE_POLICY  ((TPM2_SE) 0x01)
    // #define TPM2_SE_TRIAL   ((TPM2_SE) 0x03)
    memcpy(&session_type, request->op_request.buf+offset, sizeof(session_type));
    offset += sizeof(session_type);

    // Copy the symmetric data
    // printk(KERN_INFO "[AXIADO_TPM2_COMPAT] sizeof(symmetric): %ld", sizeof(symmetric));
    // First get the algorithm ID, it can be TPM2_ALG_NULL (0x0010)
    memcpy(&symmetric, request->op_request.buf+offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    symmetric.algorithm = tpm2_be16_to_cpu(symmetric.algorithm);
    if (symmetric.algorithm != TPM2_ALG_NULL) {
        // Then read the key bits and mode uint16_t values
        // Rewind the offset pointer and read the entire 6 bytes of the symmetric struct
        offset -= sizeof(uint16_t);
        memcpy(&symmetric, request->op_request.buf+offset, sizeof(symmetric));
        offset += sizeof(symmetric);
    }

    // Copy the auth hash (it won't be TPM2_ALG_NULL)
    memcpy(&auth_hash, request->op_request.buf+offset, sizeof(auth_hash));
    offset += sizeof(auth_hash);

    printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Offset: %d", offset);
    // TPM2_RH_NULL = 0x40000007
    printk(KERN_INFO "[AXIADO_TPM2_COMPAT] [pid: %d] tpm key: 0x%x, bind: 0x%x, digest size: %d, encrypted salt size: %d, session type: 0x%x, symmetric alg id: 0x%x, auth hash: 0x%x",
           current->pid,
           tpm2_be32_to_cpu(tpm_key_be),
           tpm2_be32_to_cpu(bind_be),
           nonce_caller.size,
           encrypted_salt.size,
           session_type,
           symmetric.algorithm,
           tpm2_be16_to_cpu(auth_hash));
    // Print the nonce bytes
    printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Nonce bytes:\n");
    for(i = 0; i < nonce_caller.size; i++) {
        printk(KERN_INFO "0x%x ", nonce_caller.buffer[i]);
    }
    printk(KERN_INFO "\n");

    printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Encrypted salt:\n");
    for(i = 0; i < encrypted_salt.size; i++) {
        printk(KERN_INFO "0x%x ", encrypted_salt.secret[i]);
    }
    printk(KERN_INFO "\n");


    // Now build a response
    // 1) Copy the tag from the incoming request
    response->op_response.header.tag = request->op_request.header.tag;
    // 2) Copy the owner pid
    response->op_response.owner_pid = request->op_request.owner_pid;
    // 3) Copy the command code
    response->op_response.command_code_cpu = tpm2_be32_to_cpu(request->op_request.header.command_code);
    // 4) Set the response size [header][session handle][nonce 2+32 bytes]
    post_header_bytes = sizeof(TPMI_SH_AUTH_SESSION) + sizeof(uint16_t) + 32;
    response->op_response.header.response_size = tpm2_cpu_to_be32(sizeof(tpm20_header_out) + post_header_bytes);
    // 5) Set the response code as success
    response->op_response.header.response_code = tpm2_cpu_to_be32(TPM2_RC_SUCCESS);
    // 6) Allocate a buffer for the post-header bytes
    response->op_response.buf = kmalloc(post_header_bytes, GFP_KERNEL);
    if (!response->op_response.buf) {
        // Free the other object we allocated and leave
        if (response) {
            kfree(response);
            response = NULL;
        }
        return TPM2_RC_FAILURE;
    }
    // 7) Clear out the newly allocated buffer
    memset(response->op_response.buf, 0, post_header_bytes);
    offset = 0;
    // 8) Fill in the post-header byte values [session handle][nonce 2+32 bytes]
    memcpy(response->op_response.buf, &session_handle, sizeof(session_handle));
    offset += sizeof(session_handle);
    nonce_tpm.size = tpm2_cpu_to_be16(nonce_caller.size);
    memcpy(nonce_tpm.buffer, nonce_caller.buffer, nonce_caller.size);
    memcpy(response->op_response.buf+offset, &nonce_tpm, sizeof(nonce_tpm.size) + nonce_caller.size);

    INIT_LIST_HEAD(&response->list);

    dump_driver_response(response);

    list_add_tail(&response->list, &op_response_q);
    return TPM2_RC_SUCCESS;

    //return handle_tpm20_cc_failure_locked(request, TPM2_RC_COMMAND_CODE);
}

ssize_t
handle_tpm20_read_locked(char *data_buf, size_t len) {
    ssize_t ret = -1; // MUST_SLEEP
    uint32_t user_id = -1;
    uint32_t group_id = -1;
    const struct cred *user_cred = NULL;
    int num_matches = 0;
    tpm2_op_driver_response *current_ptr, *next_ptr = NULL;
    char *command_buffer = NULL;
    uint32_t command_buffer_size = 0;

    // Who is calling us? We want the user and group ids
    user_cred = get_task_cred(current);
    if (user_cred) {
        user_id = user_cred->uid.val;
        group_id = user_cred->gid.val;
    }

    //printk(KERN_INFO "[AXIADO_TPM2_COMPAT] [pid: %d] Attempting a TPM2.0 read of %ld byte(s)", current->pid, len);
    // Look for any responses matching the pid
    // If we find something then return len bytes in the response and update bytes consumed
    // If we don't find anything then we need to put the process to sleep

    list_for_each_entry_safe(current_ptr, next_ptr, &op_response_q, list) {
        if (current_ptr->op_response.owner_pid != current->pid) {
            continue;
        }

        // printk(KERN_INFO "[AXIADO_TPM2_COMPAT] [pid: %d] Found pid match when attempting a TPM2.0 read of %ld byte(s)", current->pid, len);
        // TODO: remove message -> Dump the driver response (for debugging)
        // dump_driver_response(current_ptr);

        num_matches++;
        // Are we reading the entire response, part of the response or trying to read past the end of a response
        command_buffer_size = sizeof(tpm20_header_out) + get_post_header_response_bytes(current_ptr);
        command_buffer = create_command_buffer_from_driver_response(current_ptr);
        if (!command_buffer) {
            return -ENOMEM;
        }

        // Don't allow reading past the end of the command buffer
        if (current_ptr->op_response.bytes_consumed + len > command_buffer_size) {
            len = command_buffer_size - current_ptr->op_response.bytes_consumed;
        }

        // Copy data from the command buffer into the data buffer that will be returned
        memcpy(data_buf, command_buffer + current_ptr->op_response.bytes_consumed, len);
        // Update the bytes consumed
        current_ptr->op_response.bytes_consumed += len;

        if (current_ptr->op_response.bytes_consumed == command_buffer_size) {
            // Remove this response because it has been fully consumed
            list_del(&current_ptr->list);
            if (current_ptr->op_response.buf) {
                kfree(current_ptr->op_response.buf);
                current_ptr->op_response.buf = NULL;
            }
            kfree(current_ptr);
        }
        // Break once we've read one response
        break;
    }

    if (command_buffer) {
        kfree(command_buffer);
        command_buffer = NULL;
    }

    // If we did not find any matches for this PID then put this process to sleep
    if (num_matches == 0) {
        ret = -MUST_SLEEP;
        return ret;
    }

    // Return bytes read
    ret = len;
    return ret;
}
