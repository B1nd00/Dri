#include <tpm2_driver.h>

extern struct list_head op_request_q;
extern struct list_head op_response_q;

ssize_t
handle_ax_tpm20_read_locked(char *data_buf, size_t len) {
    ssize_t ret = 0;
    tpm2_op_request request;
    tpm2_op_driver_request *current_req = NULL;
    tpm2_op_driver_request *next_req = NULL;
    const struct cred *user_cred = NULL;
    uint32_t user_id = -1;
    uint32_t group_id = -1;
    uint32_t command_code_cpu = TPM2_CC_INVALID;
    uint32_t offset = 0;
    uint32_t requests_available = 0;
    uint32_t post_header_bytes = 0;

    // Who is calling us? We want the user and group ids.
    // Only a privileged process is allowed to call this routine.
    user_cred = get_task_cred(current);
    if (user_cred) {
        user_id = user_cred->uid.val;
        group_id = user_cred->gid.val;
    }

    // Must be a privileged process to read from the key_gen_request_q
    if (user_id != 0 && group_id != 0) {
        printk(KERN_ALERT "[AXIADO_TPM2_COMPAT] Blocked unauthorized (read) access attempt by pid: %d (user id: %d, group id: %d)\n",
               current->pid, user_id, group_id);
        ret = -EACCES;
        // Jump to label so we can clean up as we leave
        goto exit_ax_tpm20_read;
    }

    // If we're here then we know data_buf starts with a special magic marker
    // pull out the header so we can check what we're supposed to do

    // Clear the request structure
    memset(&request, 0, sizeof(request));
    // Copy the header, we should at least have 10 a byte header
    if (len < sizeof(tpm20_header_in)) {
        printk(KERN_ALERT "[AXIADO_TPM2_COMPAT] Buffer (size: %ld) is too small.\n",
               len);
        ret = -EINVAL;
        goto exit_ax_tpm20_read;
    }

    // Copy over the header that should have come in from userspace
    memcpy(&request.header, data_buf, sizeof(tpm20_header_in));
    // Make sure we have a read-op for client requests
    command_code_cpu = tpm2_be32_to_cpu(request.header.command_code);
    if (command_code_cpu != TPM2_CC_AX_TCU_PRIV_READ) {
        printk(KERN_ALERT "[AXIADO_TPM2_COMPAT] Expected a privileged read command (0x%x) but got something else: 0x%x.\n",
               TPM2_CC_AX_TCU_PRIV_READ, command_code_cpu);
        ret = -EINVAL;
        goto exit_ax_tpm20_read;
    }

    offset = 0;
    post_header_bytes = 0;
    // Are there any pending client requests?
    list_for_each_entry_safe(current_req, next_req,
                             &op_request_q, list) {
        requests_available++;
        // Copy the details
        memcpy(data_buf+offset, &current_req->op_request.header, sizeof(tpm20_header_in));
        offset += sizeof(tpm20_header_in);
        memcpy(data_buf+offset, &current_req->op_request.owner_pid, sizeof(pid_t));
        offset += sizeof(pid_t);
        post_header_bytes = get_post_header_request_bytes(current_req);
        memcpy(data_buf+offset, current_req->op_request.buf, post_header_bytes);
        offset += post_header_bytes;

        // Remove this entry from the request q
        list_del(&current_req->list);
        // Free any buffer in the request
        if (current_req->op_request.buf) {
            kfree(current_req->op_request.buf);
            current_req->op_request.buf = NULL;
        }
        // Free the memory for the removed struct
        kfree(current_req);

        // For the time being exit after we've read one request. In the future,
        // keep going until we run out of buffer space (or pending requests)
        ret = offset; // Set the number of bytes we read
        break;
    }

    if (requests_available == 0) {
        ret = -MUST_SLEEP;
        goto exit_ax_tpm20_read;
    }

 exit_ax_tpm20_read:
    return ret;
}

ssize_t
handle_ax_tpm20_write_locked(char *data_buf, size_t len) {
    ssize_t ret = -EINVAL;
    uint32_t user_id = -1;
    uint32_t group_id = -1;
    uint32_t offset = 0;
    uint32_t command_code_cpu = TPM2_CC_INVALID;
    uint32_t post_header_bytes = 0;
    tpm20_header_in magic_header;
    tpm2_op_driver_response *response = NULL;
    const struct cred *user_cred = NULL;

    user_cred = get_task_cred(current);
    if (user_cred) {
        user_id = user_cred->uid.val;
        group_id = user_cred->gid.val;
    }

    // Do a permissions check, only a privileged process
    // is allowed to write responses to client requests
    if (user_id != 0 && group_id != 0) {
        printk(KERN_ALERT "[AXIADO_TPM2_COMPAT] Blocked unauthorized (key-write) access attempt by pid: %d (user id: %d, group id: %d)\n",
               current->pid, user_id, group_id);
        ret = -EACCES;
        // Jump to label so we also release the semaphore
        goto exit_ax_tpm20_write;
    }

    // Allocate a response object
    response = kmalloc(sizeof(*response), GFP_KERNEL);
    if (!response) {
        ret = -ENOMEM;
        goto exit_ax_tpm20_write;
    }
    memset(response, 0, sizeof(*response));

    // Parse the buffer that we copied from userspace
    // Buffer sections:
    // 1. [ax magic header  ] - 10 bytes (used to signal device driver)
    // 2. [header           ] - 10 bytes
    // 3. [owner pid        ] - 4 bytes
    // 4. [command code cpu ] - 4 bytes
    // 5. [bytes consumed   ] - 4 bytes
    // 6. [post-header bytes] - N bytes
    memset(&magic_header, 0, sizeof(magic_header));

    // 1) Copy magic header
    memcpy(&magic_header, data_buf+offset, sizeof(magic_header));
    offset += sizeof(magic_header);
    // We expect the command code to be a privileged write
    command_code_cpu = tpm2_be32_to_cpu(magic_header.command_code);
    if (command_code_cpu != TPM2_CC_AX_TCU_PRIV_WRITE) {
        printk(KERN_ALERT "[AXIADO_TPM2_COMPAT] Expected a privileged write command (0x%x) but got something else: 0x%x.\n",
               TPM2_CC_AX_TCU_PRIV_WRITE, command_code_cpu);

        if (response) {
            kfree(response);
            response = NULL;
        }

        ret = -EINVAL;
        goto exit_ax_tpm20_write;
    }

    // 2) Copy the response header that the client will receive
    memcpy(&response->op_response.header, data_buf+offset, sizeof(response->op_response.header));
    offset += sizeof(response->op_response.header);

    // 3) Copy the owner pid
    memcpy(&response->op_response.owner_pid, data_buf+offset, sizeof(response->op_response.owner_pid));
    offset += sizeof(response->op_response.owner_pid);

    // 4) Copy the command code
    memcpy(&response->op_response.command_code_cpu, data_buf+offset, sizeof(response->op_response.command_code_cpu));
    offset += sizeof(response->op_response.command_code_cpu);

    // 5) Copy the bytes consumed
    memcpy(&response->op_response.bytes_consumed, data_buf+offset, sizeof(response->op_response.bytes_consumed));
    offset += sizeof(response->op_response.bytes_consumed);

    // 6) Copy the digest bytes
    post_header_bytes = get_op_response_post_header_response_bytes(&response->op_response);
    if (post_header_bytes > 0) {
        printk(KERN_INFO "[AXIADO_TPM2_COMPAT] Post-header bytes for command code: 0x%x = %d", response->op_response.command_code_cpu, post_header_bytes);
        response->op_response.buf = kmalloc(post_header_bytes, GFP_KERNEL);
        if (!response->op_response.buf) {
            if (response) {
                kfree(response);
                response = NULL;
            }
            ret = -ENOMEM;
            goto exit_ax_tpm20_write;
        }
        memset(response->op_response.buf, 0, post_header_bytes);
        memcpy(response->op_response.buf, data_buf+offset, post_header_bytes);
        offset += post_header_bytes;
    }
    // Initialize the list member of the response
    INIT_LIST_HEAD(&response->list);
    // Push this response onto the op response queue so the caller can read it later
    list_add_tail(&response->list, &op_response_q);
    // Set return value to the offset, since that's the number of bytes parsed from
    // the write buffer
    ret = offset;

 exit_ax_tpm20_write:
    return ret;
}

