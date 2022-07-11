#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <memory.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include <tpm2_axiado.h> // Include our custom header

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/engine.h>

#define DEFAULT_DEVICE "/dev/tpm2_compat"

// Helper method for writing
ssize_t write_server_reply_preamble(char *buf, uint32_t buf_len, tpm20_header_in *magic_header, tpm2_op_response* response, uint32_t *offset);

ssize_t ax_tpm2_server_query_sync(int fd, tpm2_op_request *request);
ssize_t ax_tpm2_server_cc_get_random_response_sync(int fd, tpm2_op_request *request);
ssize_t ax_tpm2_server_cc_get_capability_response_sync(int fd, tpm2_op_request *request);
ssize_t ax_tpm2_server_cc_get_capability_algorithms_sync(int fd, tpm2_op_request *request, uint32_t property_count_cpu);
/* Add other capability handlers here */
ssize_t ax_tpm2_server_cc_start_auth_session_response_sync(int fd, tpm2_op_request *request);
ssize_t ax_tpm2_server_cc_create_primary_sync(int fd, tpm2_op_request *request);
ssize_t ax_tpm2_server_cc_flush_context_response_sync(int fd, tpm2_op_request *request);

ssize_t ax_tpm2_server_cc_failure(int fd, tpm2_op_request *request, uint32_t response_code);

void dump_tpm2b_sensitive_create(TPM2B_SENSITIVE_CREATE *sensitive);
void dump_tpm2b_public(TPM2B_PUBLIC *public);
void dump_tpm2b_data(TPM2B_DATA *data);
void dump_tpm2b_sensitive_data(TPM2B_SENSITIVE_DATA *data);
void dump_tpm2b_digest(TPM2B_DIGEST *digest);
void dump_tpm2b_auth(TPM2B_AUTH *auth);
void dump_tpml_pcr_selection(TPML_PCR_SELECTION *pcr);
void dump_tpms_pcr_selection(TPMS_PCR_SELECTION *pcr);
void dump_tpmt_public(TPMT_PUBLIC *public);

void
dump_tpm2b_sensitive_create(TPM2B_SENSITIVE_CREATE *sensitive) {
    if (!sensitive) {
        return;
    }
    printf("Size: %d\n", tpm2_be16_to_cpu(sensitive->size));
    dump_tpm2b_auth(&(sensitive->sensitive.userAuth));
    dump_tpm2b_sensitive_data(&(sensitive->sensitive.data));
}

void
dump_tpm2b_auth(TPM2B_AUTH *auth) {
    if (!auth) {
        return;
    }
    return dump_tpm2b_digest(auth);
}

void
dump_tpm2b_sensitive_data(TPM2B_SENSITIVE_DATA *data) {
    int i = 0;
    if (!data) {
        return;
    }

    printf("Sensitive data size: %d\n", tpm2_be16_to_cpu(data->size));
    for(i = 0; i < tpm2_be16_to_cpu(data->size); i++) {
        printf("0x%x ", data->buffer[i]);
    }
    printf("\nEnd of sensitive data\n");
}

void
dump_tpm2b_digest(TPM2B_DIGEST *digest) {
    int i = 0;
    if (!digest) {
        return;
    }
    printf("Digest size: %d\n", tpm2_be16_to_cpu(digest->size));
    for(i = 0; i < tpm2_be16_to_cpu(digest->size); i++) {
        printf("0x%x ", digest->buffer[i]);
    }
    printf("\nEnd of digest\n");
}

void
dump_tpm2b_data(TPM2B_DATA *data) {
    int i = 0;
    if (!data) {
        return;
    }

    printf("Data size: %d\n", tpm2_be16_to_cpu(data->size));
    for(i = 0; i < tpm2_be16_to_cpu(data->size); i++) {
        printf("0x%x ", data->buffer[i]);
    }
    printf("\nEnd of data\n");
}

void
dump_tpm2b_public(TPM2B_PUBLIC *public) {
    if (!public) {
        return;
    }
    printf("Public size: %d\n", tpm2_be16_to_cpu(public->size));
    dump_tpmt_public(&(public->publicArea));
}

void
dump_tpmt_public(TPMT_PUBLIC *public) {
    uint32_t object_attributes_cpu = 0;
    if (!public) {
        return;
    }
    printf("Public type       : 0x%x\n", tpm2_be16_to_cpu(public->type));
    printf("Public name alg   : 0x%x\n", tpm2_be16_to_cpu(public->nameAlg));
    printf("Public obj attribs: 0x%x\n", tpm2_be32_to_cpu(public->objectAttributes));
    // Decode the object attributes
    object_attributes_cpu = tpm2_be32_to_cpu(public->objectAttributes);
    printf("Attribs Object reserved 1            : 0x%x\n", object_attributes_cpu & TPMA_OBJECT_RESERVED1_MASK);
    printf("Attribs Object fixed TPM             : 0x%x\n", object_attributes_cpu & TPMA_OBJECT_FIXEDTPM);
    printf("Attribs Object st clear              : 0x%x\n", object_attributes_cpu & TPMA_OBJECT_STCLEAR);
    printf("Attribs Object reserved 2            : 0x%x\n", object_attributes_cpu & TPMA_OBJECT_RESERVED2_MASK);
    printf("Attribs Object fixed parent          : 0x%x\n", object_attributes_cpu & TPMA_OBJECT_FIXEDPARENT);
    printf("Attribs Object sensitive data origin : 0x%x\n", object_attributes_cpu & TPMA_OBJECT_SENSITIVEDATAORIGIN);
    printf("Attribs Object user with auth        : 0x%x\n", object_attributes_cpu & TPMA_OBJECT_USERWITHAUTH);
    printf("Attribs Object admin with auth       : 0x%x\n", object_attributes_cpu & TPMA_OBJECT_ADMINWITHPOLICY);
    printf("Attribs Object reserved 3            : 0x%x\n", object_attributes_cpu & TPMA_OBJECT_RESERVED3_MASK);
    printf("Attribs Object no dictionary attack  : 0x%x\n", object_attributes_cpu & TPMA_OBJECT_NODA);
    printf("Attribs Object encrypted duplication : 0x%x\n", object_attributes_cpu & TPMA_OBJECT_ENCRYPTEDDUPLICATION);
    printf("Attribs Object reserved 4            : 0x%x\n", object_attributes_cpu & TPMA_OBJECT_RESERVED4_MASK);
    printf("Attribs Object restricted            : 0x%x\n", object_attributes_cpu & TPMA_OBJECT_RESTRICTED);
    printf("Attribs Object decrypt               : 0x%x\n", object_attributes_cpu & TPMA_OBJECT_DECRYPT);
    printf("Attribs Object sign and encrypt      : 0x%x\n", object_attributes_cpu & TPMA_OBJECT_SIGN_ENCRYPT);
    printf("Attribs Object x509 sign             : 0x%x\n", object_attributes_cpu & TPMA_OBJECT_X509SIGN);
    printf("Attribs Object reserved 5            : 0x%x\n", object_attributes_cpu & TPMA_OBJECT_RESERVED5_MASK);

    dump_tpm2b_digest(&(public->authPolicy));

    // Dump the params union and the unique union
    switch(tpm2_be16_to_cpu(public->type)) {
    case TPM2_ALG_RSA:
        { // New scope so we can declare variables within the case
            // Dump RSA detail

            // rsaDetail.symmetric (TPMT_SYM_DEF_OBJECT)
            // rsaDetail.scheme (TPMT_RSA_SCHEME)
            uint16_t key_bits = tpm2_be16_to_cpu(public->parameters.rsaDetail.keyBits);
            uint32_t exponent = tpm2_be32_to_cpu(public->parameters.rsaDetail.exponent);
            if (exponent == 0) {
                // Use default of 216 + 1 per tss2_tpm2_types.h
                exponent = 216 + 1;
            }

            // Get symmetric details
            printf("RSA detail symmetric algorithm: 0x%x\n", tpm2_be16_to_cpu(public->parameters.rsaDetail.symmetric.algorithm));
            switch(tpm2_be16_to_cpu(public->parameters.rsaDetail.symmetric.algorithm)) {
            case TPM2_ALG_NULL:
                break;
            case TPM2_ALG_AES:
                printf("RSA detail symmetric algorithm         : AES\n");
                printf("RSA detail symmetric algorithm key bits: %d\n", tpm2_be16_to_cpu(public->parameters.rsaDetail.symmetric.keyBits.aes));
                // Mode will be one of: TPM2_ALG_CFB (0x43), TPM2_ALG_CBC (0x42), TPM2_ALG_OFB (0x41), TPM2_ALG_CTR (0x40), TPM2_ALG_ECB (0x44), +TPM2_ALG_NULL (0x10), #TPM2_RC_MODE (0x09)
                printf("RSA detail symmetric algorithm mode    : 0x%x\n", tpm2_be16_to_cpu(public->parameters.rsaDetail.symmetric.mode.aes));
                break;
            default:
                break;
            }
            // Get scheme details
            printf("RSA detail scheme : 0x%x\n", tpm2_be16_to_cpu(public->parameters.rsaDetail.scheme.scheme));
            switch(tpm2_be16_to_cpu(public->parameters.rsaDetail.scheme.scheme)) {
            case TPM2_ALG_NULL:
                printf("RSA detail scheme: TPM2_ALG_NULL\n");
                break;
            default:
                break;
            }

            printf("RSA detail key bits           : %d\n", tpm2_be16_to_cpu(public->parameters.rsaDetail.keyBits));
            printf("RSA detail key exponent       : %d (%d)\n", tpm2_be16_to_cpu(public->parameters.rsaDetail.exponent), exponent);

            // Dump RSA public key detail
            printf("Unique RSA size: %d\n", tpm2_be16_to_cpu(public->unique.rsa.size));
        }
        break;
    default:
        break;
    }
}

void
dump_tpml_pcr_selection(TPML_PCR_SELECTION *pcr) {
    int i = 0;
    if (!pcr) {
        return;
    }

    printf("Num PCR selections: %d\n", tpm2_be32_to_cpu(pcr->count));
    for (i = 0; i < tpm2_be32_to_cpu(pcr->count); i++) {
        dump_tpms_pcr_selection(&(pcr->pcrSelections[i]));
    }
}

void
dump_tpms_pcr_selection(TPMS_PCR_SELECTION *pcr) {
    int i = 0;
    if (!pcr) {
        return;
    }
    printf("PCR selection alg hash: 0x%x\n", tpm2_be16_to_cpu(pcr->hash));
    printf("PCR size of select    : %d\n", pcr->sizeofSelect);
    for (i = 0; i < pcr->sizeofSelect; i++) {
        printf("0x%x ", pcr->pcrSelect[i]);
    }
    printf("\nEnd of PCR bitmap\n");
}

ssize_t
ax_tpm2_server_query_sync(int fd, tpm2_op_request *client_request) {
    tpm20_header_in header;
    ssize_t bytes_read = 0;
    bool read_complete = false;
    size_t max_command_size = 4096;
    char *buf = NULL;

    if (!client_request) {
        return bytes_read;
    }

    // We know all TPM 2.0 commands have a max size of 4K so allocate a command buffer
    buf = malloc(max_command_size);
    if (!buf) {
        return bytes_read;
    }
    // Clear the buffer
    memset(buf, 0, max_command_size);

    // Clear the header
    memset(&header, 0, sizeof(header));
    header.tag = tpm2_cpu_to_be16(TPM2_ST_AXIADO); // Set the tag as something special
    header.command_size = tpm2_cpu_to_be32(sizeof(header)); // Our command size will just be the size of the header
    header.command_code = tpm2_cpu_to_be32(TPM2_CC_AX_TCU_PRIV_READ);

    // When we're reading client requests, do the read in one shot, versus the typical TPM 2.0 style
    // where you first read the header and then read the rest
    while (!read_complete) {
        bool has_more_data = true;
        uint32_t offset = 0;

        // Clear out the buffer
        memset(buf, 0, max_command_size);
        // Copy the header into the read buffer
        memcpy(buf, &header, sizeof(header));
        // Read the header of any pending client request - use the max buffer size
        // as the number of bytes to read, the driver will return as much as it has
        // so it's fine to receive less than 4K.
        // When the driver is updated to return client requests in bulk we'll have to
        // walk the returned buffer, parsing out individual client requests. Each
        // request is prefixed by a header that indicates the size of a request so
        // we should be ok.
        bytes_read = read(fd, buf, max_command_size);
        if (bytes_read == -1 || bytes_read < sizeof(header)) {
            // The read didn't work, or we did not get back at least a header's worth
            // of data, which would be a problem
            const int err = errno;
            if (err == EINTR) {
                // Try again if our read was interrupted
                continue;
            }
            fprintf(stderr, "[AXIADO_TPM2_SERVER] Unable to read up to %ld bytes. Reason: %s\n",
                    sizeof(header), strerror(err));
            goto exit_tpm2_server_query_sync;
        }

        while (has_more_data) {
            uint32_t post_header_bytes = 0;

            // A privileged read for client commands should return a buffer that looks like:
            // [tpm 2.0 header][owner pid][post-header-bytes buffer]
            memset(client_request, 0, sizeof(client_request));
            // Copy the header
            memcpy(&client_request->header, buf+offset, sizeof(tpm20_header_in));
            offset += sizeof(tpm20_header_in);
            // Privileged reads must include the owner pid between the header and the post header request bytes
            memcpy(&client_request->owner_pid, buf+offset, sizeof(pid_t));
            offset += sizeof(pid_t);
            post_header_bytes = get_op_request_post_header_request_bytes(client_request);
            client_request->buf = malloc(post_header_bytes);
            if (!client_request->buf) {
                // Can't allocated memory so bail
                fprintf(stderr, "[AXIADO_TPM2_SERVER] Unable to allocate %d post-header bytes\n", post_header_bytes);
                goto exit_tpm2_server_query_sync;
            }
            memset(client_request->buf, 0, post_header_bytes);
            memcpy(client_request->buf, buf+offset, post_header_bytes);
            offset += post_header_bytes;

            // Dump this header so we can see what the caller wants
            printf("[AXIADO_TPM2_SERVER] tag: 0x%x, size: %d, command code: 0x%x, owner pid: %d\n",
                   tpm2_be16_to_cpu(client_request->header.tag),
                   tpm2_be32_to_cpu(client_request->header.command_size),
                   tpm2_be32_to_cpu(client_request->header.command_code),
                   client_request->owner_pid);

            has_more_data = (offset < bytes_read);
            fprintf(stderr, "[AXIADO_TPM2_SERVER] offset: %d, bytes_read: %ld, has_more_data: %d\n",
                    offset,
                    bytes_read,
                    has_more_data);
        }
        read_complete = true;
    }

 exit_tpm2_server_query_sync:
    if (buf) {
        free(buf);
        buf = NULL;
    }
    return bytes_read;
}

ssize_t
write_server_reply_preamble(char *buf, uint32_t buf_len, tpm20_header_in *magic_header, tpm2_op_response* response, uint32_t *offset) {
    ssize_t bytes_written = 0;

    if (!buf || !magic_header || !response || !offset) {
        return 0;
    }

    bytes_written = *offset;

    // 1) Write the magic header (10 bytes)
    memcpy(buf + *offset, magic_header, sizeof(*magic_header));
    *offset += sizeof(*magic_header);
    // 2) Write the response header (10 bytes)
    memcpy(buf + *offset, &response->header, sizeof(response->header));
    *offset += sizeof(response->header);
    // 3) Write the owner pid (4 bytes)
    memcpy(buf + *offset, &response->owner_pid, sizeof(response->owner_pid));
    *offset += sizeof(response->owner_pid);
    // 4) Write the command code (in cpu format) so we can debug what the client's original request was (4 bytes)
    memcpy(buf + *offset, &response->command_code_cpu, sizeof(response->command_code_cpu));
    *offset += sizeof(response->command_code_cpu);
    // 5) Write bytes consumed (4 bytes)
    memcpy(buf + *offset, &response->bytes_consumed, sizeof(response->bytes_consumed));
    *offset += sizeof(response->bytes_consumed);

    bytes_written = *offset - bytes_written;
    return bytes_written;
}

ssize_t
ax_tpm2_server_cc_failure(int fd, tpm2_op_request *request, uint32_t response_code) {
    ssize_t bytes_written = 0;
    bool write_complete = false;
    tpm2_op_response *response = NULL;
    char *buf = NULL;
    uint32_t buf_len = 0;
    tpm20_header_in magic_header;
    uint32_t offset = 0;

    if (!request) {
        goto exit_ax_tpm2_server_cc_failure;
    }

    // Allocate a response object
    response = malloc(sizeof(*response));
    if (!response) {
        goto exit_ax_tpm2_server_cc_failure;
    }
    // Clear the response struct
    memset(response, 0, sizeof(*response));

    // 1) Copy the tag from the incoming request
    response->header.tag = request->header.tag;
    // 2) Copy the owner pid
    response->owner_pid = request->owner_pid;
    // 3) Copy the command code from the request (in cpu not big endian)
    response->command_code_cpu = tpm2_be32_to_cpu(request->header.command_code);
    // 4) Set the response size (will just be the size of the header) in big endian
    response->header.response_size = tpm2_cpu_to_be32(sizeof(tpm20_header_out));
    // 5) Set the response code (in big endian)
    response->header.response_code = tpm2_cpu_to_be32(response_code);

    // Now that the response is ready we need to prepend a magic header
    // convert everything to a byte buffer and write it to the device
    // so it looks like:
    // 1. [ax magic header]
    // 2. [header]
    // 3. [owner pid]
    // 4. [command code cpu]
    // 5. [bytes consumed]
    // Since we are creating an error response, the client is only
    // going to receive section 2 as the TPM 2.0 compliant response

    // We don't use sizeof(*response) when calculating the buffer len
    // because that struct contains a pointer to a buffer which will
    // throw off the size calculation. Instead compute the size
    // component by component
    buf_len = \
        sizeof(magic_header) + \
        sizeof(response->header) + \
        sizeof(response->owner_pid) + \
        sizeof(response->command_code_cpu) + \
        sizeof(response->bytes_consumed);

    buf = malloc(buf_len);
    if (!buf) {
        goto exit_ax_tpm2_server_cc_failure;
    }
    // Clear the buffer
    memset(buf, 0, buf_len);

    // Pack the buffer
    memset(&magic_header, 0, sizeof(magic_header));
    // Create our magic header so the device driver can peel it off and process the rest of the message
    magic_header.tag = tpm2_cpu_to_be16(TPM2_ST_AXIADO);
    magic_header.command_code = tpm2_cpu_to_be32(TPM2_CC_AX_TCU_PRIV_WRITE);
    magic_header.command_size = tpm2_cpu_to_be32(buf_len);
    offset = 0;

    // Server reply preamble:
    // 1) Write the magic header
    // 2) Write the response header
    // 3) Write the owner pid
    // 4) Write the command code (in cpu format) so we can debug what the client's original request was
    // 5) Write bytes consumed
    write_server_reply_preamble(buf, buf_len, &magic_header, response, &offset);

    printf("[AXIADO_TPM2_SERVER] Command code (cpu): 0x%x\n", response->command_code_cpu);
    printf("[AXIADO_TPM2_SERVER] Bytes consumed: %d\n", response->bytes_consumed);

    // Now write this entire buffer to the device
    while (!write_complete) {
        bytes_written = write(fd, buf, buf_len);
        if (bytes_written == -1) {
            const int err = errno;
            if (err == EINTR) {
                continue;
            }
            fprintf(stderr, "[AXIADO_TPM2_SERVER] Unable to write up to %d bytes. Reason: %s\n",
                    buf_len, strerror(err));
            bytes_written = -1;
            goto exit_ax_tpm2_server_cc_failure;
        }
        write_complete = true;
        if (bytes_written == 0) {
            goto exit_ax_tpm2_server_cc_failure;
        }
    }

 exit_ax_tpm2_server_cc_failure:

    if (response) {
        if (response->buf) {
            free(response->buf);
            response->buf = NULL;
        }
        free(response);
        response = NULL;
    }

    if (buf) {
        free(buf);
        buf = NULL;
    }
    return bytes_written;
}

ssize_t
ax_tpm2_server_cc_get_random_response_sync(int fd, tpm2_op_request *request) {
    ssize_t bytes_written = 0;
    uint16_t bytes_requested_cpu = 0;
    uint16_t bytes_requested_be = 0;
    uint32_t post_header_bytes = get_op_request_post_header_request_bytes(request);
    TPM2B_DIGEST digest;
    tpm2_op_response *response = NULL;
    uint32_t digest_bytes = 0;
    char *buf = NULL;
    uint32_t buf_len = 0;
    uint32_t offset = 0;
    tpm20_header_in magic_header;
    bool write_complete = false;

    if (!request) {
        goto exit_ax_tpm2_server_cc_get_random;
    }

    // Allocate a response object
    response = malloc(sizeof(*response));
    if (!response) {
        goto exit_ax_tpm2_server_cc_get_random;
    }
    // Clear the response struct
    memset(response, 0, sizeof(*response));

    // Is this command request well formed?
    if (post_header_bytes != sizeof(uint16_t)) {
        // TODO: write a failure response with TPM2_RC_NO_RESULT
        goto exit_ax_tpm2_server_cc_get_random;
    }

    memcpy(&bytes_requested_be, request->buf, sizeof(uint16_t));
    bytes_requested_cpu = tpm2_be16_to_cpu(bytes_requested_be);
    memset(&digest, 0, sizeof(digest));
    // Fill in the digest structure with sensible values
    digest.size = bytes_requested_be;

    // Actually go read random bytes from somewhere valid
    // Write the "random bytes" requested after the size field of the digest.
    // Don't forget the typecast to uint8_t* so the pointer arithmetic increments correctly (by byte)
    memset((uint8_t*)(&digest) + sizeof(uint16_t), 0xFE, bytes_requested_cpu);

    // Beyond the header we have a TPM2B_DIGEST struct
    // TPM2B_DIGEST => [size (16 bits)][bytes in digest which may be <= sizeof(TPMU_HA)]
    digest_bytes = sizeof(uint16_t) + tpm2_be16_to_cpu(digest.size);
    // 1) Copy the tag to match the request tag
    response->header.tag = request->header.tag;
    // 2) Copy the owner pid
    response->owner_pid = request->owner_pid;
    // Copy the command code from the request (in cpu not big endian)
    response->command_code_cpu = tpm2_be32_to_cpu(request->header.command_code);
    response->bytes_consumed = 0;
    // 3) Set the response size (converting it to big endian)
    // [header][TPM2B_DIGEST]
    // header => [tag (16 bits)][response size (32 bits)][response code (32 bits)]
    // TPM2B_DIGEST => [size (16 bits)][bytes in digest which may be <= sizeof(TPMU_HA)]
    response->header.response_size = tpm2_cpu_to_be32(sizeof(tpm20_header_out) + digest_bytes);
    // 4) Set the response code
    response->header.response_code = tpm2_cpu_to_be32(TPM2_RC_SUCCESS);
    // 5) Allocate a buffer for the post-header bytes
    response->buf = malloc(digest_bytes);
    if (!response->buf) {
        goto exit_ax_tpm2_server_cc_get_random;
    }
    // 6) Clear out newly allocated buffer
    memset(response->buf, 0, digest_bytes);
    // 7) Copy the bytes after the header
    memcpy(response->buf, &digest, digest_bytes);

    // Convert the response into a buffer and write it to the device.
    // Buffer format should be [ax magic header][header][owner pid][command code cpu][bytes consumed][buffer]
    buf_len = \
        sizeof(tpm20_header_in) + \
        sizeof(response->header) + \
        sizeof(uint32_t) + \
        sizeof(uint32_t) + \
        sizeof(uint32_t) + \
        digest_bytes;

    buf = malloc(buf_len);
    if (!buf) {
        goto exit_ax_tpm2_server_cc_get_random;
    }
    memset(buf, 0, buf_len);
    // Pack this buffer
    memset(&magic_header, 0, sizeof(magic_header));
    // Create our magic header so the device driver can peel it off and process the rest of the message
    magic_header.tag = tpm2_cpu_to_be16(TPM2_ST_AXIADO);
    magic_header.command_code = tpm2_cpu_to_be32(TPM2_CC_AX_TCU_PRIV_WRITE);
    magic_header.command_size = tpm2_cpu_to_be32(buf_len);
    offset = 0;
    // Buffer sections:
    // 1. [ax magic header] - 10 bytes (used to signal device driver)
    // 2. [header] - 10 bytes
    // 3. [owner pid] - 4 bytes
    // 4. [command code cpu] - 4 bytes
    // 5. [bytes consumed] - 4 bytes
    // 6. [digest] - digest_bytes

    // Sections 2 and 6 are concatenated to be returned to the client as the
    // actual TPM 2.0 compliant response

    // Server reply preamble:
    // 1) Write the magic header
    // 2) Write the response header
    // 3) Write the owner pid
    // 4) Write the command code (in cpu format) so we can debug what the client's original request was
    // 5) Write bytes consumed
    write_server_reply_preamble(buf, buf_len, &magic_header, response, &offset);
    // 6) Write buffer (digest)
    memcpy(buf+offset, &digest, digest_bytes);
    offset += digest_bytes;

    printf("[AXIADO_TPM2_SERVER] Command code (cpu): 0x%x\n", response->command_code_cpu);
    printf("[AXIADO_TPM2_SERVER] Bytes consumed    : %d\n", response->bytes_consumed);
    printf("[AXIADO_TPM2_SERVER] Digest bytes      : %d\n", digest_bytes);

    // Now write this entire buffer to the device
    while (!write_complete) {
        bytes_written = write(fd, buf, buf_len);
        if (bytes_written == -1) {
            const int err = errno;
            if (err == EINTR) {
                continue;
            }
            fprintf(stderr, "[AXIADO_TPM2_SERVER] Unable to write up to %d bytes. Reason: %s\n",
                    buf_len, strerror(err));
            bytes_written = -1;
            goto exit_ax_tpm2_server_cc_get_random;
        }
        write_complete = true;
        if (bytes_written == 0) {
            goto exit_ax_tpm2_server_cc_get_random;
        }
    }

 exit_ax_tpm2_server_cc_get_random:

    // Clean up the response struct
    if (response) {
        if (response->buf) {
            free(response->buf);
            response->buf = NULL;
        }
        free(response);
        response = NULL;
    }
    // Clean up the buffer
    if (buf) {
        free(buf);
        buf = NULL;
    }
    return bytes_written;
}

ssize_t
ax_tpm2_server_cc_get_capability_response_sync(int fd, tpm2_op_request *request) {
    ssize_t bytes_written = 0;
    // Decode the request and parse the post-header-bytes
    TPM2_CAP capability_be = 0;
    uint32_t property_be = 0;
    uint32_t property_count_be = 0;
    TPM2_CAP capability_cpu = 0;
    uint32_t property_cpu = 0;
    uint32_t property_count_cpu = 0;
    uint32_t post_header_bytes = get_op_request_post_header_request_bytes(request);
    uint32_t offset = 0;

    // We expect the post header bytes to include 3 32-bit elements (12 bytes)
    // [TPM2_CAP capability  ] - 4 bytes
    // [UINT32 property      ] - 4 bytes
    // [UINT32 property count] - 4 bytes
    if (post_header_bytes != (sizeof(uint32_t) * 3)) {
        return ax_tpm2_server_cc_failure(fd, request, TPM2_RC_NO_RESULT);
    }

    memcpy(&capability_be, request->buf, sizeof(capability_be));
    offset += sizeof(capability_be);
    memcpy(&property_be, request->buf + offset, sizeof(property_be));
    offset += sizeof(property_be);
    memcpy(&property_count_be, request->buf + offset, sizeof(property_count_be));

    // Convert from big endian to CPU so we can continue parsing and processing this request
    capability_cpu = tpm2_be32_to_cpu(capability_be);
    property_cpu = tpm2_be32_to_cpu(property_be);
    property_count_cpu = tpm2_be32_to_cpu(property_count_be);

    // Which capability is the client asking for? Note that some of these won't have
    // any analog in the Axiado TCU so we'll act like they are not supported
    switch(capability_cpu) {
    case TPM2_CAP_ALGS: // Algorithm capabilities
        printf("[AXIADO_TPM2_SERVER] [pid: %d] Request for algorithm capabilities\n", request->owner_pid);
        return ax_tpm2_server_cc_get_capability_algorithms_sync(fd, request, property_count_cpu);
    case TPM2_CAP_HANDLES: // Handle capabilities
    case TPM2_CAP_COMMANDS: // Command capabilities
    case TPM2_CAP_PP_COMMANDS: // Physical presence (PP) capabilities
    case TPM2_CAP_AUDIT_COMMANDS: // Physical audit capabilities
    case TPM2_CAP_PCRS: // PCR capabilities (reserved)
    case TPM2_CAP_TPM_PROPERTIES: // TPM property capabilities (reserved)
    case TPM2_CAP_PCR_PROPERTIES: // PCR property capabilities (reserved)
    case TPM2_CAP_ECC_CURVES: // ECC curve capabilities (reserved)
    case TPM2_CAP_AUTH_POLICIES: // Auth policies capabilities (reserved)
    case TPM2_CAP_ACT: // Authenticated countdown timer (ACT) capabilities (reserved)
    case TPM2_CAP_VENDOR_PROPERTY: // vendor-specific capabilities (reserved)
    default:
        return ax_tpm2_server_cc_failure(fd, request, TPM2_RC_COMMAND_CODE);
    }

    return bytes_written;
}

ssize_t
ax_tpm2_server_cc_get_capability_algorithms_sync(int fd, tpm2_op_request *request, uint32_t property_count_cpu) {
    ssize_t bytes_written = 0;
    tpm2_op_response *response = NULL;
    TPMS_CAPABILITY_DATA *capability_data = NULL;
    uint32_t post_header_bytes = sizeof(TPMI_YES_NO) + sizeof(*capability_data);
    TPMI_YES_NO more_data = TPM2_NO; // No more data after this capability reply
    uint32_t offset = 0;
    TPMS_ALG_PROPERTY rsa;
    TPMS_ALG_PROPERTY sha256;
    char* buf = NULL;
    uint32_t buf_len = 0;
    tpm20_header_in magic_header;
    bool write_complete = false;

    if (!request) {
        goto exit_ax_tpm2_server_cc_get_capability_algorithms;
    }

    // Allocate a response object
    response = malloc(sizeof(*response));
    if (!response) {
        goto exit_ax_tpm2_server_cc_get_capability_algorithms;
    }
    // Clear the response struct
    memset(response, 0, sizeof(*response));

    capability_data = malloc(sizeof(*capability_data));
    if (!capability_data) {
        goto exit_ax_tpm2_server_cc_get_capability_algorithms;
    }
    // Clear the capability data struct
    memset(capability_data, 0, sizeof(*capability_data));


    // 1) Copy the tag from the incoming request
    response->header.tag = request->header.tag;
    // 2) Copy the owner pid
    response->owner_pid = request->owner_pid;
    // 3) Copy the command code
    response->command_code_cpu = tpm2_be32_to_cpu(request->header.command_code);
    // 4) Set the response size:
    // [header (10 bytes)                ]
    // [TPMI_YES_NO (1 byte)             ]
    // [TPMS_CAPABILITY_DATA (1032 bytes)]
    response->header.response_size = tpm2_cpu_to_be32(sizeof(tpm20_header_out) + post_header_bytes);
    // 5) Set the response code as success
    response->header.response_code = tpm2_cpu_to_be32(TPM2_RC_SUCCESS);
    // 6) Allocate a buffer for the post-header bytes
    response->buf = malloc(post_header_bytes);
    if (!response->buf) {
        goto exit_ax_tpm2_server_cc_get_capability_algorithms;
    }
    // 7) Clear out newly allocated buffer
    memset(response->buf, 0, post_header_bytes);
    // 8) Fill out the post-header byte values [TPM2_YES_NO][TPMS_CAPABILITY_DATA]
    memcpy(response->buf, &more_data, sizeof(more_data));
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

    memcpy(response->buf + offset, capability_data, sizeof(*capability_data));

    // Convert the response to a byte buffer and write it to the device
    // Buffer format: [magic header][header][owner pid][command code cpu][bytes consumed][post-header bytes]
    buf_len = \
        sizeof(tpm20_header_in) + \
        sizeof(response->header) + \
        sizeof(uint32_t) + \
        sizeof(uint32_t) + \
        sizeof(uint32_t) + \
        post_header_bytes;
    buf = malloc(buf_len);
    if (!buf) {
        goto exit_ax_tpm2_server_cc_get_capability_algorithms;
    }
    memset(buf, 0, buf_len);
    // Pack this buffer
    memset(&magic_header, 0, sizeof(magic_header));
    // Create our magic header so the device driver can peel it off and process the rest of the message
    magic_header.tag = tpm2_cpu_to_be16(TPM2_ST_AXIADO);
    magic_header.command_code = tpm2_cpu_to_be32(TPM2_CC_AX_TCU_PRIV_WRITE);
    magic_header.command_size = tpm2_cpu_to_be32(buf_len);
    // Buffer sections:
    // 1. [ax magic header     ] - 10 bytes (used to signal device driver)
    // 2. [header              ] - 10 bytes
    // 3. [owner pid           ] - 4 bytes
    // 4. [command code cpu    ] - 4 bytes
    // 5. [bytes consumed      ] - 4 bytes
    // 6. [more capability data] - 1 byte
    // 7. [capability bytes    ] - capability response (1032 bytes)
    // 33 + 1032 = 1065

    // Sections 2 and 6+7 are concatenated to be returned to the client as the
    // actual TPM 2.0 compliant response

    // Server reply preamble:
    // 1) Write the magic header
    // 2) Write the response header
    // 3) Write the owner pid
    // 4) Write the command code (in cpu format) so we can debug what the client's original request was
    // 5) Write bytes consumed
    offset = 0;
    ssize_t preamble_bytes = write_server_reply_preamble(buf, buf_len, &magic_header, response, &offset);

    // 6) Write whether there is more capability data
    memcpy(buf+offset, &more_data, sizeof(more_data));
    offset += sizeof(more_data);

    // 7) Write the capability data (pointer) itself
    memcpy(buf+offset, capability_data, sizeof(*capability_data));
    offset += sizeof(*capability_data);

    printf("[AXIADO_TPM2_SERVER] Preamble bytes    : %ld\n", preamble_bytes);
    printf("[AXIADO_TPM2_SERVER] Command code (cpu): 0x%x\n", response->command_code_cpu);
    printf("[AXIADO_TPM2_SERVER] Bytes consumed    : %d\n", response->bytes_consumed);
    printf("[AXIADO_TPM2_SERVER] Post-header bytes : %d\n", post_header_bytes);
    printf("[AXIADO_TPM2_SERVER] Buf len           : %d\n", buf_len);
    printf("[AXIADO_TPM2_SERVER] Offset            : %d\n", offset);

    // Now write this entire buffer to the device
    while (!write_complete) {
        bytes_written = write(fd, buf, buf_len);
        if (bytes_written == -1) {
            const int err = errno;
            if (err == EINTR) {
                continue;
            }
            fprintf(stderr, "[AXIADO_TPM2_SERVER] Unable to write up to %d bytes. Reason: %s\n",
                    buf_len, strerror(err));
            bytes_written = -1;
            goto exit_ax_tpm2_server_cc_get_capability_algorithms;
        }
        write_complete = true;
        if (bytes_written == 0) {
            goto exit_ax_tpm2_server_cc_get_capability_algorithms;
        }
    }

 exit_ax_tpm2_server_cc_get_capability_algorithms:
    if (capability_data) {
        free(capability_data);
        capability_data = NULL;
    }

    // Clean up the response struct
    if (response) {
        if (response->buf) {
            free(response->buf);
            response->buf = NULL;
        }
        free(response);
        response = NULL;
    }
    return bytes_written;
}

ssize_t
ax_tpm2_server_cc_start_auth_session_response_sync(int fd, tpm2_op_request *request) {
    ssize_t bytes_written = 0;
    TPMI_DH_OBJECT tpm_key_be = 0; // 4 bytes
    TPMI_DH_ENTITY bind_be = 0; // 4 bytes
    TPM2B_NONCE nonce_caller;
    uint32_t offset = 0;
    TPM2B_ENCRYPTED_SECRET encrypted_salt;
    TPM2_SE session_type = 0; // 1 byte
    TPMT_SYM_DEF symmetric; // 6 bytes
    TPMI_ALG_HASH auth_hash; // 2 bytes

    tpm2_op_response *response = NULL;
    TPM2B_NONCE nonce_tpm;
    uint32_t post_header_bytes = 0;
    uint32_t session_handle = 0x55555555;

    char* buf = NULL;
    uint32_t buf_len = 0;
    tpm20_header_in magic_header;
    bool write_complete = false;

    if (!request) {
        goto exit_ax_tpm2_server_cc_start_auth_session;
    }

    // Allocate a response object
    response = malloc(sizeof(*response));
    if (!response) {
        goto exit_ax_tpm2_server_cc_start_auth_session;
    }
    // Clear the response object
    memset(response, 0, sizeof(*response));

    // 49 bytes post-header example
    // 4 (tpm_key) + 4 (bind) + 34 (size+nonce/digest) + 2 (size+salt) + 1 (session_type) + 2 (symmetric) + 2 (hash)

    memset(&nonce_caller, 0, sizeof(nonce_caller));
    memset(&encrypted_salt, 0, sizeof(encrypted_salt));
    memset(&symmetric, 0, sizeof(symmetric));
    memset(&nonce_tpm, 0, sizeof(nonce_tpm));

    memcpy(&tpm_key_be, request->buf, sizeof(tpm_key_be));
    offset += sizeof(tpm_key_be);
    memcpy(&bind_be, request->buf+offset, sizeof(bind_be));
    offset += sizeof(bind_be);

    // We're about to copy a digest but we don't know how many bytes we actually have
    memcpy(&nonce_caller, request->buf+offset, sizeof(nonce_caller.size));
    offset += sizeof(nonce_caller.size);
    // Convert the BE value to cpu
    nonce_caller.size = tpm2_be16_to_cpu(nonce_caller.size);
    // Now copy the nonce bytes
    memcpy(nonce_caller.buffer, request->buf+offset, nonce_caller.size);
    offset += nonce_caller.size;

    // Next up copy the encrypted salt but we don't know how many bytes we have
    memcpy(&encrypted_salt, request->buf+offset, sizeof(encrypted_salt.size));
    offset += sizeof(encrypted_salt.size);
    encrypted_salt.size = tpm2_be16_to_cpu(encrypted_salt.size);
    // Now copy the bytes
    memcpy(encrypted_salt.secret, request->buf+offset, encrypted_salt.size);
    offset += encrypted_salt.size;

    // Copy the session type (1 byte)
    // #define TPM2_SE_HMAC    ((TPM2_SE) 0x00)
    // #define TPM2_SE_POLICY  ((TPM2_SE) 0x01)
    // #define TPM2_SE_TRIAL   ((TPM2_SE) 0x03)

    memcpy(&session_type, request->buf+offset, sizeof(session_type));
    offset += sizeof(session_type);

    // Copy the symmetric data
    // printf("[AXIADO_TPM2_COMPAT] sizeof(symmetric): %ld", sizeof(symmetric));
    // First get the algorithm ID, it can be TPM2_ALG_NULL (0x0010)

    memcpy(&symmetric, request->buf+offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    symmetric.algorithm = tpm2_be16_to_cpu(symmetric.algorithm);
    if (symmetric.algorithm != TPM2_ALG_NULL) {
        // Then read the key bits and mode uint16_t values
        // Rewind the offset pointer and read the entire 6 bytes of the symmetric struct
        offset -= sizeof(uint16_t);
        memcpy(&symmetric, request->buf+offset, sizeof(symmetric));
        offset += sizeof(symmetric);
    }

    // Copy the auth hash (it won't be TPM2_ALG_NULL)
    memcpy(&auth_hash, request->buf+offset, sizeof(auth_hash));
    offset += sizeof(auth_hash);

    // Now build a response
    // 1) Copy the tag from the incoming request
    response->header.tag = request->header.tag;
    // 2) Copy the owner pid
    response->owner_pid = request->owner_pid;
    // 3) Copy the command code
    response->command_code_cpu = tpm2_be32_to_cpu(request->header.command_code);
    // 4) Set the response size [header][session handle][nonce 2+32 bytes for a sha256 hash]
    post_header_bytes = sizeof(TPMI_SH_AUTH_SESSION) + sizeof(uint16_t) + 32;
    response->header.response_size = tpm2_cpu_to_be32(sizeof(tpm20_header_out) + post_header_bytes);
    // 5) Set the response code as success
    response->header.response_code = tpm2_cpu_to_be32(TPM2_RC_SUCCESS);
    // 6) Allocate a buffer for the post-header bytes
    response->buf = malloc(post_header_bytes);
    if (!response->buf) {
        goto exit_ax_tpm2_server_cc_start_auth_session;
    }

    // 7) Clear out the newly allocated buffer
    memset(response->buf, 0, post_header_bytes);
    offset = 0;
    // 8) Fill in the post-header byte values [session handle][nonce 2+32 bytes for a sha256 hash]
    memcpy(response->buf, &session_handle, sizeof(session_handle));
    offset += sizeof(session_handle);
    nonce_tpm.size = tpm2_cpu_to_be16(nonce_caller.size);
    memcpy(nonce_tpm.buffer, nonce_caller.buffer, nonce_caller.size);
    memcpy(response->buf+offset, &nonce_tpm, sizeof(nonce_tpm.size) + nonce_caller.size);

    // Convert the response into a buffer and write it to the device.
    // Buffer format should be [ax magic header][header][owner pid][command code cpu][bytes consumed][post-header bytes]
    buf_len = \
        sizeof(tpm20_header_in) + \
        sizeof(response->header) + \
        sizeof(uint32_t) + \
        sizeof(uint32_t) + \
        sizeof(uint32_t) + \
        post_header_bytes;

    buf = malloc(buf_len);
    if (!buf) {
        goto exit_ax_tpm2_server_cc_start_auth_session;
    }
    // Clear this buffer
    memset(buf, 0, buf_len);

    // Pack this buffer
    memset(&magic_header, 0, sizeof(magic_header));
    // Create our magic header so the device driver can peel it off and process the rest of the message
    magic_header.tag = tpm2_cpu_to_be16(TPM2_ST_AXIADO);
    magic_header.command_code = tpm2_cpu_to_be32(TPM2_CC_AX_TCU_PRIV_WRITE);
    magic_header.command_size = tpm2_cpu_to_be32(buf_len);
    offset = 0;

    // Buffer sections:
    // 1. [ax magic header] - 10 bytes (used to signal device driver)
    // 2. [header] - 10 bytes
    // 3. [owner pid] - 4 bytes
    // 4. [command code cpu] - 4 bytes
    // 5. [bytes consumed] - 4 bytes
    // 6. [post-header bytes] - post_header_bytes

    // Sections 2 and 6 are concatenated to be returned to the client as the
    // actual TPM 2.0 compliant response

    // Server reply preamble:
    // 1) Write the magic header
    // 2) Write the response header
    // 3) Write the owner pid
    // 4) Write the command code (in cpu format) so we can debug what the client's original request was
    // 5) Write bytes consumed
    write_server_reply_preamble(buf, buf_len, &magic_header, response, &offset);
    // 6) Write the remaining bytes
    memcpy(buf+offset, response->buf, post_header_bytes);
    offset += post_header_bytes;

    // Now write this entire buffer to the device
    while (!write_complete) {
        bytes_written = write(fd, buf, buf_len);
        if (bytes_written == -1) {
            const int err = errno;
            if (err == EINTR) {
                continue;
            }
            fprintf(stderr, "[AXIADO_TPM2_SERVER] Unable to write up to %d bytes. Reason: %s\n",
                    buf_len, strerror(err));
            bytes_written = -1;
            goto exit_ax_tpm2_server_cc_start_auth_session;
        }
        write_complete = true;
        if (bytes_written == 0) {
            goto exit_ax_tpm2_server_cc_start_auth_session;
        }
    }

 exit_ax_tpm2_server_cc_start_auth_session:

    if (response) {
        if (response->buf) {
            free(response->buf);
            response->buf = NULL;
        }

        free(response);
        response = NULL;
    }

    if (buf) {
        free(buf);
        buf = NULL;
    }

    return bytes_written;
}

ssize_t
ax_tpm2_server_cc_create_primary_sync(int fd, tpm2_op_request *request) {
    ssize_t bytes_written;
    uint32_t request_payload_bytes = get_op_request_post_header_request_bytes(request);
    // Request payload
    // [TPMI_RH_HIERARCHY+     @primaryHandle] - 4 byte handle
    // [TPM2B_SENSITIVE_CREATE inSensitive   ] - struct
    // [TPM2B_PUBLIC           inPublic      ] - struct
    // [TPM2B_DATA             outsideInfo   ] - struct
    // [TPML_PCR_SELECTION     creationPCR   ] - struct
    TPMI_RH_HIERARCHY primary_handle;
    TPM2B_SENSITIVE_CREATE in_sensitive;
    TPM2B_PUBLIC in_public;
    TPM2B_DATA outside_info;
    TPML_PCR_SELECTION creation_pcr;

    // Response payload
    // [TPM_HANDLE objectHandle         ] - 4 byte handle
    // [Parameter Size                  ] - 4 byte (not shown in PDU because command has auth session/area)
    // [TPM2B_PUBLIC outPublic          ] - struct
    // [TPM2B_CREATION_DATA creationData] - struct
    // [TPM2B_DIGEST creationHash       ] - struct
    // [TPMT_TK_CREATION creationTicket ] - struct
    // [TPM2B_NAME name                 ] - struct
    tpm2_op_response *response = NULL;
    TPM2_HANDLE object_handle = 0;
    uint32_t parameter_size = 0;
    TPM2B_PUBLIC out_public;
    TPM2B_CREATION_DATA creation_data;
    TPM2B_DIGEST creation_hash;
    TPMT_TK_CREATION creation_ticket;
    TPM2B_NAME name;

    char *buf = NULL;
    uint32_t buf_len = 0;
    uint32_t offset = 0;
    int i = 0;
    uint32_t authorization_size_be = 0;
    // RSA key config
    RSA *rsa_key = NULL;
    BIGNUM *bne = NULL;
    uint16_t key_bits = 0;
    uint32_t exponent = 0;

    // The min authorization size is based on
    // the TPMS_AUTH_COMMAND type
    uint32_t min_authorization_size = \
        sizeof(TPM2_HANDLE) + \
        sizeof(uint16_t) + \
        sizeof(TPMA_SESSION) + \
        sizeof(uint16_t);

    TPMS_AUTH_COMMAND authorization_area;

    // Clear out all the request payload structs
    memset(&primary_handle, 0, sizeof(primary_handle));
    memset(&in_sensitive, 0, sizeof(in_sensitive));
    memset(&in_public, 0, sizeof(in_public));
    memset(&outside_info, 0, sizeof(outside_info));
    memset(&creation_pcr, 0, sizeof(creation_pcr));

    // Clear out the authorization area struct
    memset(&authorization_area, 0, sizeof(authorization_area));

    if (!request) {
        goto exit_ax_tpm2_server_cc_create_primary;
    }

    // Create primary requires a session, so check that the tag is correct
    if (get_op_request_command_tag(request) != TPM2_ST_SESSIONS) {
        // We expect there to be an authorizationSize (32 bit) right after the handle
        bytes_written = ax_tpm2_server_cc_failure(fd, request, TPM2_RC_AUTH_MISSING);
        goto exit_ax_tpm2_server_cc_create_primary;
    }

    // Allocate a response
    response = malloc(sizeof(*response));
    if (!response) {
        goto exit_ax_tpm2_server_cc_create_primary;
    }
    // Clear the response object
    memset(response, 0, sizeof(*response));

    offset = 0;
    if (request_payload_bytes <= 0) {
        bytes_written = ax_tpm2_server_cc_failure(fd, request, TPM2_RC_NO_RESULT);
        goto exit_ax_tpm2_server_cc_create_primary;
    }


    for(i = 0; i < request_payload_bytes; i++) {
        printf("%d -> 0x%x\n", i, *(request->buf+i));
    }

    printf("[AXIADO_TPM2_SERVER] Request payload bytes: %d\n", request_payload_bytes);
    // Start parsing
    memcpy(&primary_handle, request->buf, sizeof(primary_handle));
    offset += sizeof(primary_handle);
    printf("[AXIADO_TPM2_SERVER] primary handle: 0x%x (offset: %d)\n", tpm2_be32_to_cpu(primary_handle), offset);

    // Because this is a command with sessions we need to parse the auth area (auth areas *do not* show up in the
    // PDU schematics in the spec - see Spec part 3 section 5.4, 5.5 for how to parse)
    memcpy(&authorization_size_be, request->buf+offset, sizeof(authorization_size_be));
    offset += sizeof(authorization_size_be);
    printf("[AXIADO_TPM2_SERVER] Authorization size: %d (offset: %d)\n", tpm2_be32_to_cpu(authorization_size_be), offset);

    // Make sure the authorization area is bigger than the minimum expected size
    if (tpm2_be32_to_cpu(authorization_size_be) < min_authorization_size) {
        bytes_written = ax_tpm2_server_cc_failure(fd, request, TPM2_RC_AUTHSIZE);
        goto exit_ax_tpm2_server_cc_create_primary;
    }

    // If this parse attempt fails then something is wrong so bail out, return TPM2_RC_NO_RESULT
    // to signal an input error
    if (read_authorization_area(request->buf, request_payload_bytes - offset, &offset, &authorization_area) <= 0) {
        bytes_written = ax_tpm2_server_cc_failure(fd, request, TPM2_RC_NO_RESULT);
        goto exit_ax_tpm2_server_cc_create_primary;
    }
    printf("[AXIADO_TPM2_SERVER] Post-authorization parsing auth-area size: %d (offset: %d)\n", tpm2_be32_to_cpu(authorization_size_be), offset);

    // Once we read the authorization section move onto parsing the remaining parameters

    // Parse TPM2B_SENSITIVE_CREATE in_sensitive
    if (read_tpm2b_sensitive_create(request->buf, request_payload_bytes - offset, &offset, &in_sensitive) <= 0) {
        bytes_written = ax_tpm2_server_cc_failure(fd, request, TPM2_RC_NO_RESULT);
        goto exit_ax_tpm2_server_cc_create_primary;
    }
    printf("[AXIADO_TPM2_SERVER] Post-sensitive parsing (offset: %d)\n", offset);

    // Parse TPM2B_PUBLIC in_public
    if (read_tpm2b_public(request->buf, request_payload_bytes - offset, &offset, &in_public) <= 0) {
        bytes_written = ax_tpm2_server_cc_failure(fd, request, TPM2_RC_NO_RESULT);
        goto exit_ax_tpm2_server_cc_create_primary;
    }
    printf("[AXIADO_TPM2_SERVER] Post-in_public parsing (offset: %d)\n", offset);

    // Parse TPM2B_DATA outsideInfo
    if (read_tpm2b_data(request->buf, request_payload_bytes - offset, &offset, &outside_info) <= 0) {
        bytes_written = ax_tpm2_server_cc_failure(fd, request, TPM2_RC_NO_RESULT);
        goto exit_ax_tpm2_server_cc_create_primary;
    }
    printf("[AXIADO_TPM2_SERVER] Post-outside_info parsing (offset: %d)\n", offset);

    // Parse TPML_PCR_SELECTION creationPCR
    if (read_tpml_pcr_selection(request->buf, request_payload_bytes - offset, &offset, &creation_pcr) <= 0) {
        bytes_written = ax_tpm2_server_cc_failure(fd, request, TPM2_RC_NO_RESULT);
        goto exit_ax_tpm2_server_cc_create_primary;
    }
    printf("[AXIADO_TPM2_SERVER] Post-creation_pcr parsing (offset: %d)\n", offset);

    // Dump some of the structs to see what we actually need to do
    dump_tpm2b_sensitive_create(&in_sensitive);
    // Pass in the public area type so we can decode it correctly
    dump_tpm2b_public(&in_public);
    dump_tpm2b_data(&outside_info);
    dump_tpml_pcr_selection(&creation_pcr);

    // We expect to be asked for an RSA key
    if (tpm2_be16_to_cpu(in_public.publicArea.type) == TPM2_ALG_RSA) {
        // Extract symmetric, scheme
        TPMT_SYM_DEF_OBJECT symmetric;
        TPMT_RSA_SCHEME scheme;

        memset(&symmetric, 0, sizeof(symmetric));
        memset(&scheme, 0, sizeof(scheme));

        key_bits = tpm2_be16_to_cpu(in_public.publicArea.parameters.rsaDetail.keyBits);
        exponent = tpm2_be32_to_cpu(in_public.publicArea.parameters.rsaDetail.exponent);
        if (exponent == 0) {
            // Use default of 216 + 1 per tss2_tpm2_types.h
            exponent = 216 + 1;
        }

        printf("[AXIADO_TPM2_SERVER] Handling RSA key-gen request - key bits: %d, exponent: %d\n", key_bits, exponent);
        /* ====================================== */
        /* This is where we would call CoreLockr to do key-gen instead of openssl*/
        // Generate a new RSA key (using openssl for now)
        bne = BN_new();
        if (BN_set_word(bne, exponent) != 1) {
            bytes_written = ax_tpm2_server_cc_failure(fd, request, TPM2_RC_COMMAND_CODE);
            goto exit_ax_tpm2_server_cc_create_primary;
        }
        rsa_key = RSA_new();
        RSA_generate_key_ex(rsa_key, key_bits, bne, NULL);

        // Now we have to write the response back to the driver so the caller/client can get it.
        // Recall that since this command came in with an auth section we have to write a
        // parameter size value immediately after the handle that we will return for this object.
        // Parameter size = the number of bytes in out_public, creation_data, creation_hash,
        // creation_ticket, name

        /* ====================================== */

        // [TPM_HANDLE objectHandle         ] - 4 byte handle
        // [Parameter Size                  ] - 4 byte (not shown in PDU because command has auth session/area)
        // [TPM2B_PUBLIC outPublic          ] - struct
        // [TPM2B_CREATION_DATA creationData] - struct
        // [TPM2B_DIGEST creationHash       ] - struct
        // [TPMT_TK_CREATION creationTicket ] - struct
        // [TPM2B_NAME name                 ] - struct

        // Clear return structs
        object_handle = 0xAAAAAAAA; // Fake handle
        memset(&out_public, 0, sizeof(out_public));
        memset(&creation_data, 0, sizeof(creation_data));
        memset(&creation_hash, 0, sizeof(creation_hash));
        memset(&creation_ticket, 0, sizeof(creation_ticket));
        memset(&name, 0, sizeof(name));

        // Write data in out_public
        out_public.publicArea.type = tpm2_cpu_to_be16(TPM2_ALG_RSA); // 2 bytes
        out_public.publicArea.nameAlg = tpm2_cpu_to_be16(TPM2_ALG_NULL); // 2 bytes
        out_public.publicArea.objectAttributes = in_public.publicArea.objectAttributes; // 4 bytes (copy input attribs)
        out_public.publicArea.authPolicy = in_public.publicArea.authPolicy; // struct (copy input auth policy)
        // Write publicArea.parameters union.
        // Since we're generating an RSA key we are writing to publicArea.parameters.rsaDetail
        // In rsaDetails write the key bits and the exponent we used
        out_public.publicArea.parameters.rsaDetail.symmetric = in_public.publicArea.parameters.rsaDetail.symmetric;
        out_public.publicArea.parameters.rsaDetail.scheme = in_public.publicArea.parameters.rsaDetail.scheme;
        out_public.publicArea.parameters.rsaDetail.keyBits = in_public.publicArea.parameters.rsaDetail.keyBits;
        out_public.publicArea.parameters.rsaDetail.exponent = tpm2_cpu_to_be32(exponent);
        // Now write the unique data (for RSA with will be the public key)
    }

    // Until we finish the implementation return not supported
    bytes_written = ax_tpm2_server_cc_failure(fd, request, TPM2_RC_COMMAND_CODE);
 exit_ax_tpm2_server_cc_create_primary:

    if (bne) {
        BN_free(bne);
        bne = NULL;
    }

    if (rsa_key) {
        RSA_free(rsa_key);
        rsa_key = NULL;
    }

    if (response) {
        if (response->buf) {
            free(response->buf);
            response->buf = NULL;
        }

        free(response);
        response = NULL;
    }

    if (buf) {
        free(buf);
        buf = NULL;
    }
    return bytes_written;
}

ssize_t
ax_tpm2_server_cc_flush_context_response_sync(int fd, tpm2_op_request *request) {
    ssize_t bytes_written = 0;
    tpm2_op_response *response = NULL;
    char *buf = NULL;
    uint32_t buf_len = 0;
    TPMI_DH_CONTEXT handle = 0;

    if (!request) {
        goto exit_ax_tpm2_server_cc_flush_context;
    }

    // Allocate a response
    response = malloc(sizeof(*response));
    if (!response) {
        goto exit_ax_tpm2_server_cc_flush_context;
    }
    // Clear the response object
    memset(response, 0, sizeof(*response));

    if (get_op_request_post_header_request_bytes(request) > 0) {
        memcpy(&handle, request->buf, sizeof(TPMI_DH_CONTEXT));
        // Convert the handle to CPU endian
        handle = tpm2_be32_to_cpu(handle);
        printf("[AXIADO_TPM2_SERVER] handle to flush: 0x%x\n", handle);
    }

    // Not actually an error, we just want to signal that we've flushed so use
    // the success return code (RC) instead of a true error code
    bytes_written = ax_tpm2_server_cc_failure(fd, request, TPM2_RC_SUCCESS);

 exit_ax_tpm2_server_cc_flush_context:

    if (response) {
        if (response->buf) {
            free(response->buf);
            response->buf = NULL;
        }

        free(response);
        response = NULL;
    }

    if (buf) {
        free(buf);
        buf = NULL;
    }

    return bytes_written;
}

int
main(void) {
    int fd = -1;
    int num_reads = 5; // 1;//000000;
    printf("[AXIADO_TPM2_SERVER] Starting vTPM TPM2 server...\n");
    srand(time(0));

    // Open the device
    fd = open(DEFAULT_DEVICE, O_RDWR);
    if (fd == -1) {
        const int err = errno;
        fprintf(stderr, "[AXIADO_TPM2_SERVER] Open failed on: %s. Reason: %s\n",
                DEFAULT_DEVICE, strerror(err));
        exit(EXIT_FAILURE);
    }

    // Read the device to see if clients have pending requests
    for(int i = 0; i < num_reads; i++) {
        tpm2_op_request client_request;
        ssize_t bytes_written = 0;
        ssize_t bytes_read = 0;
        uint32_t command_code_cpu = TPM2_CC_INVALID;

        printf("[AXIADO_TPM2_SERVER] Reading device, attempt: %d\n", i);

        // Clear out the client request struct
        memset(&client_request, 0, sizeof(client_request));
        bytes_read = ax_tpm2_server_query_sync(fd, &client_request);
        if (bytes_read == 0) {
            printf("[AXIADO_TPM2_SERVER] Unable to read client request\n");
            // Free the command buffer if any was allocated
            if (client_request.buf) {
                free(client_request.buf);
                client_request.buf = NULL;
            }
            continue;
        }

        command_code_cpu = tpm2_be32_to_cpu(client_request.header.command_code);

        // Parse and handle it
        switch(command_code_cpu) {
        case TPM2_CC_GetRandom:
            // Expect the number of bytes written
            bytes_written = ax_tpm2_server_cc_get_random_response_sync(fd, &client_request);
            break;
        case TPM2_CC_GetCapability:
            bytes_written = ax_tpm2_server_cc_get_capability_response_sync(fd, &client_request);
            break;
        case TPM2_CC_StartAuthSession:
            bytes_written = ax_tpm2_server_cc_start_auth_session_response_sync(fd, &client_request);
            break;
        case TPM2_CC_CreatePrimary:
            bytes_written = ax_tpm2_server_cc_create_primary_sync(fd, &client_request);
            break;
        case TPM2_CC_FlushContext:
            bytes_written = ax_tpm2_server_cc_flush_context_response_sync(fd, &client_request);
            break;
        default:
            printf("[AXIADO_TPM2_SERVER] Unexpected/invalid TPM2 command_code: 0x%x in client request\n", command_code_cpu);
            // TPM2_RC_COMMAND_CODE -> unsupported command
            bytes_written = ax_tpm2_server_cc_failure(fd, &client_request, TPM2_RC_COMMAND_CODE);
            break;
        }

        if (bytes_written == 0) {
            printf("[AXIADO_TPM2_SERVER] Unable to write client response\n");
        }

        // Free the command buffer if any was allocated
        if (client_request.buf) {
            free(client_request.buf);
            client_request.buf = NULL;
        }
    }

    printf("[AXIADO_TPM2_SERVER] vTPM TPM2 server exiting\n");
cleanup:
    // Close the device
    if (fd != -1) {
        close(fd);
    }
    return 0;
}
