#ifndef __AXIADO_TYPES_H__
#define __AXIADO_TYPES_H__

# define IO_BUF_SIZE 8192

const int VTPM_OP_KEY_GENERATE_REQUEST    = 1;
const int VTPM_OP_KEY_GENERATE_RESPONSE   = 2;
const int VTPM_OP_DATA_ENCRYPT            = 3;
const int VTPM_OP_DATA_DECRYPT            = 4;

const int VTPM_OP_READ_KEY_REQUEST        = 5;
const int VTPM_OP_SERVICE_KEY_GEN_REQUEST = 6;

const int KEY_TYPE_ECDSA = 40;

size_t sizeof_ax_tpm_request(void);
size_t sizeof_ax_tpm_response(void);

struct ax_tpm_message_header {
    int message_type;
    long transaction_id;
    long data_len;
};

// Rename these as ax_tpm_op_request and ax_tpm_op_response
// so we can use them for a variety of tpm operations not just key
// generation
struct ax_tpm_op_request {
    // Embed the header in the struct
    struct ax_tpm_message_header header;
    int owner_pid;
    int operation;
    // For key gen requests we care about the key type and size
    int key_type;
    int key_size;
    // For other operations (enc/dec, sign/verify) we care about the key_id
    long key_id;
    ssize_t io_buf_bytes;
    // Flexible array member representing a r/w buffer - must be last element of struct
    char io_buf[];
};

struct ax_tpm_op_response{
    // Embed header in struct
    struct ax_tpm_message_header header;
    int owner_pid;
    int operation;
    long key_id;
    ssize_t io_buf_bytes;
    // Flexible array member representing a r/w buffer - must be last element of struct
    char io_buf[];
};

//#ifdef AX_USER
size_t sizeof_ax_tpm_request() {
    // We no longer have to account for the size of the header separately - just add the io buffer size
    return sizeof(struct ax_tpm_op_request);// + IO_BUF_SIZE;
}

size_t sizeof_ax_tpm_response() {
    return sizeof(struct ax_tpm_op_response);// + IO_BUF_SIZE;
}
//#endif

#endif
