#include <tpm2_axiado.h>

uint16_t
get_op_request_command_tag(tpm2_op_request *op_request) {
    if (!op_request) {
        return TPM2_RC_BAD_TAG;
    }
    return tpm2_be16_to_cpu(op_request->header.tag);
}

uint32_t
get_op_request_command_size(tpm2_op_request *op_request) {
    if (!op_request) {
        return 0;
    }
    return tpm2_be32_to_cpu(op_request->header.command_size);
}

uint32_t
get_op_request_command_code(tpm2_op_request *op_request) {
    if (!op_request) {
        return TPM2_CC_INVALID;
    }
    return tpm2_be32_to_cpu(op_request->header.command_code);
}

uint32_t
get_op_request_post_header_request_bytes(tpm2_op_request *op_request) {
    if (!op_request) {
        return 0;
    }
    return tpm2_be32_to_cpu(op_request->header.command_size) - sizeof(tpm20_header_in);
}

uint16_t
get_op_response_command_tag(tpm2_op_response *op_response) {
    if (!op_response) {
        return TPM2_RC_BAD_TAG;
    }
    return tpm2_be16_to_cpu(op_response->header.tag);
}

uint32_t
get_op_response_response_size(tpm2_op_response *op_response) {
    if (!op_response) {
        return 0;
    }
    return tpm2_be32_to_cpu(op_response->header.response_size);
}

uint32_t
get_op_request_response_code(tpm2_op_response *op_response) {
    if (!op_response) {
        return TPM2_CC_INVALID;
    }
    return tpm2_be32_to_cpu(op_response->header.response_code);
}

uint32_t
get_op_response_post_header_response_bytes(tpm2_op_response *op_response) {
    if (!op_response) {
        return 0;
    }
    return tpm2_be32_to_cpu(op_response->header.response_size) - sizeof(tpm20_header_out);
}


// Marshal/unmarshal routines

uint32_t
read_uint8(char *buf, uint32_t buf_len, uint32_t *offset, uint8_t *ret_val) {
    // Non-null pointers required
    if (!buf || !offset || !ret_val) {
        return -1;
    }
    memset(ret_val, 0, sizeof(*ret_val));
    memcpy(ret_val, buf+*offset, sizeof(*ret_val));
    *offset += sizeof(*ret_val);
    return sizeof(*ret_val);
}

uint32_t
read_uint16(char *buf, uint32_t buf_len, uint32_t *offset, uint16_t *ret_val) {
    // Non-null pointers required
    if (!buf || !offset || !ret_val) {
        return -1;
    }
    memset(ret_val, 0, sizeof(*ret_val));
    memcpy(ret_val, buf+*offset, sizeof(*ret_val));
    *offset += sizeof(*ret_val);
    return sizeof(*ret_val);
}


uint32_t
read_uint32(char *buf, uint32_t buf_len, uint32_t *offset, uint32_t *ret_val) {
    // Non-null pointers required
    if (!buf || !offset || !ret_val) {
        return -1;
    }
    memset(ret_val, 0, sizeof(*ret_val));
    memcpy(ret_val, buf+*offset, sizeof(*ret_val));
    *offset += sizeof(*ret_val);
    return sizeof(*ret_val);
}


uint32_t read_uint64(char *buf, uint32_t buf_len, uint32_t *offset, uint64_t *ret_val) {
    // Non-null pointers required
    if (!buf || !offset || !ret_val) {
        return -1;
    }
    memset(ret_val, 0, sizeof(*ret_val));
    memcpy(ret_val, buf+*offset, sizeof(*ret_val));
    *offset += sizeof(*ret_val);
    return sizeof(*ret_val);
}

uint32_t
read_tpm2b_digest(char *buf, uint32_t buf_len, uint32_t *offset, TPM2B_DIGEST *ret_val) {
    uint16_t digest_size_be = 0;
    uint32_t digest_bytes = 0;

    // Non-null pointers required
    if (!buf || !offset || !ret_val) {
        return -1;
    }

    // offset may be beyond the buf_len because we would be
    // processing a section of a much larger buffer

    // Clear out the ret_val struct
    memset(ret_val, 0, sizeof(*ret_val));

    // When trying to parse a digest, the first 2 bytes are the size
    memcpy(&digest_size_be, buf+*offset, sizeof(digest_size_be));
#ifndef AXIADO_KERNEL
    //printf("[AXIADO_TPM2_SERVER] Digest size: %d, offset: %d\n", tpm2_be16_to_cpu(digest_size_be), *offset);
#endif
    digest_bytes = sizeof(digest_size_be) + tpm2_be16_to_cpu(digest_size_be);
    // Total digest size = sizeof(uint16_t) + digest size
    memcpy(ret_val, buf+*offset, digest_bytes);
    *offset += digest_bytes;
    return digest_bytes;
}

uint32_t
read_tpms_authorization_command(char *buf, uint32_t buf_len, uint32_t *offset, TPMS_AUTH_COMMAND *ret_val) {
    uint32_t ret = 0;
    uint32_t initial_offset = 0;

    if (!buf || !offset || !ret_val) {
        return -1;
    }

    // read session handle
    // read nonce (digest)
    // read tpma session
    // read hmac (digest)

    initial_offset = *offset;
#ifndef AXIADO_KERNEL
    printf("[AXIADO_TPM2_SERVER] Reading handle, offset: %d\n", *offset);
#endif
    ret = read_handle(buf, buf_len, offset, &(ret_val->sessionHandle));
    if (ret <= 0) {
        return ret;
    }

#ifndef AXIADO_KERNEL
    printf("[AXIADO_TPM2_SERVER] Read handle: 0x%x, offset: %d\n", tpm2_be32_to_cpu(ret_val->sessionHandle), *offset);
    printf("[AXIADO_TPM2_SERVER] Reading nonce\n");
#endif
    ret = read_nonce(buf, buf_len, offset, &(ret_val->nonce));
    if (ret <= 0) {
        return ret;
    }

#ifndef AXIADO_KERNEL
    printf("[AXIADO_TPM2_SERVER] Read nonce, offset: %d\n", *offset);
    printf("[AXIADO_TPM2_SERVER] Reading session\n");
#endif
    ret = read_tpma_session(buf, buf_len, offset, &(ret_val->sessionAttributes));
    if (ret <= 0) {
        return ret;
    }

#ifndef AXIADO_KERNEL
    printf("[AXIADO_TPM2_SERVER] Read session, offset: %d\n", *offset);
    printf("[AXIADO_TPM2_SERVER] Reading auth\n");
#endif
    ret = read_auth(buf, buf_len, offset, &(ret_val->hmac));
    if (ret <= 0) {
        return ret;
    }
#ifndef AXIADO_KERNEL
    printf("[AXIADO_TPM2_SERVER] Read auth, offset: %d\n", *offset);
#endif
    return *offset - initial_offset;
}

uint32_t
read_tpm2b_sensitive_create(char *buf, uint32_t buf_len, uint32_t *offset, TPM2B_SENSITIVE_CREATE *ret_val) {
    uint32_t ret = 0;
    uint32_t initial_offset = *offset;

    // Non-null pointers required
    if (!buf || !offset || !ret_val) {
        return -1;
    }

    // read uint16_t
    ret = read_uint16(buf, buf_len, offset, &(ret_val->size));
    if (ret <= 0) {
        #ifndef AXIADO_KERNEL
        printf("[AXIADO_TPM2_SERVER] sensitive size: %d, offset: %d\n", tpm2_be16_to_cpu(ret_val->size), *offset);
        #endif
        return ret;
    }

    // read TPMS_SENSITIVE_CREATE
    ret = read_auth(buf, buf_len, offset, &(ret_val->sensitive.userAuth));
    if (ret <= 0) {
        #ifndef AXIADO_KERNEL
        printf("[AXIADO_TPM2_SERVER] sensitive user auth offset: %d\n", *offset);
        #endif
        return ret;
    }

    ret = read_uint16(buf, buf_len, offset, &(ret_val->sensitive.data.size));
    if (ret <= 0) {
        #ifndef AXIADO_KERNEL
        printf("[AXIADO_TPM2_SERVER] sensitive data size offset: %d\n", *offset);
        #endif
        return ret;
    }

    memcpy(&(ret_val->sensitive.data.buffer), buf+*offset, tpm2_be16_to_cpu(ret_val->sensitive.data.size));
    *offset += tpm2_be16_to_cpu(ret_val->sensitive.data.size);
    return *offset - initial_offset;
}

uint32_t
read_tpm2b_public(char *buf, uint32_t buf_len, uint32_t *offset, TPM2B_PUBLIC *ret_val) {
    uint32_t ret = 0;
    uint32_t initial_offset = *offset;

    // Non-null pointers required
    if (!buf || !offset || !ret_val) {
        return -1;
    }

    // read uint16_t (TPMI_ALG_PUBLIC, it's just a typedef for TPM2_ALG_ID)
    ret = read_tpmi_alg_public(buf, buf_len, offset, &(ret_val->size));
    if (ret <= 0) {
        #ifndef AXIADO_KERNEL
        printf("[AXIADO_TPM2_SERVER] public size: %d, offset: %d\n", tpm2_be16_to_cpu(ret_val->size), *offset);
        #endif
        return ret;
    }

#ifndef AXIADO_KERNEL
    printf("[AXIADO_TPM2_SERVER] public size: %d, offset: %d\n", tpm2_be16_to_cpu(ret_val->size), *offset);
#endif

    // read uint16_t
    ret = read_tpmi_alg_public(buf, buf_len, offset, &(ret_val->publicArea.type));
    if (ret <= 0) {
        #ifndef AXIADO_KERNEL
        printf("[AXIADO_TPM2_SERVER] public area type offset: %d\n", *offset);
        #endif
        return ret;
    }

#ifndef AXIADO_KERNEL
    printf("[AXIADO_TPM2_SERVER] public area type: 0x%x\n", tpm2_be16_to_cpu(ret_val->publicArea.type));
#endif

    // read uint16_t (TPMI_ALG_HASH, it's just a typedef for TPM2_ALG_ID)
    ret = read_tpmi_alg_hash(buf, buf_len, offset, &(ret_val->publicArea.nameAlg));
    if (ret <= 0) {
        return ret;
    }

    // read uint32_t object attributes (TPMA_OBJECT)
    ret = read_tpma_object(buf, buf_len, offset, &(ret_val->publicArea.objectAttributes));
    if (ret <= 0) {
        return ret;
    }

    // Read digest (TPM2B_DIGEST)
    ret = read_tpm2b_digest(buf, buf_len, offset, &(ret_val->publicArea.authPolicy));
    if (ret <= 0) {
        return ret;
    }

#ifndef AXIADO_KERNEL
    printf("[AXIADO_TPM2_SERVER] TPMS_KEYEDHASH_PARMS: %ld\n" \
           "[AXIADO_TPM2_SERVER] TPMS_SYMCIPHER_PARMS: %ld\n" \
           "[AXIADO_TPM2_SERVER] TPMS_RSA_PARMS      : %ld\n" \
           "[AXIADO_TPM2_SERVER] TPMS_ECC_PARMS      : %ld\n" \
           "[AXIADO_TPM2_SERVER] TPMS_ASYM_PARMS     : %ld\n", \
           sizeof(TPMS_KEYEDHASH_PARMS),
           sizeof(TPMS_SYMCIPHER_PARMS),
           sizeof(TPMS_RSA_PARMS),
           sizeof(TPMS_ECC_PARMS),
           sizeof(TPMS_ASYM_PARMS));
#endif

    // How we read the public parameters depends on the algorithm type (TPMU_PUBLIC_PARMS)
    /*
      TPMU_UNMARSHAL2(TPMU_PUBLIC_PARMS,
      TPM2_ALG_KEYEDHASH, keyedHashDetail, Tss2_MU_TPMS_KEYEDHASH_PARMS_Unmarshal,
      TPM2_ALG_SYMCIPHER, symDetail, Tss2_MU_TPMS_SYMCIPHER_PARMS_Unmarshal,
      TPM2_ALG_RSA, rsaDetail, Tss2_MU_TPMS_RSA_PARMS_Unmarshal,
      TPM2_ALG_ECC, eccDetail, Tss2_MU_TPMS_ECC_PARMS_Unmarshal)
     */
    switch (tpm2_be16_to_cpu(ret_val->publicArea.type)) {
    case TPM2_ALG_RSA:
        ret = read_tpms_rsa_parms(buf, buf_len, offset, &(ret_val->publicArea.parameters.rsaDetail));
        break;
        // Remaining cases to implement
    case TPM2_ALG_KEYEDHASH:
    case TPM2_ALG_SYMCIPHER:
    case TPM2_ALG_ECC:
    default:
        ret = -1;
    }

    if (ret <= 0) {
        return ret;
    }

    /*
      TPMU_UNMARSHAL2(TPMU_PUBLIC_ID,
      TPM2_ALG_KEYEDHASH, keyedHash, Tss2_MU_TPM2B_DIGEST_Unmarshal,
      TPM2_ALG_SYMCIPHER, sym, Tss2_MU_TPM2B_DIGEST_Unmarshal,
      TPM2_ALG_RSA, rsa, Tss2_MU_TPM2B_PUBLIC_KEY_RSA_Unmarshal,
      TPM2_ALG_ECC, ecc, Tss2_MU_TPMS_ECC_POINT_Unmarshal)
     */
    switch (tpm2_be16_to_cpu(ret_val->publicArea.type)) {
    case TPM2_ALG_RSA:
        ret = read_tpm2b_public_key_rsa(buf, buf_len, offset, &(ret_val->publicArea.unique.rsa));
        break;
        // TODO: Other cases to consider
    case TPM2_ALG_KEYEDHASH:
    case TPM2_ALG_SYMCIPHER:
    case TPM2_ALG_ECC:
    default:
        ret = -1;
        break;
    }

    if (ret <= 0) {
        return ret;
    }

    return *offset - initial_offset;
}

uint32_t
read_tpms_rsa_parms(char *buf, uint32_t buf_len, uint32_t *offset, TPMS_RSA_PARMS *ret_val) {
    uint32_t ret = 0;
    uint32_t initial_offset = *offset;

    // Non-null pointers required
    if (!buf || !offset || !ret_val) {
        return -1;
    }

    ret = read_tpmt_sym_def_object(buf, buf_len, offset, &(ret_val->symmetric));
    if (ret <= 0) {
        return ret;
    }

    ret = read_tpmt_rsa_scheme(buf, buf_len, offset, &(ret_val->scheme));
    if (ret <= 0) {
        return ret;
    }

    ret = read_tpmi_rsa_key_bits(buf, buf_len, offset, &(ret_val->keyBits));
    if (ret <= 0) {
        return ret;
    }

#ifndef AXIADO_KERNEL
    printf("[AXIADO_TPM2_SERVER] key bits: %d\n", tpm2_be16_to_cpu(ret_val->keyBits));
#endif
    ret = read_uint32(buf, buf_len, offset, &(ret_val->exponent));
    if (ret <= 0) {
        return ret;
    }
#ifndef AXIADO_KERNEL
    printf("[AXIADO_TPM2_SERVER] exponent: %d\n", tpm2_be16_to_cpu(ret_val->exponent));
#endif

    return *offset - initial_offset;
}

uint32_t
read_tpmt_rsa_scheme(char *buf, uint32_t buf_len, uint32_t *offset, TPMT_RSA_SCHEME *ret_val) {
    uint32_t ret = 0;
    uint32_t initial_offset = *offset;

    // Non-null pointers required
    if (!buf || !offset || !ret_val) {
        return -1;
    }

    // uint16_t
    ret = read_tpmi_alg_rsa_scheme(buf, buf_len, offset, &(ret_val->scheme));
    if (ret <= 0) {
        return ret;
    }

#ifndef AXIADO_KERNEL
    printf("[AXIADO_TPM2_SERVER] RSA scheme: 0x%x\n", tpm2_be16_to_cpu(ret_val->scheme));
#endif

    // Parse the scheme details based on the selector value
    /*
      TPMU_UNMARSHAL2(TPMU_ASYM_SCHEME,
      TPM2_ALG_ECDH, ecdh, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
      TPM2_ALG_ECMQV, ecmqv, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
      TPM2_ALG_RSASSA, rsassa, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
      TPM2_ALG_RSAPSS, rsapss, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
      TPM2_ALG_ECDSA, ecdsa, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
      TPM2_ALG_ECDAA, ecdaa, Tss2_MU_TPMS_SCHEME_ECDAA_Unmarshal,
      TPM2_ALG_SM2, sm2, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
      TPM2_ALG_ECSCHNORR, ecschnorr, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal,
      TPM2_ALG_RSAES, rsaes, unmarshal_null,
      TPM2_ALG_OAEP, oaep, Tss2_MU_TPMS_SCHEME_HASH_Unmarshal)
     */

    switch (tpm2_be16_to_cpu(ret_val->scheme)) {
    case TPM2_ALG_NULL:
        // Nothing to do
        break;
    // TODO: Other selectors to implement
    case TPM2_ALG_ECDH:
    case TPM2_ALG_ECMQV:
    case TPM2_ALG_RSASSA:
    case TPM2_ALG_RSAPSS:
    case TPM2_ALG_ECDSA:
    case TPM2_ALG_ECDAA:
    case TPM2_ALG_SM2:
    case TPM2_ALG_ECSCHNORR: // do nothing
    case TPM2_ALG_RSAES:
    case TPM2_ALG_OAEP:
    default:
        ret = -1;
        return ret;
    }

    return *offset - initial_offset;
}

uint32_t
read_tpmt_sym_def_object(char *buf, uint32_t buf_len, uint32_t *offset, TPMT_SYM_DEF_OBJECT *ret_val) {
    uint32_t ret = 0;
    uint32_t initial_offset = *offset;

    // Non-null pointers required
    if (!buf || !offset || !ret_val) {
        return -1;
    }

    // TPMI_ALG_SYM_OBJECT
    ret = read_tpmi_alg_sym_object(buf, buf_len, offset, &(ret_val->algorithm));
    if (ret <= 0) {
        return ret;
    }
#ifndef AXIADO_KERNEL
    printf("[AXIADO_TPM2_SERVER] sym def object algorithm: 0x%x\n", tpm2_be16_to_cpu(ret_val->algorithm));
#endif
    // TODO: key off of 'algorithm' selector field

    // TPMU_SYM_KEY_BITS (16 bits) - every field in this union is the same size so it
    // really doesn't matter which subfield we copy into
    ret =  read_tpmu_sym_key_bits(buf, buf_len, offset, &(ret_val->keyBits.exclusiveOr));
    if (ret <= 0) {
        return ret;
    }

    // TPMU_SYM_MODE - every field in this union is the same size so it
    // really doesn't matter which subfield we copy into
    ret = read_tpmu_sym_mode(buf, buf_len, offset, &(ret_val->mode.sym));
    if (ret <= 0) {
        return ret;
    }
    return *offset - initial_offset;
}

uint32_t
read_tpms_symcipher_parms(char *buf, uint32_t buf_len, uint32_t *offset, TPMS_SYMCIPHER_PARMS *ret_val) {
    uint32_t ret = 0;
    uint32_t initial_offset = *offset;

    // Non-null pointers required
    if (!buf || !offset || !ret_val) {
        return -1;
    }
    ret = read_tpmt_sym_def_object(buf, buf_len, offset, &(ret_val->sym));
    if (ret <= 0) {
        return ret;
    }

    return *offset - initial_offset;
}

uint32_t
read_tpm2b_public_key_rsa(char *buf, uint32_t buf_len, uint32_t *offset, TPM2B_PUBLIC_KEY_RSA *ret_val) {
    uint32_t ret = 0;
    uint32_t initial_offset = *offset;

    // Non-null pointers required
    if (!buf || !offset || !ret_val) {
        return -1;
    }

    ret = read_uint16(buf, buf_len, offset, &(ret_val->size));
    if (ret <= 0) {
        return ret;
    }

    if (tpm2_be16_to_cpu(ret_val->size) > 0) {
        memcpy(ret_val, buf, tpm2_be16_to_cpu(ret_val->size));
        *offset += tpm2_be16_to_cpu(ret_val->size);
    }

    return *offset - initial_offset;
}

uint32_t read_tpm2b_data(char *buf, uint32_t buf_len, uint32_t *offset, TPM2B_DATA *ret_val) {
    uint32_t ret = 0;
    uint32_t initial_offset = *offset;

    // Non-null pointers required
    if (!buf || !offset || !ret_val) {
        return -1;
    }

    ret = read_uint16(buf, buf_len, offset, &(ret_val->size));
    if (ret <= 0) {
        return ret;
    }

    if (tpm2_be16_to_cpu(ret_val->size) > 0) {
        memcpy(ret_val, buf, tpm2_be16_to_cpu(ret_val->size));
        *offset += tpm2_be16_to_cpu(ret_val->size);
    }

    return *offset - initial_offset;
}

uint32_t
read_tpml_pcr_selection(char *buf, uint32_t buf_len, uint32_t *offset, TPML_PCR_SELECTION *ret_val) {
    uint32_t ret = 0;
    uint32_t initial_offset = *offset;
    int i = 0;

    // Non-null pointers required
    if (!buf || !offset || !ret_val) {
        return -1;
    }

    ret = read_uint32(buf, buf_len, offset, &(ret_val->count));
    if (ret <= 0) {
        return ret;
    }

#ifndef AXIADO_KERNEL
    printf("[AXIADO_TPM2_SERVER] PCR selection count: %d\n", tpm2_be32_to_cpu(ret_val->count));
#endif

    for(i = 0; i < tpm2_be32_to_cpu(ret_val->count); i++) {
        ret = read_tpms_pcr_selection(buf, buf_len, offset, &(ret_val->pcrSelections[i]));
        if (ret <= 0) {
            return ret;
        }
    }

    return *offset - initial_offset;
}

uint32_t
read_tpms_pcr_selection(char *buf, uint32_t buf_len, uint32_t *offset, TPMS_PCR_SELECTION *ret_val) {
    uint32_t ret = 0;
    uint32_t initial_offset = *offset;

    // Non-null pointers required
    if (!buf || !offset || !ret_val) {
        return -1;
    }

    ret = read_tpmi_alg_hash(buf, buf_len, offset, &(ret_val->hash));
    if (ret <= 0) {
        return ret;
    }

    ret = read_uint8(buf, buf_len, offset, &(ret_val->sizeofSelect));
    if (ret <= 0) {
        return ret;
    }

    memcpy(ret_val->pcrSelect, buf, ret_val->sizeofSelect);
    *offset += ret_val->sizeofSelect;
    return *offset - initial_offset;
}
