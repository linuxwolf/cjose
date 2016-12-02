
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cjose/cjose.h>

#include "common.h"

// raw AES key value, encoded as base64url
const char *ENC_KEY_B64U = "1xHwLCjLF9_RQf_QoxmUP9yrcbFZuY0wS6fE-SVgnyU";

int main(int argc, char **argv)
{
    cjose_err   err;

    // create JWK from raw key value
    size_t keyspecLen = 0;
    uint8_t *keyspec;
    if (!cjose_base64url_decode(ENC_KEY_B64U, strlen(ENC_KEY_B64U),
                                &keyspec, &keyspecLen,
                                &err))
    {
        fprintf(stderr, "failed to decode base64url-encoded key (%d): %s\n", err.code, err.message);
        return -1;
    }

    cjose_jwk_t *key = cjose_jwk_create_oct_spec(keyspec, keyspecLen, &err);
    if (!key)
    {
        fprintf(stderr, "failed to create JWK (%d): %s\n", err.code, err.message);
        return -1;
    }

    // prepare JWE header
    cjose_header_t  *hdr = cjose_header_new(&err);
    if (    !hdr ||
            !cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_DIR, &err) ||
            !cjose_header_set(hdr, CJOSE_HDR_ENC, CJOSE_HDR_ENC_A256GCM, &err))
    {
        fprintf(stderr, "failed setup header (%d): %s\n", err.code, err.message);
        return -1;
    }

    // prepare input
    uint8_t *plaintext = NULL;
    size_t  plaintextLen = 0;
    if (!_read_stdin(&plaintext, &plaintextLen))
    {
        fprintf(stderr, "failed to read input\n");
        return -1;
    }

    cjose_jwe_t *jwe = cjose_jwe_encrypt(key, hdr, plaintext, plaintextLen, &err);
    if (!jwe)
    {
        fprintf(stderr, "failed to encrypt (%d): %s\n", err.code, err.message);
        return -1;
    }

    char *ciphertext = cjose_jwe_export(jwe, &err);
    if (!ciphertext)
    {
        fprintf(stderr, "failed to export JWE (%d): %s\n", err.code, err.message);
        return -1;
    }

    cjose_jwe_t *rejwe = cjose_jwe_import(ciphertext, strlen(ciphertext), &err);
    if (!rejwe)
    {
        fprintf(stderr, "failed to re-import JWE (%d): %s\n", err.code, err.message);
        return -1;
    }
    
    fprintf(stdout, "%s\n", ciphertext);

    return 0;
}