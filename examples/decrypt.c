
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

    // prepare input
    char *ciphertext = NULL;
    size_t  ciphertextLen = 0;
    if (!_read_stdin((uint8_t **)&ciphertext, &ciphertextLen))
    {
        fprintf(stderr, "failed to read input\n");
        return -1;
    }

    cjose_jwe_t *jwe = cjose_jwe_import(ciphertext, ciphertextLen, &err);
    if (!jwe)
    {
        fprintf(stderr, "failed to import jwe (%d): %s\n", err.code, err.message);
        return -1;
    }

    uint8_t *plaintext = NULL;
    size_t  plaintextLen = 0;
    if (!(plaintext = cjose_jwe_decrypt(jwe, key, &plaintextLen, &err)))
    {
        fprintf(stderr, "failed to decrypt (%d): %s\n", err.code, err.message);
        return -1;
    }
    
    plaintext[plaintextLen] = 0;
    fprintf(stdout, "%s\n", plaintext);
    return 0;
}