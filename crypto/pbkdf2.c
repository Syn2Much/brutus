#include "pbkdf2.h"
#include "sha256.h"
#include <string.h>

/*
 * PBKDF2-HMAC-SHA-256 per RFC 2898.
 *
 * For each 32-byte block i (1-indexed):
 *   U1 = HMAC-SHA256(password, salt || INT_32_BE(i))
 *   Uj = HMAC-SHA256(password, U_{j-1})
 *   block_i = U1 ^ U2 ^ ... ^ U_iterations
 *
 * Since SCRAM-SHA-256 only needs 32 bytes, one block is sufficient
 * in practice, but we implement the full spec for correctness.
 */
void pbkdf2_sha256(const uint8_t *password, size_t pass_len,
                   const uint8_t *salt, size_t salt_len,
                   int iterations,
                   uint8_t *out, size_t out_len)
{
    uint32_t block_num = 1;
    size_t written = 0;

    while (written < out_len) {
        uint8_t U[32], T[32];
        uint8_t salt_block[128]; /* salt || INT_32_BE(block_num) */
        size_t sb_len;
        int j;
        size_t k;
        size_t to_copy;

        /* Build salt || INT_32_BE(block_num) */
        sb_len = salt_len + 4;
        if (salt_len <= sizeof(salt_block) - 4) {
            memcpy(salt_block, salt, salt_len);
        } else {
            memcpy(salt_block, salt, sizeof(salt_block) - 4);
            sb_len = sizeof(salt_block);
        }
        salt_block[salt_len]     = (uint8_t)((block_num >> 24) & 0xFF);
        salt_block[salt_len + 1] = (uint8_t)((block_num >> 16) & 0xFF);
        salt_block[salt_len + 2] = (uint8_t)((block_num >> 8) & 0xFF);
        salt_block[salt_len + 3] = (uint8_t)(block_num & 0xFF);

        /* U1 = HMAC(password, salt || INT(i)) */
        hmac_sha256(password, pass_len, salt_block, sb_len, U);
        memcpy(T, U, 32);

        /* U2 .. U_iterations */
        for (j = 1; j < iterations; j++) {
            hmac_sha256(password, pass_len, U, 32, U);
            for (k = 0; k < 32; k++) T[k] ^= U[k];
        }

        /* Copy result into output */
        to_copy = out_len - written;
        if (to_copy > 32) to_copy = 32;
        memcpy(out + written, T, to_copy);
        written += to_copy;
        block_num++;
    }
}
