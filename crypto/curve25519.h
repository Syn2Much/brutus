#ifndef BRUTUS_CURVE25519_H
#define BRUTUS_CURVE25519_H
#include <stdint.h>

/* X25519 Diffie-Hellman (RFC 7748).
   All buffers are 32 bytes. */

/* Compute shared = X25519(scalar, point).
   scalar: 32-byte private key (clamped internally).
   point:  32-byte public key (peer's value).
   shared: 32-byte output. */
void x25519(uint8_t shared[32], const uint8_t scalar[32], const uint8_t point[32]);

/* Compute public = X25519(scalar, 9).
   scalar: 32-byte private key.
   pub:    32-byte output (public key). */
void x25519_public(uint8_t pub[32], const uint8_t scalar[32]);

#endif
