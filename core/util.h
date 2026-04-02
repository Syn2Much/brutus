#ifndef BRUTUS_UTIL_H
#define BRUTUS_UTIL_H
#include <stdint.h>
#include <stddef.h>

void urandom_bytes(uint8_t *out, size_t len);
uint32_t urandom_u32(void);
int tcp_connect(const char *ip, int port, int timeout_sec);
#endif
