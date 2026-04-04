# Changelog

## Unreleased

### Added
- **SSH curve25519-sha256 KEX**: adds `curve25519-sha256` and `curve25519-sha256@libssh.org` as preferred key exchange algorithms, with DH group14/group1 fallback — fixes `kex-unsupported` on modern OpenSSH 8.x/9.x servers that no longer offer classic DH
- **crypto/curve25519**: standalone X25519 Diffie-Hellman implementation (RFC 7748), no external dependencies
- **Telnet protocol**: full IAC negotiation, login/password prompt detection, success/fail heuristics, banner extraction
- **MySQL caching_sha2_password** (8.0+): fast-auth path, RSA-OAEP full-auth path, and bidirectional auth-switch (native↔sha2)
- **Redis RESP wire protocol**: AUTH, PING, and INFO commands now use proper RESP framing instead of inline format
- **Redis ACL AUTH**: RESP `*3` AUTH command for Redis 6+ username:password authentication

### Fixed
- **pgsql.c**: SCRAM-SHA-256 wrong-password now correctly returns miss (server sends `E` ErrorResponse, was falling through)
- **pgsql.c**: version detection works through null bytes in PG wire protocol (`memmem` instead of `strstr`)
- **pgsql.c**: removed 5-second stall after auth by replacing blocking `recv` drain with `poll()` + 200ms timeout
- **redis.c**: empty-string username (`:password` cred format) now falls through to legacy AUTH instead of sending ACL AUTH with empty user
