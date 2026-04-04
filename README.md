# brutus

Standalone multi-protocol credential scanner. Pure C, zero external dependencies.

## Protocols

| Protocol | Port | Auth Methods | Version Detection |
|----------|------|-------------|-------------------|
| SSH | 22 | Password (multi-kex: group14-sha256, group14-sha1, group1-sha1) | Server banner |
| MySQL | 3306 | mysql_native_password + 8.0 auth-switch | `@@version` |
| PostgreSQL | 5432 | MD5, cleartext, trust, SCRAM-SHA-256 | `SELECT version()` |
| Redis | 6379 | Legacy AUTH, ACL AUTH (6.0+), open-instance detection | `INFO server` |
| Telnet | 23 | Login/password prompt (IAC negotiation) | Pre-login banner |

## Build

```
make
```

Produces a single `brutus` binary. Requires only `gcc`, `make`, and `pthreads`.

```
make static    # fully static binary
make clean
```

## Usage

```
brutus <protocol> [options]

Options:
  -T, --targets FILE       Target list (one IP per line)
  -t, --target IP          Single target (repeatable)
  -C, --creds FILE         Credential list (user:pass per line)
  -c, --cred USER:PASS     Single credential (repeatable)
  -j, --threads N          Thread count (default: 32)
  -p, --port N             Override default port
      --timeout N          Connect timeout in seconds (default: 5)
  -x, --exec CMD           Execute command on hit (ssh, redis)
      --database DB        PostgreSQL database (default: postgres)
  -o, --output FILE        Output file (default: stdout)
  -f, --format FMT         human | json | csv (default: human)
  -v, --verbose            Show misses and errors
  -q, --quiet              Hits only, no banner
```

## Examples

```sh
# SSH scan with credential list
brutus ssh -T targets.txt -C creds.txt -j 64

# Single MySQL target
brutus mysql -t 10.0.0.50 -c root:password

# Redis with command execution on hit
brutus redis -T hosts.txt -c ':secretpass' -x 'CONFIG GET dir'

# PostgreSQL with JSON output
brutus pgsql -T targets.txt -C creds.txt -f json -o results.json

# Redis password-only creds (no colon = password-only for legacy AUTH)
brutus redis -T hosts.txt -C passwords.txt
```

## Credential File Format

```
# user:pass per line (comments and blank lines ignored)
root:password
admin:admin123
postgres:postgres

# password-only (Redis legacy AUTH) — no colon
secretpass123
anotherpassword
```

## Output Formats

**human** (default):
```
[ssh] hit: 192.168.1.10 root:toor (SSH-2.0-OpenSSH_8.2p1)
[mysql] hit: 10.0.0.5 root:root (5.7.42)
[redis] hit: 10.0.0.20 (no-auth)
```

**json**:
```json
{"proto":"ssh","type":"hit","ip":"192.168.1.10","user":"root","pass":"toor","version":"SSH-2.0-OpenSSH_8.2p1"}
```

**csv**:
```
ssh,hit,192.168.1.10,root,toor,SSH-2.0-OpenSSH_8.2p1
```

## SSH Multi-Kex

The SSH scanner negotiates key exchange automatically. It offers three algorithms in preference order:

1. `diffie-hellman-group14-sha256` — default for modern OpenSSH 7.0+
2. `diffie-hellman-group14-sha1` — fallback for older OpenSSH / dropbear
3. `diffie-hellman-group1-sha1` — fallback for embedded / legacy devices

If the server doesn't support any of these, the target is skipped immediately with a `kex-unsupported` error — no credentials are wasted.

## PostgreSQL SCRAM-SHA-256

Supports PostgreSQL 14+ default authentication (SCRAM-SHA-256, RFC 5802) in addition to legacy MD5 and cleartext. Auth method is auto-detected from the server's response.

## Architecture

```
brutus/
  main.c              CLI entry, getopt, protocol dispatch
  core/
    threadpool.c       pthread work queue (one target per work item)
    output.c           thread-safe reporting (human/json/csv)
    target.c           target + credential file parsing
    util.c             urandom, tcp_connect helper
  protocols/
    ssh.c              SSH-2.0 (DH, AES-128-CTR, HMAC-SHA-256/SHA-1)
    mysql.c            MySQL native password auth
    pgsql.c            PostgreSQL MD5 + SCRAM-SHA-256
    redis.c            Redis RESP protocol auth
  crypto/
    sha256.c           SHA-256 + HMAC-SHA-256
    sha1.c             SHA-1 + HMAC-SHA-1
    md5.c              MD5
    aes128.c           AES-128-CTR
    bignum.c           Bignum arithmetic (DH key exchange)
    pbkdf2.c           PBKDF2-HMAC-SHA-256 (SCRAM)
```

All crypto is embedded — no OpenSSL, no libsodium, no external libraries.

## Work in Progress

- Honeypot detection
- FTP protocol support
- IPv6 support
- Proxy support (SOCKS/HTTP)
- `caching_sha2_password` for MySQL 8.0+
- SSH key authentication
- Command execution for MySQL/PostgreSQL
- SSH command output capture
