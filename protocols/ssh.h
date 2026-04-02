#ifndef BRUTUS_SSH_H
#define BRUTUS_SSH_H

typedef struct {
    int connect_timeout;
    int read_timeout;
    int port;
} ssh_opts_t;

#define SSH_DEFAULTS { 5, 10, 22 }

/* Error codes for ssh_connect (set via errout parameter) */
#define SSH_OK              0
#define SSH_ERR_CONNECT    -1   /* TCP connect failed / timeout */
#define SSH_ERR_HANDSHAKE  -2   /* handshake failed (protocol error) */
#define SSH_ERR_KEX_NONE   -3   /* no common kex algorithm — target doesn't support DH */

typedef struct ssh_session ssh_session_t;

/* Connect and handshake. Returns session or NULL on failure.
   If errout is non-NULL, set to SSH_OK / SSH_ERR_* on return. */
ssh_session_t *ssh_connect(const char *ip, const ssh_opts_t *opts, int *errout);

/* Try password auth on an established session.
   Returns 1=success, 0=failure, -1=error (session dead) */
int ssh_auth(ssh_session_t *s, const char *user, const char *pass);

/* Execute command on authenticated session. Returns 0=ok, -1=error */
int ssh_exec(ssh_session_t *s, const char *cmd);

/* Get server banner string (e.g. "SSH-2.0-OpenSSH_8.2p1") */
const char *ssh_banner(ssh_session_t *s);

/* Close and free session */
void ssh_close(ssh_session_t *s);

#endif
