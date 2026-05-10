/* tls-verify: validate a certificate chain the way wolfSSL actually does it
 * for a TLS peer, rather than the way the CertManager API does it.
 *
 * The CertManager API (wolfSSL_CertManagerVerify + LoadCABuffer) has no
 * concept of an untrusted intermediate: every cert handed to it via
 * LoadCABuffer becomes a WOLFSSL_USER_CA trust anchor, and the leaf chains
 * to whichever signer it finds and stops. That does not model how a TLS peer
 * chain is validated. This tool instead stands up an in-process TLS client
 * and server connected by an in-memory transport: the server presents the
 * leaf + intermediates as its certificate chain (so the intermediates arrive
 * over the wire and are processed untrusted by the client's ProcessPeerCerts
 * path), while the client trusts only the root. The client's verification of
 * that chain is the result we report.
 *
 * Usage:
 *   tls-verify -CAfile <root.pem> -key <leaf-key.pem> <chain.pem>
 *
 *   -CAfile   trust anchor (root), PEM. The only trusted cert.
 *   -key      the leaf's private key, PEM. The server needs it to complete
 *             the handshake, so that an accepted chain yields a clean success
 *             rather than a later key-exchange failure.
 *   <chain.pem>  leaf first, then intermediates toward (but excluding) the
 *             root — the order generate_nc_chains.py writes chain.pem in.
 *
 * Exit codes:
 *   0  chain verified (client completed the handshake)
 *   1  chain rejected (client aborted with a verification error)
 *   2  usage / setup / transport error
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/version.h>
#include <wolfssl/wolfio.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* ---- in-memory bidirectional transport -------------------------------- */

typedef struct {
    unsigned char *buf;
    size_t len;   /* bytes written */
    size_t cap;   /* allocated */
    size_t rd;    /* read offset */
} membuf;

static int membuf_write(membuf *m, const unsigned char *src, size_t n) {
    if (m->len + n > m->cap) {
        size_t ncap = (m->cap == 0) ? 4096 : m->cap;
        while (m->len + n > ncap) ncap *= 2;
        unsigned char *nb = realloc(m->buf, ncap);
        if (!nb) return -1;
        m->buf = nb;
        m->cap = ncap;
    }
    memcpy(m->buf + m->len, src, n);
    m->len += n;
    return 0;
}

/* A peer is one side's view: it reads from `in` and writes to `out`. */
typedef struct {
    membuf *in;
    membuf *out;
} peer_io;

static int io_send(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    peer_io *p = (peer_io *)ctx;
    if (membuf_write(p->out, (const unsigned char *)buf, (size_t)sz) != 0)
        return WOLFSSL_CBIO_ERR_GENERAL;
    return sz;
}

static int io_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    peer_io *p = (peer_io *)ctx;
    size_t avail = p->in->len - p->in->rd;
    if (avail == 0)
        return WOLFSSL_CBIO_ERR_WANT_READ;
    size_t n = ((size_t)sz < avail) ? (size_t)sz : avail;
    memcpy(buf, p->in->buf + p->in->rd, n);
    p->in->rd += n;
    return (int)n;
}

/* ---- verification result capture -------------------------------------- */

static int g_verify_called = 0;
static int g_verify_error = 0;   /* first non-zero cert error seen */
static int g_verify_depth = 0;

static int verify_cb(int preverify, WOLFSSL_X509_STORE_CTX *store) {
    g_verify_called = 1;
    if (store != NULL) {
        int err = wolfSSL_X509_STORE_CTX_get_error(store);
        if (err != 0 && g_verify_error == 0) {
            g_verify_error = err;
            g_verify_depth = wolfSSL_X509_STORE_CTX_get_error_depth(store);
        }
    }
    /* Honor wolfSSL's own decision; don't override it. */
    return preverify;
}

/* ---- file slurp ------------------------------------------------------- */

static int slurp(const char *path, unsigned char **out, long *out_sz) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "error: open %s: %s\n", path, strerror(errno)); return 0; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz < 0) { fclose(f); return 0; }
    unsigned char *b = malloc((size_t)sz);
    if (!b) { fclose(f); return 0; }
    if (fread(b, 1, (size_t)sz, f) != (size_t)sz) { free(b); fclose(f); return 0; }
    fclose(f);
    *out = b; *out_sz = sz;
    return 1;
}

static void usage(const char *a0) {
    fprintf(stderr, "usage: %s -CAfile <root.pem> -key <leaf-key.pem> <chain.pem>\n", a0);
}

int main(int argc, char **argv) {
    const char *ca_file = NULL, *key_file = NULL, *chain_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-CAfile") == 0 && i + 1 < argc) ca_file = argv[++i];
        else if (strcmp(argv[i], "-key") == 0 && i + 1 < argc) key_file = argv[++i];
        else if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-version") == 0) {
            printf("tls-verify (wolfSSL %s)\n", LIBWOLFSSL_VERSION_STRING);
            return 0;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "error: unknown option %s\n", argv[i]);
            usage(argv[0]); return 2;
        } else if (chain_file == NULL) chain_file = argv[i];
        else { fprintf(stderr, "error: unexpected arg %s\n", argv[i]); usage(argv[0]); return 2; }
    }
    if (!ca_file || !key_file || !chain_file) { usage(argv[0]); return 2; }

    unsigned char *ca = NULL, *key = NULL, *chain = NULL;
    long ca_sz = 0, key_sz = 0, chain_sz = 0;
    if (!slurp(ca_file, &ca, &ca_sz) ||
        !slurp(key_file, &key, &key_sz) ||
        !slurp(chain_file, &chain, &chain_sz)) {
        return 2;
    }

    wolfSSL_Init();

    WOLFSSL_CTX *sctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
    WOLFSSL_CTX *cctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
    if (!sctx || !cctx) { fprintf(stderr, "error: CTX_new failed\n"); return 2; }

    /* Server presents the full chain (leaf first) + the leaf key. */
    if (wolfSSL_CTX_use_certificate_chain_buffer_format(
            sctx, chain, chain_sz, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "error: server load cert chain failed\n");
        return 2;
    }
    if (wolfSSL_CTX_use_PrivateKey_buffer(
            sctx, key, key_sz, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "error: server load private key failed\n");
        return 2;
    }
    /* Server does not request a client cert. */
    wolfSSL_CTX_set_verify(sctx, WOLFSSL_VERIFY_NONE, NULL);

    /* Client trusts only the root and verifies the peer (server) chain. */
    if (wolfSSL_CTX_load_verify_buffer(
            cctx, ca, ca_sz, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "error: client load trust anchor failed\n");
        return 2;
    }
    wolfSSL_CTX_set_verify(cctx, WOLFSSL_VERIFY_PEER, verify_cb);

    wolfSSL_CTX_SetIOSend(sctx, io_send);
    wolfSSL_CTX_SetIORecv(sctx, io_recv);
    wolfSSL_CTX_SetIOSend(cctx, io_send);
    wolfSSL_CTX_SetIORecv(cctx, io_recv);

    WOLFSSL *server = wolfSSL_new(sctx);
    WOLFSSL *client = wolfSSL_new(cctx);
    if (!server || !client) { fprintf(stderr, "error: SSL_new failed\n"); return 2; }

    membuf c2s = {0}, s2c = {0};
    peer_io client_io = { .in = &s2c, .out = &c2s };
    peer_io server_io = { .in = &c2s, .out = &s2c };
    wolfSSL_SetIOReadCtx(client, &client_io);
    wolfSSL_SetIOWriteCtx(client, &client_io);
    wolfSSL_SetIOReadCtx(server, &server_io);
    wolfSSL_SetIOWriteCtx(server, &server_io);

    int client_done = 0, server_done = 0;
    int client_err = 0;
    int verdict_set = 0, accepted = 0;

    for (int iter = 0; iter < 256 && !(client_done && server_done); iter++) {
        if (!client_done) {
            int r = wolfSSL_connect(client);
            if (r == WOLFSSL_SUCCESS) {
                client_done = 1;
            } else {
                int e = wolfSSL_get_error(client, r);
                if (e != WOLFSSL_ERROR_WANT_READ && e != WOLFSSL_ERROR_WANT_WRITE) {
                    client_err = e;
                    break;
                }
            }
        }
        if (!server_done) {
            int r = wolfSSL_accept(server);
            if (r == WOLFSSL_SUCCESS) {
                server_done = 1;
            } else {
                int e = wolfSSL_get_error(server, r);
                if (e != WOLFSSL_ERROR_WANT_READ && e != WOLFSSL_ERROR_WANT_WRITE) {
                    /* Server-side failure (e.g. client closed after rejecting
                     * the cert). The client's verdict is what we report; keep
                     * looping only if the client still needs cycles. */
                    if (client_done || client_err) break;
                }
            }
        }
    }

    /* The client accepting the server's chain == chain verified. */
    if (client_done) {
        accepted = 1; verdict_set = 1;
    } else {
        accepted = 0; verdict_set = 1;
    }

    int rc;
    if (accepted) {
        printf("%s: OK\n", chain_file);
        rc = 0;
    } else {
        /* Prefer the precise cert error captured in the verify callback;
         * fall back to the connect-level error. */
        int err = g_verify_error ? g_verify_error : client_err;
        const char *msg = wc_GetErrorString(err);
        printf("%s: verification failed\n", chain_file);
        printf("error: %s (%d)%s", msg ? msg : "(no message)", err,
               g_verify_error ? "" : " [connect-level]\n");
        if (g_verify_error)
            printf(" at depth %d\n", g_verify_depth);
        rc = 1;
    }
    (void)verdict_set;

    wolfSSL_free(client);
    wolfSSL_free(server);
    wolfSSL_CTX_free(cctx);
    wolfSSL_CTX_free(sctx);
    wolfSSL_Cleanup();
    free(ca); free(key); free(chain);
    free(c2s.buf); free(s2c.buf);
    return rc;
}
