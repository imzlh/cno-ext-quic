/**
 * Circu.js External Module: QUIC transport implement
 *
 * Copyright (c) 2026 iz
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "native.h"
#include "mem.h"
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <inttypes.h>
#include <stdio.h>
#if defined(_MSC_VER)
#include <openssl/applink.c>
#endif
#include <threads.h>

thread_local JSClassID qc_conn_class_id;
thread_local JSClassID qc_sock_class_id;
static quicly_error_t qconn_flush(QuicConn *c);
static void qsock_update_timer(QuicSock *s);
static QuicConn *qsock_find_conn(QuicSock *s, quicly_conn_t *qc);
static void qsock_close(JSRuntime *rt, QuicSock *s);
static void qsock_try_free(QuicSock *s);

/* ── Time helper (ms since epoch, same domain as quicly) ─────── */
static int64_t now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int resolve_udp_addr(uv_loop_t *loop, const char *host, uint32_t port,
                            struct sockaddr_storage *addr) {
    char service[6];
    snprintf(service, sizeof(service), "%u", port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    uv_getaddrinfo_t req;
    int rc = uv_getaddrinfo(loop, &req, NULL, host, service, &hints);
    if (rc != 0) return rc;
    if (!req.addrinfo || req.addrinfo->ai_addrlen > sizeof(*addr)) {
        uv_freeaddrinfo(req.addrinfo);
        return UV_EAI_ADDRFAMILY;
    }
    memset(addr, 0, sizeof(*addr));
    memcpy(addr, req.addrinfo->ai_addr, req.addrinfo->ai_addrlen);
    uv_freeaddrinfo(req.addrinfo);
    return 0;
}

/* ── Connection table helpers ─────────────────────────────────── */
static QuicConn *qsock_find_conn(QuicSock *s, quicly_conn_t *qc) {
    for (int i = 0; i < MAX_CONNS; i++)
        if (s->conns[i] && s->conns[i]->qconn == qc) return s->conns[i];
    return NULL;
}

static int qsock_add_conn(QuicSock *s, QuicConn *c) {
    for (int i = 0; i < MAX_CONNS; i++) {
        if (!s->conns[i]) { s->conns[i] = c; return 0; }
    }
    return -1; /* full */
}

static void qsock_remove_conn(QuicSock *s, QuicConn *c) {
    for (int i = 0; i < MAX_CONNS; i++)
        if (s->conns[i] == c) { s->conns[i] = NULL; return; }
}

static void qconn_dispose(JSRuntime *rt, QuicConn *c) {
    QuicSock *s = c->sock;
    if (s) {
        s->in_receive++;
        qsock_remove_conn(s, c);
        c->sock = NULL;
    }
    if (c->qconn) {
        quicly_free(c->qconn);
        c->qconn = NULL;
    }
    JSValue self = c->self;
    c->self = JS_UNDEFINED;
    if (!JS_IsUndefined(self) && !JS_IsNull(self)) JS_SetOpaque(self, NULL);
    for (int i = 0; i < QC_CB_COUNT; i++) {
        JS_FreeValueRT(rt, c->callbacks[i]);
        c->callbacks[i] = JS_NULL;
    }
    free(c);
    if (!JS_IsUndefined(self) && !JS_IsNull(self)) JS_FreeValueRT(rt, self);
    if (s) {
        s->in_receive--;
        if (s->closing && !s->close_finished) qsock_close(rt, s);
    }
}

static void qsock_emit_error(QuicSock *s, const char *message) {
    if (!s || s->closing) return;
    JSValue value = JS_NewString(s->ctx, message);
    if (JS_IsException(value)) {
        TJS_DumpException(s->ctx);
        return;
    }
    s->in_receive++;
    QC_CALL(s->ctx, s->callbacks, QS_CB_ERROR, 1, &value);
    for (int i = 0; i < MAX_CONNS; i++) {
        if (s->closing) break;
        if (s->conns[i]) QC_CALL(s->ctx, s->conns[i]->callbacks, QC_CB_ERROR, 1, &value);
    }
    s->in_receive--;
    JS_FreeValue(s->ctx, value);
}

static void qconn_emit_error(QuicConn *c, const char *message) {
    QuicSock *s = c ? c->sock : NULL;
    if (!s || s->closing) return;
    JSValue value = JS_NewString(c->ctx, message);
    if (JS_IsException(value)) {
        TJS_DumpException(c->ctx);
        return;
    }
    s->in_receive++;
    QC_CALL(c->ctx, c->callbacks, QC_CB_ERROR, 1, &value);
    s->in_receive--;
    JS_FreeValue(c->ctx, value);
}

/* ── UDP send helper (copies data, frees on completion) ─────── */
typedef struct {
    uv_udp_send_t req;
    QuicSock *sock;
    uint8_t data[];
} SendReq;

static void on_udp_sent(uv_udp_send_t *req, int status) {
    SendReq *send = (SendReq *)req;
    QuicSock *s = send->sock;
    if (status < 0 && s && !s->closing) {
        qsock_emit_error(s, uv_strerror(status));
        if (s->closing) qsock_close(JS_GetRuntime(s->ctx), s);
    }
    s->pending_sends--;
    free(send);
    qsock_try_free(s);
}

static void qsock_udp_send(QuicSock *s, const struct sockaddr *dest,
                            const void *data, size_t len) {
    SendReq *req = malloc(sizeof(SendReq) + len);
    if (!req) {
        qsock_emit_error(s, "failed to allocate UDP send request");
        return;
    }
    req->sock = s;
    memcpy(req->data, data, len);
    uv_buf_t buf = uv_buf_init((char *)req->data, len);
    s->pending_sends++;
    int rc = uv_udp_send(&req->req, &s->udp, &buf, 1, dest, on_udp_sent);
    if (rc != 0) {
        s->pending_sends--;
        qsock_emit_error(s, uv_strerror(rc));
        free(req);
    }
}

/* ── quicly send loop ─────────────────────────────────────────── */
static quicly_error_t qconn_flush(QuicConn *c) {
    if (!c || !c->sock || !c->qconn) return QUICLY_ERROR_FREE_CONNECTION;
    QuicSock *s = c->sock;
    if (s->closing) return QUICLY_ERROR_FREE_CONNECTION;
    if (s->in_receive) {
        s->pending_flush = 1;
        return 0;
    }

    quicly_address_t dest, src;
    struct iovec     dgrams[DGRAM_BATCH];
    uint8_t          buf[DGRAM_BATCH * MAX_PKT_SIZE];
    size_t           ndgrams;

    while (1) {
        ndgrams = DGRAM_BATCH;
        s->in_receive++;
        quicly_error_t rc = quicly_send(c->qconn, &dest, &src, dgrams,
                                        &ndgrams, buf, sizeof(buf));
        s->in_receive--;
        if (s->closing) {
            qsock_close(JS_GetRuntime(c->ctx), s);
            return QUICLY_ERROR_FREE_CONNECTION;
        }
        if (rc == QUICLY_ERROR_FREE_CONNECTION) {
            if (!c->connected_fired)
                qconn_emit_error(c, "QUIC connection closed during handshake");
            if (s->closing) {
                qsock_close(JS_GetRuntime(c->ctx), s);
                return rc;
            }
            qconn_dispose(JS_GetRuntime(c->ctx), c);
            if (!s->closing) qsock_update_timer(s);
            return rc;
        }
        if (rc != 0) {
            char message[96];
            snprintf(message, sizeof(message), "QUIC send failed: %" PRId64, rc);
            qconn_emit_error(c, message);
            if (s->closing) {
                qsock_close(JS_GetRuntime(c->ctx), s);
                return rc;
            }
            qconn_dispose(JS_GetRuntime(c->ctx), c);
            if (!s->closing) qsock_update_timer(s);
            return rc;
        }
        if (ndgrams == 0) break;
        for (size_t i = 0; i < ndgrams; i++) {
            qsock_udp_send(s, &dest.sa,
                           dgrams[i].iov_base, dgrams[i].iov_len);
            if (s->closing) {
                qsock_close(JS_GetRuntime(c->ctx), s);
                return QUICLY_ERROR_FREE_CONNECTION;
            }
        }
    }
    qsock_update_timer(s);
    return 0;
}

/* ── Timer ────────────────────────────────────────────────────── */
static void on_timer(uv_timer_t *t) {
    QuicSock *s   = container_of(t, QuicSock, timer);
    if (s->closing) return;
    int64_t   now = now_ms();
    for (int i = 0; i < MAX_CONNS; i++) {
        QuicConn *c = s->conns[i];
        if (!c) continue;
        if (quicly_get_first_timeout(c->qconn) <= now)
            qconn_flush(c);
        if (s->closing) return;
    }
    qsock_update_timer(s);
}

static void qsock_update_timer(QuicSock *s) {
    if (!s || s->closing || !s->timer_initialized ||
        uv_is_closing((uv_handle_t *)&s->timer)) return;
    int64_t now     = now_ms();
    int64_t earliest = INT64_MAX;
    for (int i = 0; i < MAX_CONNS; i++) {
        QuicConn *c = s->conns[i];
        if (!c) continue;
        int64_t t = quicly_get_first_timeout(c->qconn);
        if (t < earliest) earliest = t;
    }
    if (earliest == INT64_MAX) { uv_timer_stop(&s->timer); return; }
    int64_t delay = earliest - now;
    uv_timer_start(&s->timer, on_timer, delay > 0 ? (uint64_t)delay : 0, 0);
}

/* ── quicly stream callbacks ──────────────────────────────────── */
static void stream_on_destroy(quicly_stream_t *stream, quicly_error_t err) {
    quicly_streambuf_destroy(stream, err);
}

static void stream_on_receive(quicly_stream_t *stream, size_t off,
                               const void *src, size_t len) {
    if (quicly_streambuf_ingress_receive(stream, off, src, len) != 0) return;
    ptls_iovec_t input = quicly_streambuf_ingress_get(stream);
    bool fin = quicly_recvstate_transfer_complete(&stream->recvstate);
    if (input.len == 0 && !fin) return;

    QuicStreamData *sd = stream->data;
    QuicConn  *c   = sd->conn;
    JSContext *ctx = c->ctx;
    JSValue argv[3] = {
        JS_NewFloat64(ctx, (double)stream->stream_id),
        JS_NewUint8ArrayCopy(ctx, input.base, input.len),
        JS_NewBool(ctx, fin),
    };
    QC_CALL(ctx, c->callbacks, QC_CB_DATA, 3, argv);
    JS_FreeValue(ctx, argv[0]);
    JS_FreeValue(ctx, argv[1]);
    JS_FreeValue(ctx, argv[2]);
    quicly_streambuf_ingress_shift(stream, input.len);
}

static void stream_on_receive_reset(quicly_stream_t *stream, quicly_error_t err) {
    QuicStreamData *sd = stream->data;
    QuicConn  *c   = sd->conn;
    JSContext *ctx = c->ctx;
    JSValue argv[2] = {
        JS_NewFloat64(ctx, (double)stream->stream_id),
        JS_NewFloat64(ctx, QUICLY_ERROR_IS_QUIC_APPLICATION(err)
                              ? (double)QUICLY_ERROR_GET_ERROR_CODE(err)
                              : (double)err),
    };
    QC_CALL(ctx, c->callbacks, QC_CB_STREAM_RESET, 2, argv);
    JS_FreeValue(ctx, argv[0]);
    JS_FreeValue(ctx, argv[1]);
}

static void stream_on_send_stop(quicly_stream_t *stream, quicly_error_t err) {
    QuicStreamData *sd = stream->data;
    QuicConn *c = sd->conn;
    JSContext *ctx = c->ctx;
    JSValue argv[2] = {
        JS_NewFloat64(ctx, (double)stream->stream_id),
        JS_NewFloat64(ctx, QUICLY_ERROR_IS_QUIC_APPLICATION(err)
                              ? (double)QUICLY_ERROR_GET_ERROR_CODE(err)
                              : (double)err),
    };
    QC_CALL(ctx, c->callbacks, QC_CB_STREAM_STOP, 2, argv);
    JS_FreeValue(ctx, argv[0]);
    JS_FreeValue(ctx, argv[1]);
}

static const quicly_stream_callbacks_t stream_cbs = {
    .on_destroy       = stream_on_destroy,
    .on_send_shift    = quicly_streambuf_egress_shift,
    .on_send_emit     = quicly_streambuf_egress_emit,
    .on_send_stop     = stream_on_send_stop,
    .on_receive       = stream_on_receive,
    .on_receive_reset = stream_on_receive_reset,
};

/* ── quicly connection callbacks ──────────────────────────────── */
static quicly_error_t on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream) {
    QuicSock *s  = container_of(self, QuicSock, on_stream_open_cb);
    QuicConn *c  = qsock_find_conn(s, stream->conn);
    if (!c) return QUICLY_ERROR_PACKET_IGNORED;
    int rc = quicly_streambuf_create(stream, sizeof(QuicStreamData));
    if (rc != 0) return rc;
    ((QuicStreamData *)stream->data)->conn = c;
    stream->callbacks = &stream_cbs;
    /* quicly invokes stream_open for both local and peer streams.  The
     * public onstream callback is for peer-initiated streams only. */
    if (!quicly_stream_is_self_initiated(stream)) {
        JSValue argv[2] = {
            JS_NewFloat64(s->ctx, (double)stream->stream_id),
            JS_NewBool(s->ctx, STREAM_IS_BIDI(stream->stream_id)),
        };
        QC_CALL(s->ctx, c->callbacks, QC_CB_STREAM, 2, argv);
        JS_FreeValue(s->ctx, argv[0]);
        JS_FreeValue(s->ctx, argv[1]);
    }
    return 0;
}

static void on_closed(quicly_closed_t *self, quicly_conn_t *qconn) {
    uint64_t frame_type;
    const char *reason;
    int is_remote;
    quicly_error_t err = quicly_get_close_reason(qconn, &frame_type, &reason, &is_remote);
    (void)frame_type;
    (void)is_remote;
    QuicSock *s = container_of(self, QuicSock, on_closed_cb);
    QuicConn *c = qsock_find_conn(s, qconn);
    if (!c) return;
    double close_code = (QUICLY_ERROR_IS_QUIC(err))
        ? (double)QUICLY_ERROR_GET_ERROR_CODE(err)
        : (double)err;
    JSValue argv[2] = {
        JS_NewFloat64(s->ctx, close_code),
        JS_NewString(s->ctx, reason ? reason : ""),
    };
    QC_CALL(s->ctx, c->callbacks, QC_CB_CLOSE, 2, argv);
    JS_FreeValue(s->ctx, argv[0]);
    JS_FreeValue(s->ctx, argv[1]);
}

static void on_receive_datagram_frame(quicly_receive_datagram_frame_t *self,
                                       quicly_conn_t *qconn,
                                       ptls_iovec_t payload) {
    QuicSock *s = container_of(self, QuicSock, on_datagram_cb);
    QuicConn *c = qsock_find_conn(s, qconn);
    if (!c) return;
    JSValue buf = JS_NewUint8ArrayCopy(s->ctx, payload.base, payload.len);
    QC_CALL(s->ctx, c->callbacks, QC_CB_DATAGRAM, 1, &buf);
    JS_FreeValue(s->ctx, buf);
}

/* ── UDP receive ──────────────────────────────────────────────── */
static void on_udp_alloc(uv_handle_t *h, size_t sz, uv_buf_t *buf) {
    (void)h;
    buf->base = malloc(sz);
    buf->len  = buf->base ? sz : 0;
}

static void on_udp_recv(uv_udp_t *h, ssize_t nread, const uv_buf_t *buf,
                         const struct sockaddr *addr, unsigned flags) {
    (void)flags;
    QuicSock *s = container_of(h, QuicSock, udp);
    if (nread <= 0) {
        free(buf->base);
        if (nread < 0) {
            qsock_emit_error(s, uv_strerror((int)nread));
            if (s->closing) qsock_close(JS_GetRuntime(s->ctx), s);
        }
        return;
    }

    /* Decode packet to find/create connection */
    quicly_decoded_packet_t pkt;
    size_t                  off = 0;
    quicly_address_t        local, remote;

    memset(&local, 0, sizeof(local));
    local.sin.sin_family = AF_INET; /* TODO: detect actual local addr */
    memcpy(&remote.sa, addr, addr->sa_family == AF_INET6
           ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));

    while (off < (size_t)nread) {
        size_t n = quicly_decode_packet(&s->qctx, &pkt,
                                         (const uint8_t *)buf->base,
                                         (size_t)nread, &off);
        if (n == SIZE_MAX) break;

        {
            QuicConn *c = NULL;

            /* Try to find existing connection */
            for (int j = 0; j < MAX_CONNS; j++) {
                if (!s->conns[j]) continue;
                if (quicly_is_destination(s->conns[j]->qconn, NULL,
                                          &remote.sa, &pkt)) {
                    c = s->conns[j];
                    break;
                }
            }

            if (!c && s->is_server) {
                /* New inbound connection */
                quicly_conn_t *qconn = NULL;
                quicly_error_t rc = quicly_accept(&qconn, &s->qctx, NULL, &remote.sa,
                                                   &pkt, NULL, &s->next_cid, NULL, NULL);
                if (rc != 0 || !qconn) continue;

                c = calloc(1, sizeof(QuicConn));
                if (!c || qsock_add_conn(s, c) != 0) {
                    quicly_free(qconn);
                    free(c);
                    continue;
                }
                c->qconn = qconn;
                c->sock  = s;
                c->ctx   = s->ctx;
                c->self  = JS_UNDEFINED;
                for (int k = 0; k < QC_CB_COUNT; k++)
                    c->callbacks[k] = JS_NULL;

                /* Create JS object and expose via onconnection */
                c->self = JS_NewObjectClass(s->ctx, qc_conn_class_id);
                if (JS_IsException(c->self)) {
                    qsock_remove_conn(s, c);
                    quicly_free(c->qconn);
                    free(c);
                    TJS_DumpException(s->ctx);
                    qsock_emit_error(s, "failed to allocate QUIC connection object");
                    if (s->closing) {
                        qsock_close(JS_GetRuntime(s->ctx), s);
                        free(buf->base);
                        return;
                    }
                    continue;
                }
                JS_SetOpaque(c->self, c);

                JSValue jconn = JS_DupValue(s->ctx, c->self);
                s->in_receive++;
                QC_CALL(s->ctx, s->callbacks, QS_CB_CONNECTION, 1, &jconn);
                s->in_receive--;
                JS_FreeValue(s->ctx, jconn);
                if (s->closing) {
                    qsock_close(JS_GetRuntime(s->ctx), s);
                    free(buf->base);
                    return;
                }
                qconn_flush(c);
                continue;
            }

            if (!c) continue; /* client: unknown packet, drop */

            s->in_receive++;
            quicly_error_t receive_rc = quicly_receive(c->qconn, NULL, &remote.sa, &pkt);

            /* Notify JS once when handshake completes */
            if (!c->connected_fired && quicly_connection_is_ready(c->qconn)) {
                c->connected_fired = 1;
                QC_CALL(s->ctx, c->callbacks, QC_CB_CONNECTED, 0, NULL);
            }
            s->in_receive--;
            if (s->closing) {
                qsock_close(JS_GetRuntime(s->ctx), s);
                free(buf->base);
                return;
            }
            if (receive_rc == QUICLY_ERROR_FREE_CONNECTION) {
                if (!c->connected_fired)
                    qconn_emit_error(c, "QUIC connection closed during handshake");
                if (s->closing) {
                    qsock_close(JS_GetRuntime(s->ctx), s);
                    free(buf->base);
                    return;
                }
                qconn_dispose(JS_GetRuntime(s->ctx), c);
                if (s->closing) {
                    free(buf->base);
                    return;
                }
                continue;
            }
            if (receive_rc != 0 && receive_rc != QUICLY_ERROR_PACKET_IGNORED &&
                receive_rc != QUICLY_ERROR_DECRYPTION_FAILED) {
                char message[96];
                snprintf(message, sizeof(message), "QUIC receive failed: %" PRId64, receive_rc);
                qconn_emit_error(c, message);
                if (s->closing) {
                    qsock_close(JS_GetRuntime(s->ctx), s);
                    free(buf->base);
                    return;
                }
            }

            qconn_flush(c);
            if (s->closing) {
                qsock_close(JS_GetRuntime(s->ctx), s);
                free(buf->base);
                return;
            }
            if (s->pending_flush && !s->in_receive) {
                s->pending_flush = 0;
                for (int j = 0; j < MAX_CONNS; j++) {
                    if (s->conns[j]) qconn_flush(s->conns[j]);
                    if (s->closing) break;
                }
            }
            if (s->closing) {
                qsock_close(JS_GetRuntime(s->ctx), s);
                free(buf->base);
                return;
            }
        }
        (void)n;
    }
    free(buf->base);
}

/* ── TLS / picotls helpers ────────────────────────────────────── */
static int load_cert_chain(QuicSock *s, const char *pem) {
    BIO *bio = BIO_new_mem_buf(pem, -1);
    if (!bio) return -1;
    X509 *x;
    while (s->ncerts < 8 && (x = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        unsigned char *der = NULL;
        int len = i2d_X509(x, &der);
        X509_free(x);
        if (len <= 0) continue;
        s->certs[s->ncerts].base = der;
        s->certs[s->ncerts].len  = (size_t)len;
        s->ncerts++;
    }
    BIO_free(bio);
    ERR_clear_error();
    return s->ncerts > 0 ? 0 : -1;
}

static int load_private_key(QuicSock *s, const char *pem) {
    BIO *bio = BIO_new_mem_buf(pem, -1);
    if (!bio) return -1;
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) {
        ERR_clear_error();
        return -1;
    }
    int rc = ptls_openssl_init_sign_certificate(&s->sign_cert, pkey);
    EVP_PKEY_free(pkey);
    if (rc != 0) return -1;
    s->tls.sign_certificate = &s->sign_cert.super;
    return 0;
}

static int load_ca_certificates(JSContext *ctx, JSValue opts, X509_STORE *store) {
    JSValue roots = JS_GetPropertyStr(ctx, opts, "caCerts");
    if (JS_IsException(roots)) return -1;
    if (JS_IsUndefined(roots) || JS_IsNull(roots)) {
        JS_FreeValue(ctx, roots);
        return 0;
    }
    int is_array = JS_IsArray(roots);
    if (is_array <= 0) {
        JS_FreeValue(ctx, roots);
        if (is_array == 0) JS_ThrowTypeError(ctx, "caCerts must be an array");
        return -1;
    }
    JSValue length_value = JS_GetPropertyStr(ctx, roots, "length");
    uint32_t length = 0;
    if (JS_IsException(length_value) ||
        JS_ToUint32(ctx, &length, length_value) < 0) {
        JS_FreeValue(ctx, length_value);
        JS_FreeValue(ctx, roots);
        return -1;
    }
    JS_FreeValue(ctx, length_value);
    for (uint32_t i = 0; i < length; i++) {
        JSValue value = JS_GetPropertyUint32(ctx, roots, i);
        if (JS_IsException(value)) {
            JS_FreeValue(ctx, roots);
            return -1;
        }
        if (!JS_IsString(value)) {
            JS_FreeValue(ctx, value);
            JS_FreeValue(ctx, roots);
            JS_ThrowTypeError(ctx, "caCerts entries must be PEM strings");
            return -1;
        }
        const char *pem = JS_ToCString(ctx, value);
        JS_FreeValue(ctx, value);
        if (!pem) {
            JS_FreeValue(ctx, roots);
            return -1;
        }
        BIO *bio = BIO_new_mem_buf(pem, -1);
        JS_FreeCString(ctx, pem);
        if (!bio) {
            JS_FreeValue(ctx, roots);
            JS_ThrowOutOfMemory(ctx);
            return -1;
        }
        int loaded = 0;
        X509 *cert;
        while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
            if (X509_STORE_add_cert(store, cert) == 1) {
                loaded++;
            } else {
                unsigned long error = ERR_peek_last_error();
                if (ERR_GET_REASON(error) == X509_R_CERT_ALREADY_IN_HASH_TABLE)
                    loaded++;
                ERR_clear_error();
            }
            X509_free(cert);
        }
        BIO_free(bio);
        ERR_clear_error();
        if (loaded == 0) {
            JS_FreeValue(ctx, roots);
            return -1;
        }
    }
    JS_FreeValue(ctx, roots);
    return 0;
}

/* ── QuicConn JS class ────────────────────────────────────────── */
static void qc_conn_finalizer(JSRuntime *rt, JSValue val) {
    QuicConn *c = JS_GetOpaque(val, qc_conn_class_id);
    if (!c) return;
    JS_SetOpaque(val, NULL);
    if (c->sock) {
        qsock_remove_conn(c->sock, c);
        c->sock = NULL;
    }
    if (c->qconn) {
        quicly_free(c->qconn);
        c->qconn = NULL;
    }
    for (int i = 0; i < QC_CB_COUNT; i++) {
        JS_FreeValueRT(rt, c->callbacks[i]);
        c->callbacks[i] = JS_NULL;
    }
    /* c->self is this value — do not FreeValue it from its own finalizer */
    free(c);
}

static void qc_conn_mark(JSRuntime *rt, JSValueConst val, JS_MarkFunc *mark_func) {
    QuicConn *c = JS_GetOpaque(val, qc_conn_class_id);
    if (!c) return;
    for (int i = 0; i < QC_CB_COUNT; i++)
        JS_MarkValue(rt, c->callbacks[i], mark_func);
}

static JSClassDef qc_conn_class = {
    "Connection",
    .finalizer = qc_conn_finalizer,
    .gc_mark = qc_conn_mark,
};

static inline QuicConn *conn_get(JSContext *ctx, JSValue v) {
    QuicConn *c = JS_GetOpaque2(ctx, v, qc_conn_class_id);
    /* opaque is cleared on dispose; JS_GetOpaque2 only throws on class mismatch */
    if (!c && !JS_HasException(ctx))
        JS_ThrowTypeError(ctx, "QUIC connection is closed");
    return c;
}

static int qconn_operation_enter(JSContext *ctx, JSValue this_val,
                                 QuicConn **conn, QuicSock **sock,
                                 quicly_conn_t **qconn) {
    *conn = conn_get(ctx, this_val);
    if (!*conn) return -1;
    *sock = (*conn)->sock;
    *qconn = (*conn)->qconn;
    if (!*sock || !*qconn || (*sock)->closing) return 0;
    (*sock)->in_receive++;
    return 1;
}

static void qconn_operation_leave(JSContext *ctx, QuicConn *c,
                                  QuicSock *s, int flush) {
    if (s->in_receive > 0) s->in_receive--;
    if (s->closing) {
        qsock_close(JS_GetRuntime(ctx), s);
        return;
    }
    if (flush && c->sock == s && c->qconn) (void)qconn_flush(c);
}

static uint8_t *qc_get_buffer(JSContext *ctx, JSValue value, size_t *len,
                              JSValue *array_buffer) {
    *array_buffer = JS_UNDEFINED;
    if (JS_IsArrayBuffer(value)) {
        uint8_t *ptr = JS_GetArrayBuffer(ctx, len, value);
        if (ptr) return ptr;
        return !JS_HasException(ctx) && *len == 0 ? (uint8_t *)"" : NULL;
    }

    size_t offset, view_len;
    JSValue buffer = JS_GetTypedArrayBuffer(ctx, value, &offset, &view_len, NULL);
    if (JS_IsException(buffer)) return NULL;
    size_t buffer_len;
    uint8_t *ptr = JS_GetArrayBuffer(ctx, &buffer_len, buffer);
    if ((!ptr && (JS_HasException(ctx) || view_len != 0)) ||
        offset > buffer_len || view_len > buffer_len - offset) {
        JS_FreeValue(ctx, buffer);
        if (!JS_HasException(ctx))
            JS_ThrowRangeError(ctx, "typed array view is outside its buffer");
        return NULL;
    }
    *array_buffer = buffer;
    *len = view_len;
    return ptr ? ptr + offset : (uint8_t *)"";
}

static JSValue js_conn_open_stream(JSContext *ctx, JSValue this_val,
                                    int argc, JSValue *argv) {
    QuicConn *c;
    QuicSock *s;
    quicly_conn_t *qconn;
    int entered = qconn_operation_enter(ctx, this_val, &c, &s, &qconn);
    if (entered < 0) return JS_EXCEPTION;
    if (entered == 0) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    int bidi = argc >= 1 ? JS_ToBool(ctx, argv[0]) : 1;
    if (bidi < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (s->closing) goto done;
    quicly_stream_t *stream;
    quicly_error_t rc = quicly_open_stream(qconn, &stream, !bidi);
    if (rc != 0) {
        result = JS_ThrowInternalError(ctx, "open_stream: %" PRId64, rc);
        goto done;
    }
    if (!stream->data) {
        result = JS_ThrowOutOfMemory(ctx);
        goto done;
    }
    result = JS_NewFloat64(ctx, (double)stream->stream_id);
done:
    qconn_operation_leave(ctx, c, s, !JS_IsException(result));
    return result;
}

static JSValue js_conn_send_stream(JSContext *ctx, JSValue this_val,
                                    int argc, JSValue *argv) {
    if (argc < 2) return JS_ThrowTypeError(ctx, "sendStream requires streamId and data");
    QuicConn *c;
    QuicSock *s;
    quicly_conn_t *qconn;
    int entered = qconn_operation_enter(ctx, this_val, &c, &s, &qconn);
    if (entered < 0) return JS_EXCEPTION;
    if (entered == 0) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    uint64_t sid;
    if (JS_ToIndex(ctx, &sid, argv[0]) < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (s->closing) goto done;
    quicly_stream_t *stream = quicly_get_stream(qconn, (int64_t)sid);
    if (!stream) {
        result = JS_ThrowRangeError(ctx, "unknown stream %llu", (unsigned long long)sid);
        goto done;
    }
    if (!quicly_stream_has_send_side(quicly_is_client(qconn), stream->stream_id) ||
        !quicly_sendstate_is_open(&stream->sendstate)) {
        result = JS_ThrowTypeError(ctx, "stream is not writable");
        goto done;
    }

    size_t len;
    JSValue ab_ref;
    uint8_t *ptr = qc_get_buffer(ctx, argv[1], &len, &ab_ref);
    if (!ptr) {
        JS_FreeValue(ctx, ab_ref);
        result = JS_HasException(ctx) ? JS_EXCEPTION
                                      : JS_ThrowTypeError(ctx, "expected ArrayBuffer/TypedArray");
        goto done;
    }

    int fin = argc >= 3 ? JS_ToBool(ctx, argv[2]) : 0;
    if (fin < 0) {
        JS_FreeValue(ctx, ab_ref);
        result = JS_EXCEPTION;
        goto done;
    }
    if (s->closing) {
        JS_FreeValue(ctx, ab_ref);
        goto done;
    }

    int rc = quicly_streambuf_egress_write(stream, ptr, len);
    JS_FreeValue(ctx, ab_ref);
    if (rc != 0) {
        result = JS_ThrowInternalError(ctx, "sendStream: %d", rc);
        goto done;
    }

    if (fin && (rc = quicly_streambuf_egress_shutdown(stream)) != 0)
        result = JS_ThrowInternalError(ctx, "sendStream shutdown: %d", rc);
done:
    qconn_operation_leave(ctx, c, s, !JS_IsException(result));
    return result;
}

static JSValue js_conn_reset_stream(JSContext *ctx, JSValue this_val,
                                     int argc, JSValue *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "resetStream requires streamId");
    QuicConn *c;
    QuicSock *s;
    quicly_conn_t *qconn;
    int entered = qconn_operation_enter(ctx, this_val, &c, &s, &qconn);
    if (entered < 0) return JS_EXCEPTION;
    if (entered == 0) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    uint64_t sid;
    uint32_t code = 0;
    if (JS_ToIndex(ctx, &sid, argv[0]) < 0 ||
        (argc >= 2 && JS_ToUint32(ctx, &code, argv[1]) < 0)) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (s->closing) goto done;
    quicly_stream_t *stream = quicly_get_stream(qconn, (int64_t)sid);
    if (stream && quicly_stream_has_send_side(quicly_is_client(qconn), stream->stream_id) &&
        !quicly_sendstate_transfer_complete(&stream->sendstate))
        quicly_reset_stream(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(code));
done:
    qconn_operation_leave(ctx, c, s, !JS_IsException(result));
    return result;
}

static JSValue js_conn_stop_sending(JSContext *ctx, JSValue this_val,
                                     int argc, JSValue *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "stopSending requires streamId");
    QuicConn *c;
    QuicSock *s;
    quicly_conn_t *qconn;
    int entered = qconn_operation_enter(ctx, this_val, &c, &s, &qconn);
    if (entered < 0) return JS_EXCEPTION;
    if (entered == 0) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    uint64_t sid;
    uint32_t code = 0;
    if (JS_ToIndex(ctx, &sid, argv[0]) < 0 ||
        (argc >= 2 && JS_ToUint32(ctx, &code, argv[1]) < 0)) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (s->closing) goto done;
    quicly_stream_t *stream = quicly_get_stream(qconn, (int64_t)sid);
    if (stream && quicly_stream_has_receive_side(quicly_is_client(qconn), stream->stream_id))
        quicly_request_stop(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(code));
done:
    qconn_operation_leave(ctx, c, s, !JS_IsException(result));
    return result;
}

static JSValue js_conn_send_datagram(JSContext *ctx, JSValue this_val,
                                      int argc, JSValue *argv) {
    if (argc < 1) return JS_ThrowTypeError(ctx, "sendDatagram requires data");
    QuicConn *c;
    QuicSock *s;
    quicly_conn_t *qconn;
    int entered = qconn_operation_enter(ctx, this_val, &c, &s, &qconn);
    if (entered < 0) return JS_EXCEPTION;
    if (entered == 0) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    size_t len;
    JSValue ab_ref;
    uint8_t *ptr = qc_get_buffer(ctx, argv[0], &len, &ab_ref);
    if (!ptr) {
        JS_FreeValue(ctx, ab_ref);
        result = JS_HasException(ctx) ? JS_EXCEPTION
                                      : JS_ThrowTypeError(ctx, "expected ArrayBuffer/TypedArray");
        goto done;
    }
    if (!s->closing) {
        ptls_iovec_t v = { ptr, len };
        quicly_send_datagram_frames(qconn, &v, 1);
    }
    JS_FreeValue(ctx, ab_ref);
done:
    qconn_operation_leave(ctx, c, s, !JS_IsException(result));
    return result;
}

static JSValue js_conn_close(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    QuicConn *c;
    QuicSock *s;
    quicly_conn_t *qconn;
    int entered = qconn_operation_enter(ctx, this_val, &c, &s, &qconn);
    if (entered < 0) return JS_EXCEPTION;
    if (entered == 0) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    uint64_t    code = 0;
    const char *reason = "";
    if (argc >= 1 && JS_ToIndex(ctx, &code, argv[0]) < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (argc >= 2) {
        reason = JS_ToCString(ctx, argv[1]);
        if (!reason) {
            result = JS_EXCEPTION;
            goto done;
        }
    }
    if (!s->closing) {
        quicly_error_t rc = quicly_close(
            qconn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(code), reason);
        if (rc != 0)
            result = JS_ThrowInternalError(ctx, "close: %" PRId64, rc);
    }
    if (argc >= 2) JS_FreeCString(ctx, reason);
done:
    qconn_operation_leave(ctx, c, s, !JS_IsException(result));
    return result;
}

static JSValue js_conn_get_stats(JSContext *ctx, JSValue this_val,
                                  int argc, JSValue *argv) {
    (void)argc; (void)argv;
    QuicConn *c;
    QuicSock *s;
    quicly_conn_t *qconn;
    int entered = qconn_operation_enter(ctx, this_val, &c, &s, &qconn);
    if (entered < 0) return JS_EXCEPTION;
    if (entered == 0) return JS_NULL;
    quicly_stats_t st;
    quicly_error_t stats_rc = quicly_get_stats(qconn, &st);
    qconn_operation_leave(ctx, c, s, 0);
    if (stats_rc != 0)
        return JS_ThrowInternalError(ctx, "getStats: %" PRId64, stats_rc);
    JSValue o = JS_NewObject(ctx);
    if (JS_IsException(o)) return o;
#define SET(k, v) JS_SetPropertyStr(ctx, o, k, v)
    SET("rttMin",        JS_NewFloat64(ctx, st.rtt.minimum == UINT32_MAX ? 0 : st.rtt.minimum));
    SET("rttLatest",     JS_NewFloat64(ctx, st.rtt.latest));
    SET("rttSmoothed",   JS_NewFloat64(ctx, st.rtt.smoothed));
    SET("pktSent",       JS_NewFloat64(ctx, (double)st.num_packets.sent));
    SET("pktLost",       JS_NewFloat64(ctx, (double)st.num_packets.lost));
    SET("pktReceived",   JS_NewFloat64(ctx, (double)st.num_packets.received));
    SET("bytesSent",     JS_NewFloat64(ctx, (double)st.num_bytes.sent));
    SET("bytesReceived", JS_NewFloat64(ctx, (double)st.num_bytes.received));
    SET("cwnd",          JS_NewFloat64(ctx, (double)st.cc.cwnd));
#undef SET
    if (!JS_HasException(ctx)) return o;
    JS_FreeValue(ctx, o);
    return JS_EXCEPTION;
}

/* Conn callback get/set (magic = QcConnCbIdx) */
static JSValue js_conn_get_cb(JSContext *ctx, JSValue this_val, int magic) {
    QuicConn *c = conn_get(ctx, this_val);
    return c ? JS_DupValue(ctx, c->callbacks[magic]) : JS_EXCEPTION;
}
static JSValue js_conn_set_cb(JSContext *ctx, JSValue this_val,
                               JSValue val, int magic) {
    QuicConn *c;
    QuicSock *s;
    quicly_conn_t *qconn;
    int entered = qconn_operation_enter(ctx, this_val, &c, &s, &qconn);
    if (entered < 0) return JS_EXCEPTION;
    if (entered == 0) return JS_UNDEFINED;
    (void)qconn;
    JSValue old = c->callbacks[magic];
    c->callbacks[magic] = JS_DupValue(ctx, val);
    JS_FreeValue(ctx, old);
    qconn_operation_leave(ctx, c, s, 0);
    return JS_UNDEFINED;
}

static const JSCFunctionListEntry qc_conn_proto[] = {
    JS_CFUNC_DEF("openStream",   1, js_conn_open_stream),
    JS_CFUNC_DEF("sendStream",   3, js_conn_send_stream),
    JS_CFUNC_DEF("resetStream",  2, js_conn_reset_stream),
    JS_CFUNC_DEF("stopSending",  2, js_conn_stop_sending),
    JS_CFUNC_DEF("sendDatagram", 1, js_conn_send_datagram),
    JS_CFUNC_DEF("close",        2, js_conn_close),
    JS_CFUNC_DEF("getStats",     0, js_conn_get_stats),
    JS_CGETSET_MAGIC_DEF("onstream",      js_conn_get_cb, js_conn_set_cb, QC_CB_STREAM),
    JS_CGETSET_MAGIC_DEF("ondata",        js_conn_get_cb, js_conn_set_cb, QC_CB_DATA),
    JS_CGETSET_MAGIC_DEF("onstreamreset", js_conn_get_cb, js_conn_set_cb, QC_CB_STREAM_RESET),
    JS_CGETSET_MAGIC_DEF("onstreamstop",  js_conn_get_cb, js_conn_set_cb, QC_CB_STREAM_STOP),
    JS_CGETSET_MAGIC_DEF("ondatagram",    js_conn_get_cb, js_conn_set_cb, QC_CB_DATAGRAM),
    JS_CGETSET_MAGIC_DEF("onconnected",   js_conn_get_cb, js_conn_set_cb, QC_CB_CONNECTED),
    JS_CGETSET_MAGIC_DEF("onclose",       js_conn_get_cb, js_conn_set_cb, QC_CB_CLOSE),
    JS_CGETSET_MAGIC_DEF("onerror",       js_conn_get_cb, js_conn_set_cb, QC_CB_ERROR),
};

/* ── QuicSocket JS class ──────────────────────────────────────── */

static int opt_str(JSContext *ctx, JSValue obj, const char *k,
                   const char **result) {
    *result = NULL;
    JSValue v = JS_GetPropertyStr(ctx, obj, k);
    if (JS_IsException(v)) return -1;
    if (JS_IsUndefined(v) || JS_IsNull(v)) {
        JS_FreeValue(ctx, v);
        return 0;
    }
    if (!JS_IsString(v)) {
        JS_FreeValue(ctx, v);
        JS_ThrowTypeError(ctx, "%s must be a string", k);
        return -1;
    }
    *result = JS_ToCString(ctx, v);
    JS_FreeValue(ctx, v);
    return *result ? 0 : -1;
}

static int opt_u32(JSContext *ctx, JSValue obj, const char *k, uint32_t def,
                   uint32_t *result) {
    *result = def;
    JSValue v = JS_GetPropertyStr(ctx, obj, k);
    if (JS_IsException(v)) return -1;
    if (JS_IsUndefined(v) || JS_IsNull(v)) {
        JS_FreeValue(ctx, v);
        return 0;
    }
    int rc = JS_ToUint32(ctx, result, v);
    JS_FreeValue(ctx, v);
    return rc;
}

static int opt_bool(JSContext *ctx, JSValue obj, const char *k, int def,
                    int *result) {
    *result = def;
    JSValue v = JS_GetPropertyStr(ctx, obj, k);
    if (JS_IsException(v)) return -1;
    if (JS_IsUndefined(v) || JS_IsNull(v)) {
        JS_FreeValue(ctx, v);
        return 0;
    }
    int rc = JS_ToBool(ctx, v);
    JS_FreeValue(ctx, v);
    if (rc < 0) return -1;
    *result = rc;
    return 0;
}

static int opt_present_u32(JSContext *ctx, JSValue obj, const char *k,
                           int *present, uint32_t *result) {
    *present = 0;
    JSValue v = JS_GetPropertyStr(ctx, obj, k);
    if (JS_IsException(v)) return -1;
    if (JS_IsUndefined(v)) {
        JS_FreeValue(ctx, v);
        return 0;
    }
    int rc = JS_ToUint32(ctx, result, v);
    JS_FreeValue(ctx, v);
    if (rc < 0) return -1;
    *present = 1;
    return 0;
}

static void qsock_try_free(QuicSock *s) {
    if (s->handles_open > 0 || s->pending_sends > 0) return;
    for (size_t i = 0; i < s->ncerts; i++) OPENSSL_free(s->certs[i].base);
    if (s->sign_cert.key) ptls_openssl_dispose_sign_certificate(&s->sign_cert);
    if (s->verify_initialized) ptls_openssl_dispose_verify_certificate(&s->verify_cert);
    free(s->alpn_storage);
    tjs__free(s);
}

static void on_udp_closed(uv_handle_t *h) {
    QuicSock *s = container_of((uv_udp_t *)h, QuicSock, udp);
    s->handles_open--;
    qsock_try_free(s);
}

static void on_timer_closed(uv_handle_t *h) {
    QuicSock *s = container_of((uv_timer_t *)h, QuicSock, timer);
    s->handles_open--;
    qsock_try_free(s);
}

/* Tear down conns + stop libuv handles (async free via close cbs). */
static void qsock_close(JSRuntime *rt, QuicSock *s) {
    if (!s || s->close_finished) return;
    s->closing = 1;
    if (s->in_receive) return;
    s->close_finished = 1;
    for (int i = 0; i < MAX_CONNS; i++) {
        QuicConn *c = s->conns[i];
        if (!c) continue;
        qconn_dispose(rt, c);
    }
    for (int i = 0; i < QS_CB_COUNT; i++) {
        JS_FreeValueRT(rt, s->callbacks[i]);
        s->callbacks[i] = JS_NULL;
    }
    if (s->udp_initialized) {
        uv_udp_recv_stop(&s->udp);
        if (!uv_is_closing((uv_handle_t *)&s->udp))
            uv_close((uv_handle_t *)&s->udp, on_udp_closed);
    }
    if (s->timer_initialized) {
        uv_timer_stop(&s->timer);
        if (!uv_is_closing((uv_handle_t *)&s->timer))
            uv_close((uv_handle_t *)&s->timer, on_timer_closed);
    }
    qsock_try_free(s);
}

static void qc_sock_finalizer(JSRuntime *rt, JSValue val) {
    QuicSock *s = JS_GetOpaque(val, qc_sock_class_id);
    if (!s) return;
    JS_SetOpaque(val, NULL);
    qsock_close(rt, s);
}

static void qc_sock_mark(JSRuntime *rt, JSValueConst val, JS_MarkFunc *mark_func) {
    QuicSock *s = JS_GetOpaque(val, qc_sock_class_id);
    if (!s) return;
    for (int i = 0; i < QS_CB_COUNT; i++)
        JS_MarkValue(rt, s->callbacks[i], mark_func);
    for (int i = 0; i < MAX_CONNS; i++) {
        if (s->conns[i]) JS_MarkValue(rt, s->conns[i]->self, mark_func);
    }
}

static JSClassDef qc_sock_class = {
    "Socket",
    .finalizer = qc_sock_finalizer,
    .gc_mark = qc_sock_mark,
};

static inline QuicSock *sock_get(JSContext *ctx, JSValue v) {
    QuicSock *s = JS_GetOpaque2(ctx, v, qc_sock_class_id);
    /* opaque is cleared on close; JS_GetOpaque2 only throws on class mismatch */
    if (!s && !JS_HasException(ctx))
        JS_ThrowTypeError(ctx, "QUIC socket is closed");
    return s;
}

static int qsock_operation_enter(JSContext *ctx, JSValue this_val,
                                 QuicSock **sock) {
    *sock = sock_get(ctx, this_val);
    if (!*sock) return -1;
    if ((*sock)->closing) return 0;
    (*sock)->in_receive++;
    return 1;
}

static int qsock_operation_leave(JSContext *ctx, QuicSock *s) {
    if (s->in_receive > 0) s->in_receive--;
    if (!s->closing) return 1;
    qsock_close(JS_GetRuntime(ctx), s);
    return 0;
}

static int on_client_hello(ptls_on_client_hello_t *self, ptls_t *tls,
                           ptls_on_client_hello_parameters_t *params) {
    QuicSock *s = container_of(self, QuicSock, on_client_hello_cb);
    if (s->alpn.len == 0) return 0;

    for (size_t i = 0; i < params->negotiated_protocols.count; i++) {
        ptls_iovec_t offered = params->negotiated_protocols.list[i];
        if (offered.len == s->alpn.len &&
            memcmp(offered.base, s->alpn.base, s->alpn.len) == 0) {
            return ptls_set_negotiated_protocol(tls, (const char *)s->alpn.base, s->alpn.len);
        }
    }
    return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}

/* ── Transport params / CC helpers ────────────────────────────── */

static int apply_transport_params(JSContext *ctx, JSValue opts,
                                  quicly_context_t *qctx) {
    JSValue t = JS_GetPropertyStr(ctx, opts, "transport");
    if (JS_IsException(t)) return -1;
    if (JS_IsUndefined(t) || JS_IsNull(t)) {
        JS_FreeValue(ctx, t);
        return 0;
    }
    if (!JS_IsObject(t)) {
        JS_FreeValue(ctx, t);
        JS_ThrowTypeError(ctx, "transport must be an object");
        return -1;
    }

    quicly_transport_parameters_t *tp = &qctx->transport_params;
    uint32_t u;
    int present;

#define TP(key, field) \
    do { \
        if (opt_present_u32(ctx, t, key, &present, &u) < 0) goto fail; \
        if (present) field = u; \
    } while (0)

    TP("maxStreamsBidi", tp->max_streams_bidi);
    TP("maxStreamsUni",  tp->max_streams_uni);
    TP("maxData",        tp->max_data);

    if (opt_present_u32(ctx, t, "maxStreamData", &present, &u) < 0) goto fail;
    if (present) {
        tp->max_stream_data.bidi_local  = u;
        tp->max_stream_data.bidi_remote = u;
        tp->max_stream_data.uni         = u;
    }

    TP("idleTimeoutMs", tp->max_idle_timeout);

    TP("initialRttMs", qctx->loss.default_initial_rtt);

    JSValue v = JS_GetPropertyStr(ctx, t, "cc");
    if (JS_IsException(v)) goto fail;
    if (!JS_IsUndefined(v)) {
        if (!JS_IsString(v)) {
            JS_FreeValue(ctx, v);
            JS_ThrowTypeError(ctx, "cc must be \"reno\", \"cubic\", or \"pico\"");
            goto fail;
        }
        const char *cc = JS_ToCString(ctx, v);
        JS_FreeValue(ctx, v);
        if (!cc) goto fail;
        if (strcmp(cc, "reno") == 0)
            qctx->init_cc = &quicly_cc_reno_init;
        else if (strcmp(cc, "cubic") == 0)
            qctx->init_cc = &quicly_cc_cubic_init;
        else if (strcmp(cc, "pico") == 0)
            qctx->init_cc = &quicly_cc_pico_init;
        else {
            JS_ThrowRangeError(ctx, "unknown congestion control algorithm: %s", cc);
            JS_FreeCString(ctx, cc);
            goto fail;
        }
        JS_FreeCString(ctx, cc);
    } else {
        JS_FreeValue(ctx, v);
    }
#undef TP

    JS_FreeValue(ctx, t);
    return 0;

fail:
#undef TP
    JS_FreeValue(ctx, t);
    return -1;
}

/* QuicSocket constructor: new QuicSocket({ host, port, cert, key, isServer, alpn? })
 * cert/key are PEM strings (not file paths). */
static JSValue js_sock_ctor(JSContext *ctx, JSValue new_target,
                             int argc, JSValue *argv) {
    (void)new_target;
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "Socket(opts) requires at least one argument");
    if (!JS_IsObject(argv[0]))
        return JS_ThrowTypeError(ctx, "Socket options must be an object");

    uv_loop_t *loop = TJS_GetLoop(TJS_GetRuntime(ctx));
    JSValue opts     = argv[0];
    JSValue obj      = JS_UNDEFINED;
    const char *host = NULL, *cert = NULL, *key = NULL, *alpn_str = NULL;
    uint32_t port = 4433;
    int verify_peer = 1;
    int uv_rc = 0;

    QuicSock *s = tjs__mallocz(sizeof(*s));
    if (!s) return JS_ThrowOutOfMemory(ctx);
    s->ctx  = ctx;
    s->loop = loop;
    for (int i = 0; i < QS_CB_COUNT; i++) s->callbacks[i] = JS_NULL;

    /* Parse options */
    if (opt_str(ctx, opts, "host", &host) < 0 ||
        opt_str(ctx, opts, "cert", &cert) < 0 ||
        opt_str(ctx, opts, "key", &key) < 0 ||
        opt_str(ctx, opts, "alpn", &alpn_str) < 0 ||
        opt_u32(ctx, opts, "port", 4433, &port) < 0 ||
        opt_bool(ctx, opts, "isServer", 0, &s->is_server) < 0 ||
        opt_bool(ctx, opts, "verifyPeer", verify_peer, &verify_peer) < 0)
        goto fail;
    if (port > 65535) {
        JS_ThrowRangeError(ctx, "port must be between 0 and 65535");
        goto fail;
    }

    /* TLS setup */
    s->tls.random_bytes         = ptls_openssl_random_bytes;
    s->tls.get_time             = &ptls_get_time;
    s->tls.key_exchanges        = ptls_openssl_key_exchanges;
    s->tls.cipher_suites        = ptls_openssl_cipher_suites;
    s->tls.certificates.list    = s->certs;
    s->tls.certificates.count   = 0;

    /* ALPN */
    if (alpn_str) {
        size_t len = strlen(alpn_str);
        s->alpn_storage = malloc(len + 1);
        if (!s->alpn_storage) goto oom;
        memcpy(s->alpn_storage, alpn_str, len + 1);
        s->alpn                    = ptls_iovec_init(s->alpn_storage, len);
        s->on_client_hello_cb.cb   = on_client_hello;
        s->tls.on_client_hello     = &s->on_client_hello_cb;
    }

    /* Cert / key (PEM strings) */
    if (cert) {
        if (load_cert_chain(s, cert) != 0) {
            JS_ThrowTypeError(ctx, "invalid certificate chain");
            goto fail;
        }
        s->tls.certificates.count = s->ncerts;
    }
    if (key && load_private_key(s, key) != 0) {
        JS_ThrowTypeError(ctx, "invalid private key");
        goto fail;
    }
    if (s->is_server && (!cert || !key)) {
        JS_ThrowTypeError(ctx, "server sockets require cert and key");
        goto fail;
    }
    if (verify_peer && !s->is_server) {
        if (ptls_openssl_init_verify_certificate(&s->verify_cert, NULL) != 0) {
            JS_ThrowInternalError(ctx, "failed to initialize certificate verification");
            goto fail;
        }
        s->verify_initialized = 1;
        if (load_ca_certificates(ctx, opts, s->verify_cert.cert_store) != 0) {
            if (!JS_HasException(ctx))
                JS_ThrowTypeError(ctx, "caCerts must contain valid PEM certificates");
            goto fail;
        }
        s->tls.verify_certificate = &s->verify_cert.super;
    }

    /* quicly context */
    s->qctx = quicly_spec_context;
    s->qctx.tls = &s->tls;
    quicly_amend_ptls_context(s->qctx.tls);
    s->qctx.transport_params.max_streams_uni = 100;
    s->qctx.transport_params.max_datagram_frame_size =
        s->qctx.transport_params.max_udp_payload_size;
    s->qctx.stream_open            = &s->on_stream_open_cb;
    s->qctx.closed                 = &s->on_closed_cb;
    s->qctx.receive_datagram_frame = &s->on_datagram_cb;
    s->on_stream_open_cb.cb        = on_stream_open;
    s->on_closed_cb.cb             = on_closed;
    s->on_datagram_cb.cb           = on_receive_datagram_frame;
    if (apply_transport_params(ctx, opts, &s->qctx) < 0) goto fail;

    /* UDP */
    uv_rc = uv_udp_init(loop, &s->udp);
    if (uv_rc != 0) goto uv_fail;
    s->udp_initialized = 1;
    s->handles_open++;

    /* Timer */
    uv_rc = uv_timer_init(loop, &s->timer);
    if (uv_rc != 0) goto uv_fail;
    s->timer_initialized = 1;
    s->handles_open++;

    if (s->is_server) {
        struct sockaddr_storage addr;
        const char *bind_host = host ? host : "0.0.0.0";
        if (strchr(bind_host, ':')) {
            uv_rc = uv_ip6_addr(bind_host, (int)port, (struct sockaddr_in6 *)&addr);
        } else {
            uv_rc = uv_ip4_addr(bind_host, (int)port, (struct sockaddr_in *)&addr);
        }
        if (uv_rc != 0) goto uv_fail;
        uv_rc = uv_udp_bind(&s->udp, (struct sockaddr *)&addr, 0);
        if (uv_rc != 0) goto uv_fail;
    }
    uv_rc = uv_udp_recv_start(&s->udp, on_udp_alloc, on_udp_recv);
    if (uv_rc != 0) goto uv_fail;

    obj = JS_NewObjectClass(ctx, qc_sock_class_id);
    if (JS_IsException(obj)) goto fail;
    JS_SetOpaque(obj, s);
    goto done;

oom:
    JS_ThrowOutOfMemory(ctx);
    goto fail;
uv_fail:
    JS_ThrowInternalError(ctx, "QUIC socket: %s", uv_strerror(uv_rc));
fail:
    qsock_close(JS_GetRuntime(ctx), s);
    obj = JS_EXCEPTION;
done:
    JS_FreeCString(ctx, host);
    JS_FreeCString(ctx, cert);
    JS_FreeCString(ctx, key);
    JS_FreeCString(ctx, alpn_str);
    return obj;
}

/* QuicSocket.close() — stop UDP/timer so the event loop can exit. */
static JSValue js_sock_close(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    (void)argc;
    (void)argv;
    if (JS_GetClassID(this_val) != qc_sock_class_id) {
        (void)sock_get(ctx, this_val);
        return JS_EXCEPTION;
    }
    QuicSock *s = JS_GetOpaque(this_val, qc_sock_class_id);
    if (!s) return JS_UNDEFINED;
    JS_SetOpaque(this_val, NULL);
    qsock_close(JS_GetRuntime(ctx), s);
    return JS_UNDEFINED;
}

/* QuicSocket.connect(sock, host, port) → QuicConnection */
static JSValue js_sock_connect(JSContext *ctx, JSValue this_val,
                                int argc, JSValue *argv) {
    QuicSock *s;
    int entered = qsock_operation_enter(ctx, this_val, &s);
    if (entered < 0) return JS_EXCEPTION;
    if (entered == 0) return JS_ThrowTypeError(ctx, "socket is closed");
    if (argc < 1) {
        qsock_operation_leave(ctx, s);
        return JS_ThrowTypeError(ctx, "connect requires a host");
    }
    /* A server socket never gets tls.verify_certificate (see js_sock_ctor), so a
     * client handshake on one would skip chain *and* CertificateVerify checks. */
    if (s->is_server) {
        qsock_operation_leave(ctx, s);
        return JS_ThrowTypeError(ctx, "connect() requires a client socket; a server socket has no peer verification");
    }

    JSValue result = JS_EXCEPTION;
    const char *host = NULL;
    const char *server_name_arg = NULL;
    QuicConn *c = NULL;
    uint32_t port = 4433;

    host = JS_ToCString(ctx, argv[0]);
    if (!host) goto done;
    if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1]) &&
        JS_ToUint32(ctx, &port, argv[1]) < 0)
        goto done;
    if (port > 65535) {
        JS_ThrowRangeError(ctx, "port must be between 0 and 65535");
        goto done;
    }
    const char *server_name = host;
    if (argc >= 3 && !JS_IsUndefined(argv[2]) && !JS_IsNull(argv[2])) {
        server_name_arg = JS_ToCString(ctx, argv[2]);
        if (!server_name_arg) goto done;
        server_name = server_name_arg;
    }
    if (s->closing) {
        JS_ThrowTypeError(ctx, "socket was closed while converting connect arguments");
        goto done;
    }

    struct sockaddr_storage remote;
    int resolve_rc = resolve_udp_addr(s->loop, host, port, &remote);
    if (resolve_rc != 0) {
        JS_ThrowInternalError(ctx, "resolve %s: %s", host, uv_strerror(resolve_rc));
        goto done;
    }

    c = calloc(1, sizeof(*c));
    if (!c) {
        JS_ThrowOutOfMemory(ctx);
        goto done;
    }
    if (qsock_add_conn(s, c) != 0) {
        free(c);
        c = NULL;
        JS_ThrowInternalError(ctx, "too many connections");
        goto done;
    }
    c->sock = s;
    c->ctx  = ctx;
    c->self = JS_UNDEFINED;
    for (int i = 0; i < QC_CB_COUNT; i++) c->callbacks[i] = JS_NULL;

    ptls_handshake_properties_t hs_properties = { 0 };
    if (s->alpn.len != 0) {
        hs_properties.client.negotiated_protocols.list = &s->alpn;
        hs_properties.client.negotiated_protocols.count = 1;
    }

    quicly_error_t rc = quicly_connect(
        &c->qconn, &s->qctx, server_name, (struct sockaddr *)&remote, NULL,
        &s->next_cid, ptls_iovec_init(NULL, 0), &hs_properties, NULL, NULL);
    if (rc != 0) {
        qsock_remove_conn(s, c);
        free(c);
        c = NULL;
        JS_ThrowInternalError(ctx, "quicly_connect: %" PRId64, rc);
        goto done;
    }

    c->self = JS_NewObjectClass(ctx, qc_conn_class_id);
    if (JS_IsException(c->self)) {
        qsock_remove_conn(s, c);
        quicly_free(c->qconn);
        free(c);
        c = NULL;
        goto done;
    }
    JS_SetOpaque(c->self, c);
    result = JS_DupValue(ctx, c->self);

done:
    JS_FreeCString(ctx, server_name_arg);
    JS_FreeCString(ctx, host);
    int socket_open = qsock_operation_leave(ctx, s);
    if (!socket_open) {
        if (!JS_IsException(result)) JS_FreeValue(ctx, result);
        if (JS_HasException(ctx)) return JS_EXCEPTION;
        return JS_ThrowTypeError(ctx, "socket was closed during connect");
    }
    if (JS_IsException(result)) return result;

    quicly_error_t flush_rc = qconn_flush(c);
    if (flush_rc == 0) return result;
    JS_FreeValue(ctx, result);
    return JS_ThrowInternalError(ctx, "initial QUIC send failed: %" PRId64, flush_rc);
}

/* Sock callback get/set */
static JSValue js_sock_get_cb(JSContext *ctx, JSValue this_val, int magic) {
    QuicSock *s = sock_get(ctx, this_val);
    return s ? JS_DupValue(ctx, s->callbacks[magic]) : JS_EXCEPTION;
}
static JSValue js_sock_set_cb(JSContext *ctx, JSValue this_val,
                               JSValue val, int magic) {
    QuicSock *s;
    int entered = qsock_operation_enter(ctx, this_val, &s);
    if (entered < 0) return JS_EXCEPTION;
    if (entered == 0) return JS_UNDEFINED;
    JSValue old = s->callbacks[magic];
    s->callbacks[magic] = JS_DupValue(ctx, val);
    JS_FreeValue(ctx, old);
    qsock_operation_leave(ctx, s);
    return JS_UNDEFINED;
}

static const JSCFunctionListEntry qc_sock_proto[] = {
    JS_CFUNC_DEF        ("connect",   2, js_sock_connect),
    JS_CFUNC_DEF        ("close",     0, js_sock_close),
    JS_CGETSET_MAGIC_DEF("onconnection", js_sock_get_cb, js_sock_set_cb, QS_CB_CONNECTION),
    JS_CGETSET_MAGIC_DEF("onerror",      js_sock_get_cb, js_sock_set_cb, QS_CB_ERROR),
};

/* ── Constants ────────────────────────────────────────────────── */
static JSValue make_constants(JSContext *ctx) {
    JSValue o = JS_NewObject(ctx);
    if (JS_IsException(o)) return o;
#define C(name, value) \
    JS_SetPropertyStr(ctx, o, name, JS_NewFloat64(ctx, (double)(value)))
    C("ERROR_PACKET_IGNORED", QUICLY_ERROR_PACKET_IGNORED);
    C("ERROR_FREE_CONNECTION", QUICLY_ERROR_FREE_CONNECTION);
    C("TRANSPORT_ERROR_NO_ERROR", QUICLY_ERROR_GET_ERROR_CODE(QUICLY_TRANSPORT_ERROR_NONE));
    C("TRANSPORT_ERROR_INTERNAL_ERROR", QUICLY_ERROR_GET_ERROR_CODE(QUICLY_TRANSPORT_ERROR_INTERNAL));
    C("TRANSPORT_ERROR_FLOW_CONTROL_ERROR", QUICLY_ERROR_GET_ERROR_CODE(QUICLY_TRANSPORT_ERROR_FLOW_CONTROL));
    C("TRANSPORT_ERROR_STREAM_LIMIT_ERROR", QUICLY_ERROR_GET_ERROR_CODE(QUICLY_TRANSPORT_ERROR_STREAM_LIMIT));
    C("TRANSPORT_ERROR_STREAM_STATE_ERROR", QUICLY_ERROR_GET_ERROR_CODE(QUICLY_TRANSPORT_ERROR_STREAM_STATE));
    C("TRANSPORT_ERROR_FINAL_SIZE_ERROR", QUICLY_ERROR_GET_ERROR_CODE(QUICLY_TRANSPORT_ERROR_FINAL_SIZE));
    C("TRANSPORT_ERROR_PROTOCOL_VIOLATION", QUICLY_ERROR_GET_ERROR_CODE(QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION));
    C("TRANSPORT_ERROR_APPLICATION_ERROR", QUICLY_ERROR_GET_ERROR_CODE(QUICLY_TRANSPORT_ERROR_APPLICATION));
#undef C
    if (!JS_HasException(ctx)) return o;
    JS_FreeValue(ctx, o);
    return JS_EXCEPTION;
}

/* ── Module init ──────────────────────────────────────────────────
 * Init function is exposed (non-static) so it can be statically
 * linked into a host like cno-cli. When CJS_STATIC_LINK is defined,
 * we skip DEF_MODULE — its emitted `tjs_module_info` symbol would
 * collide with other statically linked extensions in the same binary.
 */

void qc_ns_init(JSContext *ctx, JSValue ns) {
    JSRuntime *rt = JS_GetRuntime(ctx);
    /* QuicConnection class */
    JS_NewClassID(rt, &qc_conn_class_id);
    JS_NewClass(rt, qc_conn_class_id, &qc_conn_class);
    JSValue conn_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, conn_proto, qc_conn_proto, countof(qc_conn_proto));
    JS_SetClassProto(ctx, qc_conn_class_id, conn_proto);

    /* QuicSocket class */
    JS_NewClassID(rt, &qc_sock_class_id);
    JS_NewClass(rt, qc_sock_class_id, &qc_sock_class);
    JSValue sock_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, sock_proto, qc_sock_proto, countof(qc_sock_proto));

    JSValue sock_ctor = JS_NewCFunction2(ctx, js_sock_ctor,
                                          "Socket", 1, JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, sock_ctor, sock_proto);
    JS_SetClassProto(ctx, qc_sock_class_id, sock_proto);

    JS_SetPropertyStr(ctx, ns, "Socket",    sock_ctor);
    JS_SetPropertyStr(ctx, ns, "constants", make_constants(ctx));
}

#ifndef CJS_STATIC_LINK
DEF_MODULE("ext:quic", qc_ns_init, false)
#endif
