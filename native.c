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
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#if defined(_MSC_VER)
#include <openssl/applink.c>
#endif
#include <threads.h>

thread_local JSClassID qc_conn_class_id;
thread_local JSClassID qc_sock_class_id;
static void qconn_flush(QuicConn *c);
static void qsock_update_timer(QuicSock *s);
static QuicConn *qsock_find_conn(QuicSock *s, quicly_conn_t *qc);

/* ── Time helper (ms since epoch, same domain as quicly) ─────── */
static int64_t now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
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

/* ── UDP send helper (copies data, frees on completion) ─────── */
typedef struct { uv_udp_send_t req; uint8_t data[]; } SendReq;

static void on_udp_sent(uv_udp_send_t *req, int status) {
    (void)status;
    free(req);
}

static void qsock_udp_send(QuicSock *s, const struct sockaddr *dest,
                            const void *data, size_t len) {
    SendReq *req = malloc(sizeof(SendReq) + len);
    if (!req) return;
    memcpy(req->data, data, len);
    uv_buf_t buf = uv_buf_init((char *)req->data, len);
    if (uv_udp_send(&req->req, &s->udp, &buf, 1, dest, on_udp_sent) != 0)
        free(req);
}

/* ── quicly send loop ─────────────────────────────────────────── */
static void qconn_flush(QuicConn *c) {
    if (c->sock->in_receive) {
        c->sock->pending_flush = 1;
        return;
    }

    quicly_address_t dest, src;
    struct iovec     dgrams[DGRAM_BATCH];
    uint8_t          buf[DGRAM_BATCH * MAX_PKT_SIZE];
    size_t           ndgrams;

    while (1) {
        ndgrams = DGRAM_BATCH;
        int rc  = quicly_send(c->qconn, &dest, &src, dgrams, &ndgrams,
                               buf, sizeof(buf));
        if (rc == QUICLY_ERROR_FREE_CONNECTION) {
            /* connection is done */
            break;
        }
        if (rc != 0 || ndgrams == 0) break;
        for (size_t i = 0; i < ndgrams; i++)
            qsock_udp_send(c->sock, &dest.sa,
                           dgrams[i].iov_base, dgrams[i].iov_len);
    }
    qsock_update_timer(c->sock);
}

/* ── Timer ────────────────────────────────────────────────────── */
static void on_timer(uv_timer_t *t) {
    QuicSock *s   = container_of(t, QuicSock, timer);
    int64_t   now = now_ms();
    for (int i = 0; i < MAX_CONNS; i++) {
        QuicConn *c = s->conns[i];
        if (!c) continue;
        if (quicly_get_first_timeout(c->qconn) <= now)
            qconn_flush(c);
    }
    qsock_update_timer(s);
}

static void qsock_update_timer(QuicSock *s) {
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
    (void)off;
    QuicStreamData *sd = stream->data;
    QuicConn  *c   = sd->conn;
    JSContext *ctx = c->ctx;
    bool fin       = quicly_recvstate_transfer_complete(&stream->recvstate);
    JSValue argv[3] = {
        JS_NewFloat64(ctx, (double)stream->stream_id),
        JS_NewArrayBufferCopy(ctx, src, len),
        JS_NewBool(ctx, fin),
    };
    QC_CALL(ctx, c->callbacks, QC_CB_DATA, 3, argv);
    JS_FreeValue(ctx, argv[0]);
    JS_FreeValue(ctx, argv[1]);
    JS_FreeValue(ctx, argv[2]);
    quicly_stream_sync_recvbuf(stream, len);
}

static void stream_on_receive_reset(quicly_stream_t *stream, quicly_error_t err) {
    QuicStreamData *sd = stream->data;
    QuicConn  *c   = sd->conn;
    JSContext *ctx = c->ctx;
    JSValue argv[2] = {
        JS_NewFloat64(ctx, (double)stream->stream_id),
        JS_NewInt32(ctx, err),
    };
    QC_CALL(ctx, c->callbacks, QC_CB_STREAM_RESET, 2, argv);
    JS_FreeValue(ctx, argv[0]);
    JS_FreeValue(ctx, argv[1]);
}

static const quicly_stream_callbacks_t stream_cbs = {
    .on_destroy       = stream_on_destroy,
    .on_send_shift    = quicly_streambuf_egress_shift,
    .on_send_emit     = quicly_streambuf_egress_emit,
    .on_send_stop     = NULL,
    .on_receive       = stream_on_receive,
    .on_receive_reset = stream_on_receive_reset,
};

/* ── quicly connection callbacks ──────────────────────────────── */
static quicly_error_t on_stream_open(quicly_stream_open_t *self, quicly_stream_t *stream) {
    QuicSock *s  = container_of(self, QuicSock, on_stream_open_cb);
    QuicConn *c  = qsock_find_conn(s, stream->conn);
    if (!c) return QUICLY_ERROR_PACKET_IGNORED;
    quicly_streambuf_create(stream, sizeof(QuicStreamData));
    ((QuicStreamData *)stream->data)->conn = c;
    stream->callbacks = &stream_cbs;
    JSValue argv[2] = {
        JS_NewFloat64(s->ctx, (double)stream->stream_id),
        JS_NewBool(s->ctx, STREAM_IS_BIDI(stream->stream_id)),
    };
    QC_CALL(s->ctx, c->callbacks, QC_CB_STREAM, 2, argv);
    JS_FreeValue(s->ctx, argv[0]);
    JS_FreeValue(s->ctx, argv[1]);
    return 0;
}

static void on_closed(quicly_closed_t *self, quicly_conn_t *qconn) {
    uint64_t frame_type;
    const char *reason;
    int is_remote;
    int err = quicly_get_close_reason(qconn, &frame_type, &reason, &is_remote);
    (void)frame_type;
    (void)is_remote;
    QuicSock *s = container_of(self, QuicSock, on_closed_cb);
    QuicConn *c = qsock_find_conn(s, qconn);
    if (!c) return;
    JSValue argv[2] = {
        JS_NewInt32(s->ctx, err),
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
    JSValue buf = JS_NewArrayBufferCopy(s->ctx, payload.base, payload.len);
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
    if (nread <= 0) { free(buf->base); return; }

    QuicSock *s = container_of(h, QuicSock, udp);

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
                int rc = quicly_accept(&qconn, &s->qctx, NULL, &remote.sa,
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
                for (int k = 0; k < QC_CB_COUNT; k++)
                    c->callbacks[k] = JS_NULL;

                /* Create JS object and expose via onconnection */
                c->self = JS_NewObjectClass(s->ctx, qc_conn_class_id);
                JS_SetOpaque(c->self, c);

                JSValue jconn = JS_DupValue(s->ctx, c->self);
                QC_CALL(s->ctx, s->callbacks, QS_CB_CONNECTION, 1, &jconn);
                JS_FreeValue(s->ctx, jconn);
                qconn_flush(c);
                continue;
            }

            if (!c) continue; /* client: unknown packet, drop */

            s->in_receive++;
            quicly_receive(c->qconn, NULL, &remote.sa, &pkt);
            s->in_receive--;

            /* Notify JS if handshake just completed */
            if (quicly_connection_is_ready(c->qconn)) {
                /* Fire onconnected once — guard with a flag via stream_id hack:
                 * use a simple boolean in QuicConn via next_cid space.
                 * Here we just always fire; JS layer should guard if needed. */
                QC_CALL(s->ctx, c->callbacks, QC_CB_CONNECTED, 0, NULL);
            }

            qconn_flush(c);
            if (s->pending_flush && !s->in_receive) {
                s->pending_flush = 0;
                for (int j = 0; j < MAX_CONNS; j++) {
                    if (s->conns[j]) qconn_flush(s->conns[j]);
                }
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
    return s->ncerts > 0 ? 0 : -1;
}

static int load_private_key(QuicSock *s, const char *pem) {
    BIO *bio = BIO_new_mem_buf(pem, -1);
    if (!bio) return -1;
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) return -1;
    ptls_openssl_init_sign_certificate(&s->sign_cert, pkey);
    EVP_PKEY_free(pkey);
    s->tls.sign_certificate = &s->sign_cert.super;
    return 0;
}

/* ── QuicConn JS class ────────────────────────────────────────── */
static void qc_conn_finalizer(JSRuntime *rt, JSValue val) {
    QuicConn *c = JS_GetOpaque(val, qc_conn_class_id);
    if (!c) return;
    if (c->qconn) { quicly_free(c->qconn); c->qconn = NULL; }
    if (c->sock)  qsock_remove_conn(c->sock, c);
    for (int i = 0; i < QC_CB_COUNT; i++) JS_FreeValueRT(rt, c->callbacks[i]);
    JS_FreeValueRT(rt, c->self);
    free(c);
}

static JSClassDef qc_conn_class = { "Connection", .finalizer = qc_conn_finalizer };

static inline QuicConn *conn_get(JSContext *ctx, JSValue v) {
    return JS_GetOpaque2(ctx, v, qc_conn_class_id);
}

static JSValue js_conn_open_stream(JSContext *ctx, JSValue this_val,
                                    int argc, JSValue *argv) {
    QuicConn *c = conn_get(ctx, this_val);
    if (!c || !c->qconn) return JS_UNDEFINED;
    int bidi = argc >= 1 ? JS_ToBool(ctx, argv[0]) : 1;
    quicly_stream_t *stream;
    int rc = quicly_open_stream(c->qconn, &stream, !bidi);
    if (rc != 0) return JS_ThrowInternalError(ctx, "open_stream: %d", rc);
    if (stream->data == NULL) {
        quicly_streambuf_create(stream, sizeof(QuicStreamData));
        ((QuicStreamData *)stream->data)->conn = c;
        stream->callbacks = &stream_cbs;
    }

    qconn_flush(c);
    return JS_NewFloat64(ctx, (double)stream->stream_id);
}

static JSValue js_conn_send_stream(JSContext *ctx, JSValue this_val,
                                    int argc, JSValue *argv) {
    QuicConn *c = conn_get(ctx, this_val);
    if (!c || !c->qconn) return JS_UNDEFINED;
    uint64_t sid;
    JS_ToIndex(ctx, &sid, argv[0]);
    quicly_stream_t *stream = quicly_get_stream(c->qconn, (int64_t)sid);
    if (!stream) return JS_ThrowRangeError(ctx, "unknown stream %llu", (unsigned long long)sid);

    /* get data */
    size_t   len; JSValue ab_ref;
    size_t   off = 0;
    uint8_t *ptr = NULL;
    /* accept ArrayBuffer or TypedArray */
    ptr = JS_GetArrayBuffer(ctx, &len, argv[1]);
    ab_ref = JS_UNDEFINED;
    if (!ptr) {
        size_t blen;
        JSValue ab = JS_GetTypedArrayBuffer(ctx, argv[1], &off, &blen, NULL);
        if (!JS_IsException(ab)) {
            ptr    = JS_GetArrayBuffer(ctx, &len, ab);
            len    = blen;
            ab_ref = ab;
        }
    }
    if (!ptr) return JS_ThrowTypeError(ctx, "expected ArrayBuffer/TypedArray");

    quicly_streambuf_egress_write(stream, ptr + off, len);
    JS_FreeValue(ctx, ab_ref);

    int fin = argc >= 3 ? JS_ToBool(ctx, argv[2]) : 0;
    if (fin) quicly_streambuf_egress_shutdown(stream);
    qconn_flush(c);
    return JS_UNDEFINED;
}

static JSValue js_conn_reset_stream(JSContext *ctx, JSValue this_val,
                                     int argc, JSValue *argv) {
    QuicConn *c = conn_get(ctx, this_val);
    if (!c || !c->qconn) return JS_UNDEFINED;
    uint64_t sid; uint32_t code = 0;
    JS_ToIndex(ctx, &sid, argv[0]);
    if (argc >= 2) JS_ToUint32(ctx, &code, argv[1]);
    quicly_stream_t *stream = quicly_get_stream(c->qconn, (int64_t)sid);
    if (stream) quicly_reset_stream(stream, code);
    qconn_flush(c);
    return JS_UNDEFINED;
}

static JSValue js_conn_stop_sending(JSContext *ctx, JSValue this_val,
                                     int argc, JSValue *argv) {
    QuicConn *c = conn_get(ctx, this_val);
    if (!c || !c->qconn) return JS_UNDEFINED;
    uint64_t sid; uint32_t code = 0;
    JS_ToIndex(ctx, &sid, argv[0]);
    if (argc >= 2) JS_ToUint32(ctx, &code, argv[1]);
    quicly_stream_t *stream = quicly_get_stream(c->qconn, (int64_t)sid);
    if (stream) quicly_request_stop(stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE(code));
    qconn_flush(c);
    return JS_UNDEFINED;
}

static JSValue js_conn_send_datagram(JSContext *ctx, JSValue this_val,
                                      int argc, JSValue *argv) {
    (void)argc;
    QuicConn *c = conn_get(ctx, this_val);
    if (!c || !c->qconn) return JS_UNDEFINED;
    size_t len;
    uint8_t *ptr = JS_GetArrayBuffer(ctx, &len, argv[0]);
    if (!ptr) return JS_ThrowTypeError(ctx, "expected ArrayBuffer");
    ptls_iovec_t v = { ptr, len };
    quicly_send_datagram_frames(c->qconn, &v, 1);
    qconn_flush(c);
    return JS_UNDEFINED;
}

static JSValue js_conn_close(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    QuicConn *c = conn_get(ctx, this_val);
    if (!c || !c->qconn) return JS_UNDEFINED;
    uint32_t    code = 0;
    const char *reason = "";
    if (argc >= 1) JS_ToUint32(ctx, &code, argv[0]);
    if (argc >= 2) reason = JS_ToCString(ctx, argv[1]);
    quicly_close(c->qconn, code, reason);
    if (argc >= 2) JS_FreeCString(ctx, reason);
    qconn_flush(c);
    return JS_UNDEFINED;
}

static JSValue js_conn_get_stats(JSContext *ctx, JSValue this_val,
                                  int argc, JSValue *argv) {
    (void)argc; (void)argv;
    QuicConn *c = conn_get(ctx, this_val);
    if (!c || !c->qconn) return JS_NULL;
    quicly_stats_t st;
    quicly_get_stats(c->qconn, &st);
    JSValue o = JS_NewObject(ctx);
#define SET(k, v) JS_SetPropertyStr(ctx, o, k, v)
    SET("rttMin",        JS_NewFloat64(ctx, st.rtt.minimum  / 1000.0));
    SET("rttLatest",     JS_NewFloat64(ctx, st.rtt.latest   / 1000.0));
    SET("rttSmoothed",   JS_NewFloat64(ctx, st.rtt.smoothed / 1000.0));
    SET("pktSent",       JS_NewFloat64(ctx, (double)st.num_packets.sent));
    SET("pktLost",       JS_NewFloat64(ctx, (double)st.num_packets.lost));
    SET("pktReceived",   JS_NewFloat64(ctx, (double)st.num_packets.received));
    SET("bytesSent",     JS_NewFloat64(ctx, (double)st.num_bytes.sent));
    SET("bytesReceived", JS_NewFloat64(ctx, (double)st.num_bytes.received));
    SET("cwnd",          JS_NewFloat64(ctx, (double)st.cc.cwnd));
#undef SET
    return o;
}

/* Conn callback get/set (magic = QcConnCbIdx) */
static JSValue js_conn_get_cb(JSContext *ctx, JSValue this_val, int magic) {
    QuicConn *c = conn_get(ctx, this_val);
    return c ? JS_DupValue(ctx, c->callbacks[magic]) : JS_UNDEFINED;
}
static JSValue js_conn_set_cb(JSContext *ctx, JSValue this_val,
                               JSValue val, int magic) {
    QuicConn *c = conn_get(ctx, this_val);
    if (!c) return JS_UNDEFINED;
    JS_FreeValue(ctx, c->callbacks[magic]);
    c->callbacks[magic] = JS_DupValue(ctx, val);
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
    JS_CGETSET_MAGIC_DEF("ondatagram",    js_conn_get_cb, js_conn_set_cb, QC_CB_DATAGRAM),
    JS_CGETSET_MAGIC_DEF("onconnected",   js_conn_get_cb, js_conn_set_cb, QC_CB_CONNECTED),
    JS_CGETSET_MAGIC_DEF("onclose",       js_conn_get_cb, js_conn_set_cb, QC_CB_CLOSE),
    JS_CGETSET_MAGIC_DEF("onerror",       js_conn_get_cb, js_conn_set_cb, QC_CB_ERROR),
};

/* ── QuicSocket JS class ──────────────────────────────────────── */

static const char *opt_str(JSContext *ctx, JSValue obj, const char *k) {
    JSValue v = JS_GetPropertyStr(ctx, obj, k);
    if (!JS_IsString(v)) { JS_FreeValue(ctx, v); return NULL; }
    const char *s = JS_ToCString(ctx, v);
    JS_FreeValue(ctx, v);
    return s;
}

static uint32_t opt_u32(JSContext *ctx, JSValue obj, const char *k, uint32_t def) {
    JSValue v = JS_GetPropertyStr(ctx, obj, k);
    if (JS_IsUndefined(v) || JS_IsNull(v)) return def;
    uint32_t n = def;
    JS_ToUint32(ctx, &n, v);
    return n;
}
static void qc_sock_finalizer(JSRuntime *rt, JSValue val) {
    QuicSock *s = JS_GetOpaque(val, qc_sock_class_id);
    if (!s) return;
    for (int i = 0; i < MAX_CONNS; i++) {
        if (!s->conns[i]) continue;
        quicly_free(s->conns[i]->qconn);
        for (int k = 0; k < QC_CB_COUNT; k++)
            JS_FreeValueRT(rt, s->conns[i]->callbacks[k]);
        JS_FreeValueRT(rt, s->conns[i]->self);
        free(s->conns[i]);
        s->conns[i] = NULL;
    }
    for (int i = 0; i < QS_CB_COUNT; i++) JS_FreeValueRT(rt, s->callbacks[i]);
    for (size_t i = 0; i < s->ncerts; i++) OPENSSL_free(s->certs[i].base);
    free(s->alpn_storage);
    free(s);
}

static JSClassDef qc_sock_class = { "Socket", .finalizer = qc_sock_finalizer };

static inline QuicSock *sock_get(JSContext *ctx, JSValue v) {
    return JS_GetOpaque2(ctx, v, qc_sock_class_id);
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

static void apply_transport_params(JSContext *ctx, JSValue opts,
                                    quicly_context_t *qctx) {
    if (!JS_IsObject(opts)) return;
    JSValue t = JS_GetPropertyStr(ctx, opts, "transport");
    if (!JS_IsObject(t)) { JS_FreeValue(ctx, t); return; }

    quicly_transport_parameters_t *tp = &qctx->transport_params;
    JSValue v; uint32_t u;

#define TP(key, field) \
    v = JS_GetPropertyStr(ctx, t, key); \
    if (!JS_IsUndefined(v)) { JS_ToUint32(ctx, &u, v); field = u; } \
    JS_FreeValue(ctx, v);

    TP("maxStreamsBidi", tp->max_streams_bidi)
    TP("maxStreamsUni",  tp->max_streams_uni)
    TP("maxData",        tp->max_data)

    /* maxStreamData applies to all stream directions */
    v = JS_GetPropertyStr(ctx, t, "maxStreamData");
    if (!JS_IsUndefined(v)) {
        JS_ToUint32(ctx, &u, v);
        tp->max_stream_data.bidi_local  = u;
        tp->max_stream_data.bidi_remote = u;
        tp->max_stream_data.uni         = u;
    }
    JS_FreeValue(ctx, v);

    v = JS_GetPropertyStr(ctx, t, "idleTimeoutMs");
    if (!JS_IsUndefined(v)) {
        JS_ToUint32(ctx, &u, v);
        tp->max_idle_timeout = u;
    }
    JS_FreeValue(ctx, v);

    v = JS_GetPropertyStr(ctx, t, "initialRttMs");
    (void)u;
    JS_FreeValue(ctx, v);

    v = JS_GetPropertyStr(ctx, t, "cc");
    if (JS_IsString(v)) {
        const char *cc = JS_ToCString(ctx, v);
        if      (strcmp(cc, "cubic") == 0) qctx->init_cc = &quicly_cc_cubic_init;
        else if (strcmp(cc, "pico")  == 0) qctx->init_cc = &quicly_cc_pico_init;
        else                               qctx->init_cc = &quicly_cc_reno_init;
        JS_FreeCString(ctx, cc);
    }
    JS_FreeValue(ctx, v);
#undef TP

    JS_FreeValue(ctx, t);
}

/* QuicSocket constructor: new QuicSocket({ host, port, cert, key, isServer, alpn? })
 * cert/key are PEM strings (not file paths). */
static JSValue js_sock_ctor(JSContext *ctx, JSValue new_target,
                             int argc, JSValue *argv) {
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "Socket(opts) requires at least one argument");

    uv_loop_t *loop = TJS_GetLoop(TJS_GetRuntime(ctx));
    JSValue opts     = argv[0];
    JSValue obj      = JS_UNDEFINED;
    const char *host = NULL, *cert = NULL, *key = NULL, *alpn_str = NULL;

    QuicSock *s = calloc(1, sizeof(QuicSock));
    if (!s) return JS_ThrowOutOfMemory(ctx);
    s->ctx  = ctx;
    s->loop = loop;
    for (int i = 0; i < QS_CB_COUNT; i++) s->callbacks[i] = JS_NULL;

    /* Parse options */
    host      = opt_str(ctx, opts, "host");
    cert      = opt_str(ctx, opts, "cert");
    key       = opt_str(ctx, opts, "key");
    alpn_str  = opt_str(ctx, opts, "alpn");
    uint32_t port     = opt_u32(ctx, opts, "port", 4433);
    s->is_server      = JS_ToBool(ctx, JS_GetPropertyStr(ctx, opts, "isServer"));

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
    if (cert && load_cert_chain(s, cert) == 0)
        s->tls.certificates.count = s->ncerts;
    if (key) load_private_key(s, key);

    /* quicly context */
    s->qctx = quicly_spec_context;
    s->qctx.tls = &s->tls;
    quicly_amend_ptls_context(s->qctx.tls);
    s->qctx.transport_params.max_datagram_frame_size =
        s->qctx.transport_params.max_udp_payload_size;
    s->qctx.stream_open            = &s->on_stream_open_cb;
    s->qctx.closed                 = &s->on_closed_cb;
    s->qctx.receive_datagram_frame = &s->on_datagram_cb;
    s->on_stream_open_cb.cb        = on_stream_open;
    s->on_closed_cb.cb             = on_closed;
    s->on_datagram_cb.cb           = on_receive_datagram_frame;
    apply_transport_params(ctx, opts, &s->qctx);

    /* UDP */
    uv_udp_init(loop, &s->udp);
    struct sockaddr_in addr;
    uv_ip4_addr(host ? host : "0.0.0.0", (int)port, &addr);
    if (s->is_server)
        uv_udp_bind(&s->udp, (struct sockaddr *)&addr, 0);
    uv_udp_recv_start(&s->udp, on_udp_alloc, on_udp_recv);

    /* Timer */
    uv_timer_init(loop, &s->timer);

    obj = JS_NewObjectClass(ctx, qc_sock_class_id);
    JS_SetOpaque(obj, s);
    goto done;

oom:
    JS_ThrowOutOfMemory(ctx);
done:
    JS_FreeCString(ctx, host);
    JS_FreeCString(ctx, cert);
    JS_FreeCString(ctx, key);
    JS_FreeCString(ctx, alpn_str);
    return obj;
}

/* QuicSocket.connect(sock, host, port) → QuicConnection */
static JSValue js_sock_connect(JSContext *ctx, JSValue this_val,
                                int argc, JSValue *argv) {
    QuicSock *s = sock_get(ctx, this_val);
    if (!s) return JS_UNDEFINED;

    const char *host = JS_ToCString(ctx, argv[0]);
    uint32_t    port = 4433;
    if (argc >= 2) JS_ToUint32(ctx, &port, argv[1]);

    struct sockaddr_in remote;
    uv_ip4_addr(host, (int)port, &remote);

    QuicConn *c = calloc(1, sizeof(QuicConn));
    if (!c || qsock_add_conn(s, c) != 0) {
        JS_FreeCString(ctx, host);
        free(c);
        return JS_ThrowInternalError(ctx, "too many connections");
    }
    c->sock = s;
    c->ctx  = ctx;
    for (int i = 0; i < QC_CB_COUNT; i++) c->callbacks[i] = JS_NULL;

    ptls_handshake_properties_t hs_properties = { 0 };
    if (s->alpn.len != 0) {
        hs_properties.client.negotiated_protocols.list = &s->alpn;
        hs_properties.client.negotiated_protocols.count = 1;
    }

    int rc = quicly_connect(&c->qconn, &s->qctx, host,
                             (struct sockaddr *)&remote, NULL,
                             &s->next_cid, ptls_iovec_init(NULL, 0), &hs_properties, NULL, NULL);
    JS_FreeCString(ctx, host);
    if (rc != 0) {
        qsock_remove_conn(s, c);
        free(c);
        return JS_ThrowInternalError(ctx, "ly_connect: %d", rc);
    }

    c->self = JS_NewObjectClass(ctx, qc_conn_class_id);
    JS_SetOpaque(c->self, c);
    qconn_flush(c);
    return JS_DupValue(ctx, c->self);
}

/* Sock callback get/set */
static JSValue js_sock_get_cb(JSContext *ctx, JSValue this_val, int magic) {
    QuicSock *s = sock_get(ctx, this_val);
    return s ? JS_DupValue(ctx, s->callbacks[magic]) : JS_UNDEFINED;
}
static JSValue js_sock_set_cb(JSContext *ctx, JSValue this_val,
                               JSValue val, int magic) {
    QuicSock *s = sock_get(ctx, this_val);
    if (!s) return JS_UNDEFINED;
    JS_FreeValue(ctx, s->callbacks[magic]);
    s->callbacks[magic] = JS_DupValue(ctx, val);
    return JS_UNDEFINED;
}

static const JSCFunctionListEntry qc_sock_proto[] = {
    JS_CFUNC_DEF        ("connect",   2, js_sock_connect),
    JS_CGETSET_MAGIC_DEF("onconnection", js_sock_get_cb, js_sock_set_cb, QS_CB_CONNECTION),
    JS_CGETSET_MAGIC_DEF("onerror",      js_sock_get_cb, js_sock_set_cb, QS_CB_ERROR),
};

/* ── Constants ────────────────────────────────────────────────── */
static JSValue make_constants(JSContext *ctx) {
    JSValue o = JS_NewObject(ctx);
    // strip 
#define C(x) JS_SetPropertyStr(ctx, o, #x + 7, JS_NewFloat64(ctx, (double)(x)))
    C(QUICLY_ERROR_PACKET_IGNORED);
    C(QUICLY_ERROR_FREE_CONNECTION);
    C(QUICLY_TRANSPORT_ERROR_NONE);
    C(QUICLY_TRANSPORT_ERROR_INTERNAL);
    C(QUICLY_TRANSPORT_ERROR_FLOW_CONTROL);
    C(QUICLY_TRANSPORT_ERROR_STREAM_LIMIT);
    C(QUICLY_TRANSPORT_ERROR_STREAM_STATE);
    C(QUICLY_TRANSPORT_ERROR_FINAL_SIZE);
    C(QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION);
    C(QUICLY_TRANSPORT_ERROR_APPLICATION);
#undef C
    return o;
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
