#ifndef QUICLY_CIRCU_H
#define QUICLY_CIRCU_H

#include <quicly.h>
#include <quicly/defaults.h>
#include <picotls.h>
#include <picotls/openssl.h>
#define FOREIGN_QJS
#include <quickjs.h>
#include <quickjs-libc.h>
#include <tjs.h>   /* DEF_MODULE, TJSModuleInfo, TJS_EXPORT */
#include <uv.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/* ── QuicConnection callback indices ──────────────────────────── */
typedef enum {
    QC_CB_STREAM       = 0, /* (streamId: number, bidi: boolean)              */
    QC_CB_DATA         = 1, /* (streamId: number, Uint8Array, fin: boolean)   */
    QC_CB_STREAM_RESET = 2, /* (streamId: number, errorCode: number)          */
    QC_CB_DATAGRAM     = 3, /* (Uint8Array)                                   */
    QC_CB_CONNECTED    = 4, /* ()                                             */
    QC_CB_CLOSE        = 5, /* (errorCode: number, reason: string)            */
    QC_CB_ERROR        = 6, /* (msg: string)                                  */
    QC_CB_COUNT
} QcConnCbIdx;

/* ── QuicSocket callback indices ──────────────────────────────── */
typedef enum {
    QS_CB_CONNECTION = 0, /* (conn: QuicConnection) new inbound connection   */
    QS_CB_ERROR      = 1, /* (msg: string)                                   */
    QS_CB_COUNT
} QcSockCbIdx;

/* ── tjs-style callback invoke ────────────────────────────────── */
static inline JSValue qc_call_cb(JSContext *ctx, JSValue cb,
                                  int argc, JSValue *argv) {
    if (JS_IsFunction(ctx, cb))
        return JS_Call(ctx, cb, JS_UNDEFINED, argc, argv);
    if (!JS_IsArray(ctx, cb)) return JS_UNDEFINED;
    JSValue fn   = JS_GetPropertyUint32(ctx, cb, 0);
    JSValue self = JS_GetPropertyUint32(ctx, cb, 1);
    JSValue ret  = JS_Call(ctx, fn, self, argc, argv);
    JS_FreeValue(ctx, fn);
    JS_FreeValue(ctx, self);
    return ret;
}

#define QC_CALL(ctx, cbs, idx, argc, argv) \
    do { \
        JSValue _r = qc_call_cb(ctx, (cbs)[idx], argc, argv); \
        if (JS_IsException(_r)) TJS_DumpException(ctx); \
        JS_FreeValue(ctx, _r); \
    } while(0)

#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - offsetof(type, member)))

#define STREAM_IS_BIDI(id)  (((id) & 2) == 0)
#define MAX_CONNS           64
#define DGRAM_BATCH         16
#define MAX_PKT_SIZE        1452  /* typical QUIC MTU */

extern JSClassID qc_conn_class_id;
extern JSClassID qc_sock_class_id;

/* ── Structs (exposed for H3 and other extension layers) ─────── */
typedef struct QuicSock QuicSock;
typedef struct QuicConn QuicConn;

struct QuicConn {
    quicly_conn_t *qconn;
    QuicSock      *sock;
    JSContext     *ctx;
    JSValue        self;
    JSValue        callbacks[QC_CB_COUNT];
};

struct QuicSock {
    uv_udp_t                        udp;
    uv_timer_t                      timer;
    uv_loop_t                      *loop;
    JSContext                      *ctx;
    quicly_context_t                qctx;
    ptls_context_t                  tls;
    ptls_openssl_sign_certificate_t sign_cert;
    ptls_iovec_t                    certs[8];
    size_t                          ncerts;
    quicly_stream_open_t            on_stream_open_cb;
    quicly_closed_by_remote_t       on_closed_remote_cb;
    quicly_receive_datagram_frame_t on_datagram_cb;
    QuicConn                       *conns[MAX_CONNS];
    int                             is_server;
    quicly_cid_plaintext_t          next_cid;
    JSValue                         callbacks[QS_CB_COUNT];
};

/* Get raw quicly_conn_t from a JS QuicConnection object.
 * Returns NULL if val is not a valid QuicConnection.
 * H3 layer uses this to hook into the QUIC connection. */
static inline quicly_conn_t *qc_get_native(JSContext *ctx, JSValue val) {
    QuicConn *c = JS_GetOpaque(val, qc_conn_class_id);
    return c ? c->qconn : NULL;
}

/* Get QuicConn from a JS QuicConnection object. */
static inline QuicConn *qc_conn_from_js(JSContext *ctx, JSValue val) {
    return JS_GetOpaque(val, qc_conn_class_id);
}

void qc_ns_init(JSContext *ctx, JSValue ns);

#endif /* QUICLY_CIRCU_H */