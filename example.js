/**
 * circu:quicly examples
 *
 * 1. Echo server + client
 * 2. Simple RPC over QUIC (custom protocol)
 */

import { QuicSocket, constants } from "circu:quicly";

/* ── Helpers ────────────────────────────────────────────────────── */

const enc = new TextEncoder();
const dec = new TextDecoder();

function concat(...bufs) {
    const total = bufs.reduce((n, b) => n + b.byteLength, 0);
    const out   = new Uint8Array(total);
    let   off   = 0;
    for (const b of bufs) { out.set(new Uint8Array(b), off); off += b.byteLength; }
    return out;
}

/* ══════════════════════════════════════════════════════════════════
 * Example 1 — Echo server
 * ══════════════════════════════════════════════════════════════════ */

export function startEchoServer({ cert, key, port = 4433 } = {}) {
    const sock = new QuicSocket({
        isServer: true,
        host:     "0.0.0.0",
        port,
        cert,
        key,
        transport: {
            maxStreamsBidi: 128,
            maxStreamData:  256 * 1024,
            maxData:        4 * 1024 * 1024,
            idleTimeoutMs:  30_000,
            cc:             "cubic",
        },
    });

    sock.onconnection = conn => {
        console.log("[server] new connection");
        const recvBufs = new Map(); // streamId → Uint8Array[]

        conn.onstream = (streamId, bidi) => {
            console.log(`[server] stream ${streamId} opened bidi=${bidi}`);
            recvBufs.set(streamId, []);
        };

        conn.ondata = (streamId, chunk, fin) => {
            recvBufs.get(streamId)?.push(chunk);
            if (!fin) return;

            const body = concat(...recvBufs.get(streamId));
            recvBufs.delete(streamId);
            console.log(`[server] echo ${body.byteLength}b on stream ${streamId}`);

            // echo back
            conn.sendStream(streamId, body, /* fin */ true);
        };

        conn.onstreamreset = (streamId, code) => {
            recvBufs.delete(streamId);
            console.warn(`[server] stream ${streamId} reset code=${code}`);
        };

        conn.onclose = (code, reason) => {
            console.log(`[server] connection closed code=${code} reason="${reason}"`);
        };
    };

    sock.onerror = msg => console.error("[server] error:", msg);
    console.log(`[server] listening on :${port}`);
    return sock;
}

/* ══════════════════════════════════════════════════════════════════
 * Example 2 — Echo client
 * ══════════════════════════════════════════════════════════════════ */

export async function echoClient({ host = "127.0.0.1", port = 4433, messages }) {
    const sock = new QuicSocket({ transport: { cc: "cubic" } });
    const conn = sock.connect(host, port);

    // wait for handshake
    await new Promise(resolve => conn.onconnected = resolve);
    console.log("[client] connected");

    const results = [];

    for (const msg of messages) {
        const result = await sendEcho(conn, enc.encode(msg));
        results.push(dec.decode(result));
        console.log(`[client] echo: "${msg}" → "${results.at(-1)}"`);
    }

    conn.close(constants.QUICLY_TRANSPORT_ERROR_NO_ERROR, "done");
    return results;
}

function sendEcho(conn, data) {
    return new Promise((resolve, reject) => {
        // lower urgency for bulk echo, incremental for fairness across streams
        const streamId = conn.openStream(true, { urgency: 5, incremental: true });
        const chunks   = [];

        const prevOnData       = conn.ondata;
        const prevOnStreamReset = conn.onstreamreset;

        conn.ondata = (id, chunk, fin) => {
            if (id !== streamId) return prevOnData?.(id, chunk, fin);
            chunks.push(chunk);
            if (fin) resolve(concat(...chunks));
        };

        conn.onstreamreset = (id, code) => {
            if (id !== streamId) return prevOnStreamReset?.(id, code);
            reject(new Error(`stream reset: ${code}`));
        };

        conn.sendStream(streamId, data, /* fin */ true);
    });
}

/* ══════════════════════════════════════════════════════════════════
 * Example 3 — Simple length-prefixed RPC protocol
 *
 * Frame format (binary):
 *   [4 bytes: request id][4 bytes: payload length][payload]
 *
 * Each RPC call opens a new bidi stream.
 * Server reads request, calls handler, sends response on same stream.
 * ══════════════════════════════════════════════════════════════════ */

const RPC_HDR = 8; // bytes

function encodeRpcFrame(id, payload) {
    const buf = new ArrayBuffer(RPC_HDR + payload.byteLength);
    const dv  = new DataView(buf);
    dv.setUint32(0, id,             false);
    dv.setUint32(4, payload.byteLength, false);
    new Uint8Array(buf, RPC_HDR).set(new Uint8Array(payload));
    return new Uint8Array(buf);
}

function decodeRpcFrame(buf) {
    if (buf.byteLength < RPC_HDR) return null;
    const dv      = new DataView(buf.buffer, buf.byteOffset);
    const id      = dv.getUint32(0, false);
    const paylen  = dv.getUint32(4, false);
    if (buf.byteLength < RPC_HDR + paylen) return null;
    return { id, payload: buf.slice(RPC_HDR, RPC_HDR + paylen) };
}

/* RPC server */
export function startRpcServer({ cert, key, port = 4434, handlers = {} }) {
    const sock = new QuicSocket({
        isServer: true, port, cert, key,
        transport: {
            maxStreamsBidi: 256,
            idleTimeoutMs:  60_000,
            cc:             "reno",
        },
    });

    sock.onconnection = conn => {
        const recvBufs = new Map();

        conn.onstream = (streamId) => recvBufs.set(streamId, []);

        conn.ondata = async (streamId, chunk, fin) => {
            recvBufs.get(streamId)?.push(chunk);
            if (!fin) return;

            const raw   = concat(...recvBufs.get(streamId));
            recvBufs.delete(streamId);
            const frame = decodeRpcFrame(raw);
            if (!frame) {
                conn.resetStream(streamId, constants.QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION);
                return;
            }

            const method  = dec.decode(frame.payload.slice(0, frame.payload.indexOf(0)));
            const argsBuf = frame.payload.slice(method.length + 1);
            const handler = handlers[method];

            let respPayload;
            if (handler) {
                try {
                    const result = await handler(JSON.parse(dec.decode(argsBuf)));
                    respPayload  = enc.encode(JSON.stringify({ ok: true, result }));
                } catch (e) {
                    respPayload  = enc.encode(JSON.stringify({ ok: false, error: e.message }));
                }
            } else {
                respPayload = enc.encode(JSON.stringify({ ok: false, error: "unknown method" }));
            }

            conn.sendStream(streamId,
                encodeRpcFrame(frame.id, respPayload), /* fin */ true);
        };
    };

    return sock;
}

/* RPC client */
export function createRpcClient({ host = "127.0.0.1", port = 4434 }) {
    const sock    = new QuicSocket({ transport: { cc: "reno" } });
    const conn    = sock.connect(host, port);
    const pending = new Map(); // streamId → { resolve, reject }
    let   ready   = false;

    conn.onconnected = () => { ready = true; };

    conn.ondata = (streamId, chunk, fin) => {
        if (!fin) return; // wait for full response
        const frame = decodeRpcFrame(chunk);
        const p     = pending.get(streamId);
        if (!p || !frame) return;
        pending.delete(streamId);
        const resp = JSON.parse(dec.decode(frame.payload));
        resp.ok ? p.resolve(resp.result) : p.reject(new Error(resp.error));
    };

    conn.onstreamreset = (streamId, code) => {
        pending.get(streamId)?.reject(new Error(`stream reset: ${code}`));
        pending.delete(streamId);
    };

    async function call(method, args) {
        if (!ready) await new Promise(r => conn.onconnected = r);

        // high priority for RPC calls
        const streamId = conn.openStream(true, { urgency: 1, incremental: false });

        return new Promise((resolve, reject) => {
            pending.set(streamId, { resolve, reject });

            const methodBuf = enc.encode(method + "\0");
            const argsBuf   = enc.encode(JSON.stringify(args));
            const payload   = concat(methodBuf, argsBuf);
            const reqId     = streamId; // reuse stream id as request id

            conn.sendStream(streamId,
                encodeRpcFrame(reqId, payload), /* fin */ true);
        });
    }

    function close() {
        conn.close(constants.QUICLY_TRANSPORT_ERROR_NO_ERROR, "bye");
    }

    return { call, close, conn };
}

/* ══════════════════════════════════════════════════════════════════
 * Usage
 * ══════════════════════════════════════════════════════════════════ */

// --- Echo ---
// const server = startEchoServer({ cert: "cert.pem", key: "key.pem" });
// const results = await echoClient({ messages: ["hello", "world"] });

// --- RPC ---
// const server = startRpcServer({
//     cert: "cert.pem", key: "key.pem", port: 4434,
//     handlers: {
//         add:  ({ a, b }) => a + b,
//         echo: ({ msg }) => msg,
//     },
// });
//
// const client = createRpcClient({ port: 4434 });
// const sum    = await client.call("add",  { a: 1, b: 2 });   // 3
// const echoed = await client.call("echo", { msg: "hi" });    // "hi"
// client.close();