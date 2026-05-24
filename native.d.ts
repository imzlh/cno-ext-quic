/**
 * QUIC extension for cno/circu.js
 * QUIC transport via quicly + picotls (OpenSSL crypto backend).
 * UDP socket and timer management are handled at C level (libuv).
 */
declare namespace CModuleExternalQuic {

    type Callback<T extends unknown[]> =
        | ((...args: T) => void)
        | [(...args: T) => void, unknown];

    /* ── Transport parameters ────────────────────────────────────── */
    interface TransportParams {
        /** Max concurrent bidi streams peer can open. Default 100. */
        maxStreamsBidi?: number;
        /** Max concurrent uni streams peer can open. Default 100. */
        maxStreamsUni?: number;
        /** Per-stream receive window (bytes). Default 256KB. */
        maxStreamData?: number;
        /** Connection-level receive window (bytes). Default 1MB. */
        maxData?: number;
        /** Idle timeout in ms. Default 30000. */
        idleTimeoutMs?: number;
        /** Initial RTT estimate in ms. Default 333. */
        initialRttMs?: number;
        /** Congestion control algorithm. Default "reno". */
        cc?: "reno" | "cubic" | "pico";
    }

    /* ── QuicSocket options ──────────────────────────────────────── */
    interface SocketOptions {
        /** Bind/connect host. Default "0.0.0.0" for server. */
        host?: string;
        /** UDP port. Default 4433. */
        port?: number;
        /** Path to PEM certificate file. */
        cert?: string;
        /** Path to PEM private key file. */
        key?: string;
        /** Whether to act as server (bind + accept). Default false. */
        isServer?: boolean;
        /** ALPN protocol string. */
        alpn?: string;
        /** QUIC transport parameters. */
        transport?: TransportParams;
    }

    /* ── Stats ───────────────────────────────────────────────────── */
    interface Stats {
        rttMin: number; /* ms */
        rttLatest: number; /* ms */
        rttSmoothed: number; /* ms */
        pktSent: number;
        pktLost: number;
        pktReceived: number;
        bytesSent: number;
        bytesReceived: number;
        cwnd: number; /* bytes */
    }

    /* ── QuicConnection ──────────────────────────────────────────── */
    class Connection {
        /** Not directly constructable — obtained from QuicSocket */
        private constructor();

        /**
         * Open a new stream.
         * @param bidirectional default true
         * @param priority      urgency 0(highest)–7(lowest), incremental for fairness
         * @returns stream id
         */
        openStream(bidirectional?: boolean, priority?: {
            urgency?: number;  /* 0–7, default 3 */
            incremental?: boolean; /* default false  */
        }): number;

        /**
         * Write data to a stream.
         * @param fin  if true, send FIN after this data
         */
        sendStream(streamId: number, data: Uint8Array | ArrayBuffer, fin?: boolean): void;

        /** Send RESET_STREAM (abort send side). */
        resetStream(streamId: number, errorCode?: number): void;

        /** Send STOP_SENDING (request peer abort their send side). */
        stopSending(streamId: number, errorCode?: number): void;

        /** Send a QUIC unreliable datagram. */
        sendDatagram(data: Uint8Array | ArrayBuffer): void;

        /** Initiate graceful close (CONNECTION_CLOSE frame). */
        close(errorCode?: number, reason?: string): void;

        /** Return current connection statistics. */
        getStats(): Stats;

        /* ── Callbacks ───────────────────────────────────────────── */

        /** New stream opened by peer. args: (streamId, bidirectional) */
        onstream: Callback<[streamId: number, bidirectional: boolean]> | null;

        /** Data received on a stream. args: (streamId, chunk, fin) */
        ondata: Callback<[streamId: number, chunk: Uint8Array, fin: boolean]> | null;

        /** Peer reset a stream (RESET_STREAM). args: (streamId, errorCode) */
        onstreamreset: Callback<[streamId: number, errorCode: number]> | null;

        /** Unreliable datagram received. args: (chunk) */
        ondatagram: Callback<[chunk: Uint8Array]> | null;

        /** Handshake completed and connection is ready. args: () */
        onconnected: Callback<[]> | null;

        /** Connection closed by peer. args: (errorCode, reason) */
        onclose: Callback<[errorCode: number, reason: string]> | null;

        /** Internal error. args: (msg) */
        onerror: Callback<[msg: string]> | null;
    }

    /* ── QuicSocket ──────────────────────────────────────────────── */
    class Socket {
        /**
         * Create a QUIC endpoint.
         * Binds the UDP socket immediately if isServer is true.
         * The libuv loop is obtained automatically from the runtime.
         *
         * @example
         * import { Socket } from "npm:@cnojs/quic"
         * 
         * // Server
         * const sock = new Socket({ isServer: true, port: 4433, cert, key });
         * sock.onconnection = conn => { conn.ondata = (id, chunk, fin) => { ... }; };
         *
         * // Client
         * const sock = new Socket({ cert, key });
         * const conn = sock.connect("example.com", 4433);
         * conn.onconnected = () => { const id = conn.openStream(); ... };
         */
        constructor(opts: SocketOptions);

        /**
         * Initiate a client connection to a remote host.
         * Returns the QuicConnection immediately (handshake runs async).
         * Listen to onconnected before sending data.
         */
        connect(host: string, port?: number): Connection;

        /** New inbound connection (server mode). args: (conn) */
        onconnection: Callback<[conn: Connection]> | null;

        /** Socket-level error. args: (msg) */
        onerror: Callback<[msg: string]> | null;
    }

    /* ── Constants ───────────────────────────────────────────────── */
    const constants: {
        readonly ERROR_PACKET_IGNORED: number;
        readonly ERROR_FREE_CONNECTION: number;
        readonly TRANSPORT_ERROR_NO_ERROR: number;
        readonly TRANSPORT_ERROR_INTERNAL_ERROR: number;
        readonly TRANSPORT_ERROR_FLOW_CONTROL_ERROR: number;
        readonly TRANSPORT_ERROR_STREAM_LIMIT_ERROR: number;
        readonly TRANSPORT_ERROR_STREAM_STATE_ERROR: number;
        readonly TRANSPORT_ERROR_FINAL_SIZE_ERROR: number;
        readonly TRANSPORT_ERROR_PROTOCOL_VIOLATION: number;
        readonly TRANSPORT_ERROR_APPLICATION_ERROR: number;
    };

    export { Socket, Connection, constants };
    export type { SocketOptions, Stats, Callback };
}