# ext-quic

`ext-quic/` is the optional QUIC native extension for circu.js/cno. It is used
by WebTransport-related runtime code and can be statically embedded in the root
`cno` build.

The module name used by the root build is:

```text
@cnojs/quic
```

## Directory Layout

| Path | Role |
| --- | --- |
| `native.c` | circu.js native module implementation |
| `native.h` | Native declarations |
| `index.d.ts` | Public TypeScript declarations |
| `native.d.ts` | Native binding TypeScript declarations |
| `index.js` | JS entry/helper |
| `example.js` | Small usage example |
| `CMakeLists.txt` | Extension build glue |
| `deps/quicly/` | QUIC implementation submodule |

## Build Integration

From the repository root, statically embed the extension with:

```sh
cmake -B build -DCNO_EMBED_EXT_QUIC=ON
cmake --build build
```

The root `CMakeLists.txt` expects the `deps/quicly` submodule to be present and
links against OpenSSL.

## Runtime Use

The higher-level WebTransport and Deno QUIC integration lives in:

```text
cno/src/webapi/webtransport.ts
cno/src/deno/10_quic.ts
```

Keep compatibility behavior in those TypeScript layers. This extension should
remain the native QUIC binding surface.
