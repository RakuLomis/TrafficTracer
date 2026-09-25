# VLESS Implementation in Mihomo

## Scope and source baseline

This document describes the VLESS client outbound used by the TrafficTracer-aware Mihomo core at commit `fcacc8696dfd574d0faa2770c5d3151e21dd9bbc`. It covers the base VLESS request/response format, Mihomo's UDP modes, the available stream transports, REALITY, XTLS Vision, and the resulting TrafficTracer evidence.

VLESS is a routing and authentication protocol, not an encryption algorithm. Confidentiality is provided only when the configured outer transport supplies it, for example TLS, REALITY, or a secure WebSocket/gRPC channel. Raw VLESS over plain TCP does not protect its protocol header or inner payload bytes; nested HTTPS may still independently protect the application's content.

## Layering model

The common stack is:

```text
application TCP bytes or logical UDP packets
  -> VLESS destination request and payload framing
  -> raw TCP, WebSocket, HTTP, HTTP/2, or gRPC transport
  -> optional TLS or REALITY security
  -> physical TCP connection to the VLESS server
```

The exact order is implemented through nested `net.Conn` wrappers. From the physical network inward, TLS/REALITY and the selected HTTP-family transport carry the VLESS byte stream. A visible SNI, HTTP Host, WebSocket path, or gRPC service name belongs to those outer layers, not to the browser's destination and not to the base VLESS header.

## Configuration accepted by the outbound

`VlessOption` exposes these protocol-relevant fields:

| Field | Purpose |
| --- | --- |
| `server`, `port` | Physical proxy endpoint. |
| `uuid` | 16-byte VLESS user identity after UUID parsing/mapping. |
| `flow` | Optional XTLS flow; this implementation accepts `xtls-rprx-vision` under the stated constraints. |
| `network` | Raw TCP by default, or `ws`, `http`, `h2`, or `grpc`. |
| `tls`, `servername`, `alpn` | Enables and configures transport TLS. |
| `reality-opts` | REALITY X25519 public key and short ID. |
| `client-fingerprint`, `fingerprint` | ClientHello emulation and certificate fingerprint configuration. |
| transport option blocks | WebSocket, HTTP, H2, and gRPC host/path/header/service settings. |
| `udp`, `xudp`, `packet-addr`, `packet-encoding` | Selects logical UDP support and framing. |
| common dial fields | Interface, routing mark, IP preference, TFO/MPTCP, and optional dialer proxy. |

### Constructor normalization

`NewVless` performs several important normalizations:

- For non-WebSocket transports, a `flow` of at least 16 characters is truncated to 16 characters and must equal `xtls-rprx-vision`; any other value is rejected.
- A shorter non-empty flow value is not installed as an addon, and the constructor does not install Vision for the WebSocket network. This is current implementation behavior, not a recommendation to rely on silently ignored values.
- `packet-encoding: packetaddr` or `packet` enables PacketAddr and disables XUDP.
- Otherwise XUDP becomes the default unless PacketAddr was explicitly enabled.
- If XUDP is enabled, it wins and PacketAddr is disabled.
- An H2 transport with no host configured receives `www.example.com` as its default host list.
- A gRPC transport creates a reusable HTTP/2 client transport at adapter construction time.

The UUID and REALITY parameters are also validated during construction. This makes malformed identity and key material configuration errors rather than late capture-time errors.

## Base VLESS request and response

The VLESS client is implemented in `transport/vless`. The request is lazily written on the first application write so the header and early payload can be coalesced.

### Request layout

```text
+----------------------+------------------------------------------+
| Field                | Encoding                                 |
+----------------------+------------------------------------------+
| Version              | 1 byte; current implementation writes 0  |
| User identity        | 16 UUID bytes                            |
| Addons length        | 1 byte                                   |
| Addons               | protobuf bytes, possibly empty           |
| Command              | 1 byte: TCP=1, UDP=2, Mux=3             |
| Destination port     | uint16, big endian; absent for Mux       |
| Address type         | 1 byte; absent for Mux                   |
| Destination address  | IPv4, IPv6, or length-prefixed domain    |
| Early payload        | remaining bytes in the first write       |
+----------------------+------------------------------------------+
```

Address types are `1` for IPv4, `2` for a domain, and `3` for IPv6. A domain is represented by a one-byte length followed by its bytes. When XUDP is selected, the VLESS command is Mux and XUDP performs the logical destination framing inside that channel.

### Response layout

Before returning application bytes, the client reads:

```text
version byte || addon-length byte || addon bytes
```

The version must match the implemented VLESS version. Addon bytes are currently discarded by the client. Once this prefix is consumed, subsequent reads are application payload.

### Security consequence

The UUID is an authentication/routing identity, not a session cipher key in this implementation. Without a secure outer layer, the UUID, destination, and payload are not protected by VLESS itself. Production and measurement configurations must record whether TLS or REALITY was actually enabled.

## TCP dial and transport selection

For non-reused gRPC calls, `DialContextWithDialer` follows this path:

1. Build the outbound dialer and optionally wrap it with `dialer-proxy`.
2. Open a physical TCP connection to the configured VLESS server.
3. Apply the selected transport wrapper.
4. Create the VLESS stream with the browser's logical destination.
5. Emit the VLESS request on the first write and relay data.

The transport switch behaves as follows.

### Raw TCP

The default path optionally applies TLS/REALITY and then places VLESS directly on that stream. With `tls: false`, no transport encryption is added by this path.

### WebSocket

The VMess WebSocket helper is reused. It supports a path, headers, early-data settings, HTTP Upgrade behavior, and optional TLS. With TLS, SNI defaults to the server host, is overridden by `servername`, and otherwise can follow the configured HTTP `Host` header. Without TLS and without an explicit Host header, Mihomo creates a randomized host and user agent.

### HTTP camouflage

The `http` network first applies the ordinary TLS/REALITY logic when enabled and then wraps the connection in the VMess HTTP transport using the configured method, path, headers, and host.

### HTTP/2

The `h2` network applies TLS with ALPN forced to `h2`, then creates the H2 stream using the configured host list and path.

### gRPC

The gRPC path uses Mihomo's `gun` transport over HTTP/2. Its service name and host are independently configurable. A reusable HTTP/2 client transport is retained by the adapter, so multiple logical VLESS connections can be streams on shared underlying transport state. This is materially different from assuming a new physical TCP handshake for every URL connection.

## TLS and visible names

For standard TLS, the server name defaults to the proxy server host and can be overridden by `servername`. The selected client fingerprint, certificate policy, ALPN, and optional CA behavior are applied by Mihomo's TLS helpers.

Therefore, an outer ClientHello can legitimately contain a name such as a cover or front domain while the inner VLESS destination refers to YouTube, Bilibili, or another origin. The layers should be interpreted as:

```text
browser URL/origin
  != VLESS proxy server endpoint
  != optional TLS/REALITY SNI or HTTP Host
```

Equality is possible but is not required. TrafficTracer should retain all three values with their provenance instead of replacing one with another.

## REALITY implementation

REALITY is enabled when `reality-opts.public-key` is present. The parser requires:

- a raw URL-safe base64 X25519 public key that decodes to exactly 32 bytes;
- a hexadecimal short ID no longer than 8 bytes.

Parsing REALITY options does not itself enable `tls`. On the raw TCP, HTTP, and H2 paths, `tls: true` is required for `streamTLSConn` to consume the REALITY configuration. The WebSocket branch constructs its own TLS configuration and does not pass the parsed REALITY configuration to that helper.

The connection path in `component/tls/reality.go` is:

1. Select the configured uTLS client fingerprint and build its ClientHello.
2. Put a protocol version marker, current NTP-adjusted Unix time, and short ID into the first 16 bytes of the ClientHello session ID workspace.
3. Perform X25519 ECDH with the configured REALITY public key.
4. Derive an authentication key with HKDF-SHA256 using the label `REALITY` and ClientHello random material.
5. Encrypt/authenticate the 16-byte session data into the session ID using AES-GCM or ChaCha20-Poly1305 according to the ClientHello cipher preference.
6. Complete the uTLS handshake.
7. Validate the server's Ed25519 certificate signature with an HMAC-SHA512 construction based on the derived authentication key.

Certificate verification is initially delegated to the custom REALITY verifier. A conventional certificate chain for the configured server name can also pass the verifier's fallback branch, but `verified` is set only by the REALITY-specific signature check. If that authentication flag is not set, Mihomo starts a best-effort HTTP/2 GET to `https://<servername>` over the same connection, waits a randomized 5–14 seconds, closes it, and returns `REALITY authentication failed` to the proxy caller.

The configured `servername` remains the outer TLS name. It is commonly a cover name and must not be treated as the inner requested website.

## XTLS Vision flow

`xtls-rprx-vision` is carried as a protobuf addon in the VLESS request. Mihomo's Vision wrapper requires the upstream connection to expose a Go TLS, uTLS, or Mihomo uTLS connection and rejects an unsuitable security stack. On the first write it also requires TLS 1.3.

Vision examines a bounded number of early TLS records, applies its UUID/command/content-length/padding-length framing, and can transition between padded processing and a direct path when the nested traffic is suitable. “Direct” here does not mean plaintext on the physical network. It changes how already encrypted nested TLS application data is relayed through the established outer connection to reduce redundant processing and copying.

For analysis, Vision can change early packet sizes, padding, and relay behavior. It should be captured as a separate flow variant rather than merged with ordinary VLESS/TLS solely because both use the VLESS leaf type.

## UDP implementation

Mihomo carries VLESS logical UDP over a stream transport. The physical connection to the VLESS server is therefore normally TCP, even when the browser-side flow is UDP.

Before opening the stream, unresolved UDP destinations are resolved locally so that a concrete address can be supplied to the packet wrapper.

### XUDP

XUDP is the default when neither PacketAddr nor a packet encoding override is selected. The VLESS header uses command Mux, then `sing-vmess` supplies XUDP framing. Mihomo derives an eight-byte global ID from the logical source address when one is available and passes the destination UDP address to the XUDP connection.

### PacketAddr

PacketAddr replaces the VLESS request destination with its protocol magic address and binds destination information in the packet stream. `packet-encoding: packetaddr` and `packet-encoding: packet` select this mode.

### Simple length-prefixed UDP

When neither XUDP nor PacketAddr is active, each packet is written as:

```text
uint16 big-endian payload length || payload
```

Mihomo chunks a write larger than 8192 bytes into multiple length-prefixed units. On reads it preserves any unread remainder when the caller's buffer is smaller than the framed unit.

All three modes preserve a distinction between logical UDP and the physical stream carrier.

## State model

```text
UNINITIALIZED
  -> validate UUID, flow, REALITY key, transport, and UDP mode
READY
  -> create or obtain physical/reusable transport
TRANSPORT_CONNECTING
  -> optional TLS or REALITY handshake
  -> optional WS / HTTP / H2 / gRPC setup
VLESS_READY
  -> first write emits VLESS request plus optional early data
FORWARDING
  -> TCP bytes or framed logical UDP
CLOSED / FAILED
```

Failures can occur independently at physical dial, certificate/TLS, REALITY authentication, HTTP-family transport, VLESS response parsing, XTLS Vision validation, or destination resolution. The terminal reason should preserve the failed layer when possible.

## TrafficTracer observability

For the common one-connection raw TCP, WS, HTTP, or H2 path:

1. The TUN path is captured as the original logical five-tuple.
2. The physical dialer reports the local TCP endpoint and VLESS server endpoint.
3. The selected policy and final leaf type `Vless` are written into proxy-dial events.
4. Chrome CDP/NetLog supplies URL and browser transport context.

The resulting evidence model is:

```text
URL/request
  -> browser connection and pre-proxy tuple
  -> Mihomo logical flow
  -> VLESS leaf and destination metadata
  -> outer TCP tuple to the proxy server
  -> optional visible transport SNI/Host
```

These are related values, not interchangeable identifiers.

The reusable gRPC transport and any lower-layer multiplexing require additional caution. A single outer connection can serve several logical flows, and the physical socket may have been created before a later logical trace context exists. Unlike Hysteria2, this VLESS adapter has no dedicated protocol-specific carrier registry that emits explicit generation, reuse, and path-update events. The analyzer must not invent one-to-one post-flow mappings when the evidence indicates a shared or previously established transport.

## Measurement implications

- Record `network`, TLS state, REALITY state, `servername`, ALPN, flow, UDP encoding, and the final leaf proxy alongside the protocol label.
- Treat cover SNI/Host as an outer-transport feature, not as the browser destination.
- Do not describe raw VLESS as encrypted merely because the page itself used HTTPS; those are separate layers.
- Treat XUDP/PacketAddr/simple UDP as logical UDP over a stream carrier.
- Separate Vision from ordinary VLESS in experiments sensitive to burst, padding, and packet-size distributions.
- Allow shared-carrier relations for gRPC or other multiplexed transports.
- Preserve authentication and fallback failures as terminal evidence; do not convert them into successful page flows based only on the presence of packets to the cover host.

## Implementation source map

| Concern | Source |
| --- | --- |
| Outbound options, transport selection, UDP modes | `adapter/outbound/vless.go` |
| Base request/response framing | `transport/vless/conn.go`, `transport/vless/vless.go` |
| Addon protobuf | `transport/vless/config.proto` |
| XTLS Vision | `transport/vless/vision/` |
| REALITY option parsing | `adapter/outbound/reality.go` |
| REALITY handshake and verification | `component/tls/reality.go` |
| WebSocket/HTTP/H2 helpers | `transport/vmess/` |
| gRPC transport | `transport/gun/` |
| Logical and physical trace hooks | `tunnel/tunnel.go`, `component/dialer/dialer.go`, `component/tracer/tracer.go` |
