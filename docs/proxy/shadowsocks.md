# Shadowsocks Implementation in Mihomo

## Scope and source baseline

This document describes the Shadowsocks outbound used by the TrafficTracer-aware Mihomo core at commit `fcacc8696dfd574d0faa2770c5d3151e21dd9bbc`. It explains the implemented client path rather than every variant in the broader Shadowsocks ecosystem.

The active outbound is implemented in `adapter/outbound/shadowsocks.go` and delegates cryptographic framing to `github.com/metacubex/sing-shadowsocks2` v0.2.2, as pinned by `go.mod`. The older code under `transport/shadowsocks/` is not the main outbound path described here.

## Architectural position

For a normal TCP request, the effective stack is:

```text
application bytes
  -> encrypted Shadowsocks destination request and records
  -> optional plugin transport or camouflage
  -> TCP socket to the configured Shadowsocks server
```

For native UDP it is:

```text
application UDP datagram
  -> Shadowsocks address plus encrypted payload
  -> UDP socket to the configured Shadowsocks server
```

For UDP-over-TCP (UoT), the application datagrams are packet-framed inside a Shadowsocks TCP stream instead of being sent through a physical UDP socket.

This ordering matters. A TLS or WebSocket signature seen on the physical interface can be produced by a configured plugin; it is not an intrinsic property of Shadowsocks.

## Configuration accepted by the outbound

`ShadowSocksOption` accepts the following protocol-relevant fields:

| Field | Purpose |
| --- | --- |
| `server`, `port` | Physical proxy endpoint. |
| `password`, `cipher` | Inputs used to construct the selected Shadowsocks method. |
| `udp` | Advertises UDP support to Mihomo. |
| `plugin`, `plugin-opts` | Adds simple-obfs, WebSocket, ShadowTLS, or RESTLS outside the Shadowsocks record layer. |
| `udp-over-tcp` | Carries UDP datagrams over a Shadowsocks TCP stream. |
| `udp-over-tcp-version` | Selects the current or legacy UoT framing; zero defaults to the legacy version. |
| `client-fingerprint` | Used by plugin transports that emulate a TLS client. |
| common dial fields | Interface binding, routing mark, IP preference, TFO/MPTCP, and an optional dialer proxy. |

Construction calls `shadowsocks.CreateMethod` immediately. An unknown cipher, missing password, malformed 2022 key, or unsupported UoT version therefore fails while the proxy adapter is being created rather than during the first page visit.

## Cipher families

The pinned library registers three method families.

### Classic AEAD

The standard methods include:

- `aes-128-gcm`, `aes-192-gcm`, and `aes-256-gcm`;
- `chacha20-ietf-poly1305`;
- `xchacha20-ietf-poly1305`.

The fork also registers several non-standard AEAD methods. Their availability should not be interpreted as cross-implementation compatibility. The password is converted to a fixed-length master key by the legacy Shadowsocks key derivation when a raw key is not supplied.

Each TCP direction starts with a random salt. A per-direction subkey is derived from the master key and salt. The stream is then split into authenticated records: an encrypted length field followed by an encrypted payload. The implementation caps a classic AEAD plaintext record at `16 KiB - 1` bytes. Nonces advance across records and the response direction uses its own salt and cipher state.

For classic AEAD UDP, each physical datagram is independently decryptable and has the conceptual form:

```text
random salt || AEAD(SOCKS destination || UDP payload)
```

The destination is therefore protected along with the payload.

### Shadowsocks 2022 AEAD

The implemented 2022 methods include the standard AES-GCM and ChaCha20-Poly1305 forms:

- `2022-blake3-aes-128-gcm`;
- `2022-blake3-aes-256-gcm`;
- `2022-blake3-chacha20-poly1305`.

The configured password is parsed as one or more colon-separated, standard-base64 PSKs. Every decoded key must have the method's exact key length. BLAKE3-derived session keys, timestamps, randomized padding, and structured request/response headers are used. The AES forms can carry extended identity headers for multi-user key chains; the ChaCha20 form rejects that multi-key mode in this implementation.

The 2022 UDP format maintains explicit session and packet identity and replay-related state. It should not be decoded with the classic `salt || ciphertext` model.

### Legacy stream ciphers

The dependency still registers legacy stream methods for compatibility. They are a distinct, older construction and should not be treated as equivalent in security or wire format to AEAD or Shadowsocks 2022. TrafficTracer records the proxy type as Shadowsocks; experimental metadata should separately retain the configured cipher when comparisons depend on the method family.

## TCP connection path

The TCP path in `DialContextWithDialer` is:

1. Build a dialer from the outbound's interface, routing, IP-version, TFO/MPTCP, and call-specific options.
2. If `dialer-proxy` is configured, wrap the dialer so that the server connection itself is reached through another outbound.
3. Open one physical TCP connection to `server:port`.
4. Wrap that connection in the selected plugin, if any.
5. Wrap the resulting stream in the selected Shadowsocks method and encode the requested destination.
6. Return the encrypted stream to Mihomo's tunnel.

The destination is a SOCKS-style address containing an IPv4 address, IPv6 address, or domain plus port. With `DialConn`, the client sends the Shadowsocks request immediately. With `DialEarlyConn`, request emission is deferred and the first application payload can be coalesced with the destination header. Mihomo selects the early form when a plugin connection reports that it still needs a handshake, and for ShadowTLS and RESTLS.

Conceptually:

```text
connect proxy server
  -> establish optional plugin layer
  -> emit encrypted destination request
  -> exchange encrypted records
  -> close the logical and physical stream
```

Without a multiplexing plugin, one logical TCP connection normally produces one physical TCP connection to the Shadowsocks server. A plugin with multiplexing enabled can invalidate that simple one-to-one assumption.

## Optional plugin layer

Mihomo recognizes the following plugin forms in this outbound:

| Plugin | Accepted mode and behavior |
| --- | --- |
| `obfs` | simple-obfs `http` or `tls`; default camouflage host is `bing.com` when omitted. |
| `v2ray-plugin` | WebSocket only, with optional TLS, headers, early-data/HTTP Upgrade behavior, fingerprint, and mux. |
| `gost-plugin` | WebSocket only, with optional TLS, headers, fingerprint, and mux. |
| `shadow-tls` | ShadowTLS with host, password, version, certificate policy, and client fingerprint. |
| `restls` | RESTLS with host, password, version hint, script, and client fingerprint. |

The plugin transforms the already protected Shadowsocks byte stream. Consequently:

- an observed HTTP host, WebSocket path, TLS SNI, or certificate describes the plugin transport;
- that visible name need not equal the browser's destination URL;
- a cover domain is not proof that the browser requested that domain;
- base Shadowsocks without such a plugin does not generate a TLS SNI by itself.

## UDP paths

### Native Shadowsocks UDP

For native UDP, Mihomo resolves the configured proxy server as UDP, opens a local packet socket, binds its remote side to the resolved server, and applies `method.DialPacketConn`. Each application datagram keeps its destination metadata inside the Shadowsocks packet format.

The physical five-tuple is therefore:

```text
local physical UDP endpoint -> Shadowsocks server UDP endpoint
```

It is not the browser's original destination tuple. Several logical UDP exchanges may use the same packet socket during its lifetime, so packet boundaries remain meaningful while a universal one-logical-flow-to-one-outer-socket rule does not.

### UDP-over-TCP

When `udp-over-tcp` is enabled, Mihomo first creates a TCP Shadowsocks stream addressed to the UoT protocol's special destination. It then exposes a packet connection over that stream:

- the legacy version uses `uot.NewConn`;
- the current version uses `uot.NewLazyConn`.

Before constructing the UoT request, an unresolved logical destination is resolved locally because this adapter supplies a concrete UDP destination. On the wire, the carrier is TCP even though the logical flow is UDP. Analyses must retain both facts instead of rewriting the logical protocol to TCP.

## State model

```text
UNINITIALIZED
  -> validate method, password/key, plugin, and UoT version
READY
  -> dial physical server endpoint
PHYSICAL_CONNECTED
  -> optional plugin handshake/wrapper
TRANSPORT_READY
  -> Shadowsocks destination request, immediate or first-write lazy
FORWARDING
  -> encrypted records or datagrams
CLOSED / FAILED
```

Important failures include DNS or dial failure, plugin handshake failure, method initialization failure, authentication-tag failure, unsupported plugin mode, and a server-side close before a usable response stream is established.

## TrafficTracer observability

TrafficTracer observes the Shadowsocks path at two different semantic levels:

1. `tunnel/tunnel.go` captures the original TUN-side logical flow before routing and starts a TCP or UDP trace session.
2. `component/dialer/dialer.go` reports the successful physical socket through `traffictrace.ObserveOuterFlow`.
3. The tunnel reports the selected policy and leaf outbound, including leaf type `Shadowsocks`, and publishes the proxy-dial event with the observed endpoints.
4. Close events preserve byte counts and terminal state.

The typical non-multiplexed TCP relation is:

```text
browser/TUN five-tuple
  -> Mihomo logical connection ID
  -> selected Shadowsocks leaf
  -> local physical TCP endpoint -> Shadowsocks server endpoint
```

TrafficTracer cannot recover the ultimate destination from physical ciphertext alone. That information comes from the pre-proxy flow, routing metadata, Chrome evidence, and the in-process trace event. Likewise, a plugin SNI should be recorded as outer-transport evidence, not substituted for the requested URL.

For native UDP, UoT, and multiplexing plugins, the analyzer must allow one-to-many or many-to-one relations. Shadowsocks does not currently have the dedicated long-lived carrier registry implemented for Hysteria2, so absence of an explicit `reused` carrier event must not be interpreted as proof that no plugin-level reuse occurred.

## Measurement implications

- Preserve `cipher`, plugin name, plugin mode, UoT state, and leaf proxy identity in dataset provenance. Two Shadowsocks configurations can have materially different packet traces.
- Compare the browser/TUN tuple with the physical proxy-server tuple; do not expect the physical destination to equal the page origin.
- Attribute TLS SNI or HTTP camouflage only to the plugin layer.
- Treat UoT as logical UDP over a TCP carrier.
- Treat plugin mux and shared UDP sockets as potentially shared carriers.
- Do not infer application record sizes directly from TCP segments. Shadowsocks records, plugin framing, TLS records, kernel segmentation, and capture offload can all change the packetization.

## Implementation source map

| Concern | Source |
| --- | --- |
| Outbound options, validation, TCP/UDP branching | `adapter/outbound/shadowsocks.go` |
| Physical socket observation | `component/dialer/dialer.go` |
| Logical pre-flow and proxy-dial tracing | `tunnel/tunnel.go`, `component/tracer/tracer.go` |
| Active cipher implementation pin | `go.mod` (`github.com/metacubex/sing-shadowsocks2` v0.2.2) |
| Classic AEAD methods and framing | dependency module `shadowaead/method.go`, `shadowaead/protocol.go` |
| Shadowsocks 2022 methods and framing | dependency module `shadowaead_2022/method.go`, `shadowaead_2022/protocol.go` |
| Plugin transports | `transport/simple-obfs/`, `transport/v2ray-plugin/`, `transport/gost-plugin/`, `transport/sing-shadowtls/`, `transport/restls/` |
