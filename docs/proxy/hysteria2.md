# Hysteria2 Implementation in Mihomo

## Scope and source baseline

This document describes the Hysteria2 client outbound used by the TrafficTracer-aware Mihomo core at commit `fcacc8696dfd574d0faa2770c5d3151e21dd9bbc`. Mihomo's adapter is in `adapter/outbound/hysteria2.go`; the QUIC session, authentication, stream, and datagram logic comes from `github.com/metacubex/sing-quic` at pseudo-version `v0.0.0-20250119013740-2a19cce83925`, pinned by `go.mod`.

Hysteria2 is fundamentally different from the ordinary one-logical-flow/one-physical-socket model. A long-lived QUIC connection over UDP can carry many proxy TCP streams and many logical UDP sessions. TrafficTracer therefore implements an explicit shared-carrier registry for this outbound.

## Layering model

```text
logical TCP connection          logical UDP session
        |                               |
        v                               v
  QUIC bidirectional stream       QUIC DATAGRAM messages
        \                               /
         +---- one reusable QUIC connection ----+
                            |
                  optional Salamander obfs
                            |
          physical UDP socket to Hysteria2 server
```

TLS 1.3 is integrated into QUIC. The Hysteria2 password authenticates an HTTP/3 request after the QUIC transport has been established; it is not used as the QUIC traffic-encryption key. When Salamander is enabled, it transforms each complete QUIC UDP datagram outside the QUIC implementation.

## Configuration accepted by the outbound

`Hysteria2Option` exposes:

| Field | Purpose |
| --- | --- |
| `server`, `port` | Fixed server endpoint. |
| `ports` | Port or port-range expression used for randomized port hopping. |
| `hop-interval` | Seconds between port changes; defaults to 30 and is clamped to at least 5 when hopping is active. |
| `password` | Value sent in the encrypted Hysteria2 authentication request. |
| `up`, `down` | Configured send and receive bandwidth used for congestion-control negotiation. |
| `obfs`, `obfs-password` | Optional Salamander packet obfuscation; no other obfs type is accepted here. |
| `sni`, `skip-cert-verify`, `fingerprint`, `alpn`, `ca`, `ca-str` | QUIC TLS identity and trust settings. |
| `cwnd` | Congestion-window input for the Mihomo congestion-controller hook. |
| `udp-mtu` | Maximum Hysteria2 UDP message size before protocol fragmentation; defaults to 1197. |
| four QUIC receive-window fields | Initial/max stream and connection receive windows. |
| common dial fields | Interface, routing mark, IP-version preference, and optional dialer proxy. |

Only Salamander is recognized as `obfs`; selecting it without a password is rejected. At least one fixed port or a non-empty expanded port range is required.

The TLS server name defaults to `server` and is overridden by `sni`. Minimum TLS version is 1.3. If no ALPN is supplied, the sing-quic Hysteria2 client uses `h3`.

## Adapter construction

`NewHysteria2` performs the following work:

1. Validate and prepare Salamander, if requested.
2. Create a TLS 1.3 configuration with SNI, CA, fingerprint, certificate policy, and optional ALPN.
3. Set the default Hysteria2 UDP MTU to `1200 - 3 = 1197` when omitted.
4. Create the QUIC receive-window configuration.
5. Create a dynamically replaceable sing dialer so each logical call can apply current Mihomo dial options.
6. Build a server-address callback for the fixed endpoint or randomized port list.
7. Create a persistent `hysteria2.Client` and a TrafficTracer carrier registry.

The client is retained by the outbound rather than reconstructed for every browser connection. Removing or finalizing the proxy clears the carrier registry and closes the Hysteria2 client.

## Establishing the shared QUIC carrier

The sing-quic client serializes access to its current connection. Its `offer` operation returns the active QUIC connection when one exists; otherwise it calls `offerNew`.

`offerNew` follows this sequence:

1. Resolve or select the current server UDP endpoint.
2. Open one physical UDP packet socket through Mihomo's dialer.
3. Optionally wrap the packet socket in Salamander.
4. Create a QUIC early connection and HTTP/3 transport with TLS 1.3.
5. Send an HTTP/3 `POST` authentication request.
6. Require the Hysteria2 success status.
7. Configure Brutal or BBR congestion control from the negotiated bandwidth values.
8. Start the QUIC datagram receive loop when UDP is enabled.
9. Start the port-hopping loop when a range was configured.

### Authentication request

The request is internal to the encrypted HTTP/3 connection:

```text
method:    POST
scheme:    https
authority: hysteria
path:      /auth
headers:
  Hysteria-Auth:    <configured password>
  Hysteria-CC-RX:   <requested receive bytes/second, or 0>
  Hysteria-Padding: <random padding>
```

The server must return status `233`. Response headers state whether UDP is enabled and advertise a receive-rate value or `auto`. Because the request is inside QUIC encryption, the pseudo-authority `hysteria` and password are not ordinary plaintext DNS/SNI observations. The public TLS SNI comes from the adapter's `sni`/server setting.

### Congestion controller selection

The client caps its effective transmit rate using the server's advertised receive rate and local `up` value. If the server returns a fixed usable rate, the client installs the Hysteria Brutal sender. If the response requests automatic behavior or no fixed rate is selected, it invokes Mihomo's BBR congestion-controller hook.

Brutal is rate-oriented and uses acknowledgements and smoothed RTT to update pacing and congestion window. This means a Hysteria2 packet trace is shaped both by application demand and by a protocol-specific controller; it should not be compared to a TCP carrier as if only encryption overhead differed.

## Logical TCP over QUIC streams

Each `DialConn` obtains the shared QUIC carrier and opens a new bidirectional QUIC stream. The Hysteria2 proxy request is lazy: it is written with the first application payload.

The first stream write has this form:

```text
QUIC varint 0x401                     # TCP request frame type
QUIC varint address_length
address bytes                         # destination in host:port form
QUIC varint padding_length
random padding bytes
optional early application payload
```

The server response prefix is:

```text
status byte                           # 0 success, nonzero error
QUIC varint message_length
message bytes
QUIC varint padding_length
padding bytes
optional early response payload
```

After a successful response, the remainder of the QUIC stream is the proxied byte stream. Closing a logical TCP connection cancels reading and closes only that QUIC stream; the underlying QUIC carrier can remain active for subsequent logical connections.

## Logical UDP over QUIC DATAGRAM

`ListenPacket` also reuses the current QUIC carrier. It allocates a monotonically increasing 32-bit session ID and registers a packet connection in the carrier's session map. Every application datagram is encoded as:

```text
session_id       uint32, big endian
packet_id        uint16, big endian
fragment_id      uint8
fragment_count   uint8
address_length   QUIC varint
destination      address bytes
payload          remaining bytes
```

The packet ID advances per logical UDP packet. If the encoded message would exceed `udp-mtu`, the payload is split into protocol fragments carrying the same session/packet identity and explicit fragment indexes. Received fragments are reassembled before delivery to Mihomo. The receive loop demultiplexes messages by session ID into the relevant logical packet connection.

This is QUIC DATAGRAM traffic, not one new physical UDP five-tuple per target datagram. Many DNS, HTTP/3, media, or other logical UDP flows can coexist on the same outer UDP carrier.

## Salamander obfuscation

When enabled, Salamander wraps the physical packet socket. For every outgoing QUIC datagram it:

1. creates an 8-byte random salt;
2. computes BLAKE2b-256 over `password || salt`;
3. XORs the QUIC datagram with the repeated 32-byte digest;
4. sends `salt || transformed_datagram`.

The receiver performs the inverse operation. Salamander changes the observable appearance of QUIC packets, but it is not the protocol's authenticated encryption layer; QUIC/TLS 1.3 still provides authenticated transport security. Dataset provenance must distinguish plain Hysteria2 QUIC from Hysteria2 plus Salamander.

## Port hopping

When `ports` is configured, Mihomo expands the range and selects a random member for initial connection. The sing-quic hop loop periodically asks for another address, copies the existing remote IP, replaces only the UDP port, and calls QUIC's `SetRemoteAddr` on the active connection.

The consequences are:

- one QUIC connection can have several sequential outer destination ports;
- a changed physical five-tuple does not necessarily mean a new logical connection or QUIC handshake;
- the local source port can remain stable while the remote port changes;
- packet analysis must group these paths by carrier identity and generation rather than by a single immutable five-tuple.

Mihomo's TrafficTracer-specific `ServerAddress` callback reports hop updates to the active carrier registry when the resolution is not part of initial trace-context creation.

## TrafficTracer carrier model

Hysteria2 has dedicated instrumentation because generic per-dial endpoint extraction cannot describe a reusable QUIC session correctly.

### Creation

When the first logical dial causes a physical UDP socket to be created, `component/dialer/dialer.go` produces an `OuterFlowObservation`. The Hysteria2 adapter captures it, promotes it into the registry, and sets:

```text
protocol = hysteria2
shared = true
relation = created
generation = previous_generation + 1
paths = [initial_outer_five_tuple]
```

A carrier-open lifecycle event is emitted.

### Reuse

When a later logical TCP stream or UDP session obtains the already active QUIC connection, no new physical dial observation occurs. The adapter instead obtains the registry entry and publishes it to the logical trace as:

```text
same carrier ID
same generation
relation = reused
shared = true
```

The logical flow therefore remains associated with the physical carrier without pretending that it created a new UDP socket.

### Path update

On port hopping, the registry updates the carrier's current destination port, retains every distinct path tuple, and emits a carrier-path-update lifecycle event. The current flow and historical `paths` are both preserved.

### Replacement and close

If the active QUIC connection becomes unusable, sing-quic creates a new one on demand. The next captured socket is promoted with a new generation. Removing the proxy clears the active registry and emits a carrier-close event.

This model yields:

```text
many browser/TUN logical flows
  -> many Mihomo logical trace IDs
  -> one Hysteria2 carrier ID and generation
  -> one or more port-hopped physical UDP paths
```

It is intentionally many-to-one. `candidate 2/3` or other association multiplicity in analysis must not automatically be labeled an error when the alternatives describe legitimate shared-carrier evidence.

## Concurrency and dial context

The adapter protects `DialContext` and `ListenPacketContext` with `dialMu`. For each call it installs a dialer configured with the current outbound options and attaches a temporary outer-flow capture observer. This serialization prevents concurrent first-use calls from racing while the shared QUIC carrier is being established and bound to TrafficTracer.

Once the carrier exists, QUIC itself multiplexes streams and datagrams. The mutex guards adapter setup and binding, not all data transfer for the lifetime of every stream.

## State model

```text
UNINITIALIZED
  -> validate ports, TLS, obfs, windows, and rates
CLIENT_READY
  -> first logical request calls offer()
UDP_SOCKET_OPEN
  -> optional Salamander wrapper
QUIC_HANDSHAKE
  -> HTTP/3 POST /auth
AUTHENTICATED CARRIER (generation N)
  -> open/reuse TCP streams
  -> allocate/reuse UDP sessions
  -> optional remote-port path updates
DEAD CARRIER
  -> next offer creates generation N+1
CLOSED / FAILED
```

Failures include server resolution, UDP socket creation, TLS/QUIC handshake, certificate validation, authentication status other than 233, server-disabled UDP, QUIC stream creation, datagram decode/reassembly, and connection-idle or network loss. A logical page failure and a carrier failure are related but not identical; one carrier failure can affect several contemporaneous logical flows.

## Measurement implications

- The post-proxy carrier is semantically QUIC over UDP even when the pre-proxy logical flow is TCP; with Salamander enabled, the physical payload no longer has an ordinary QUIC wire signature.
- Count logical flows and physical carriers separately. Their totals are not expected to match.
- Group outer path tuples by carrier ID and generation, especially with port hopping.
- Record SNI, ALPN, Salamander state, port ranges, hop interval, bandwidth settings, UDP MTU, and QUIC window settings in capture provenance.
- Do not interpret the internal HTTP/3 authority `hysteria` as the requested website or public SNI.
- Do not infer a mixed proxy protocol merely because browser HTTPS, HTTP/3, logical TCP/UDP, QUIC, and optional Salamander coexist in one capture. The selected leaf remains Hysteria2; these are different layers.
- A temporary node-quality problem can reset the carrier and degrade several page activities. Preserve carrier generation and terminal errors so that such failures can be separated from URL-specific browser failures.
- QUIC packet numbers, encryption, retransmission behavior, pacing, and port hopping make packet-size/timing comparisons carrier-context dependent.

## Implementation source map

| Concern | Source |
| --- | --- |
| Mihomo options, validation, dial serialization | `adapter/outbound/hysteria2.go` |
| TrafficTracer carrier registry and lifecycle | `adapter/outbound/hysteria2.go`, `common/traffictrace/`, `component/tracer/tracer.go` |
| Physical UDP socket observation | `component/dialer/dialer.go` |
| Logical pre-flow and proxy-dial tracing | `tunnel/tunnel.go` |
| Active Hysteria2 dependency pin | `go.mod` (`github.com/metacubex/sing-quic` pseudo-version shown above) |
| QUIC creation, auth, reuse, and port hopping | dependency module `hysteria2/client.go` |
| TCP request/response and UDP wire formats | dependency module `hysteria2/internal/protocol/proxy.go` |
| HTTP/3 authentication constants | dependency module `hysteria2/internal/protocol/http.go` |
| UDP fragmentation/reassembly | dependency module `hysteria2/packet.go` |
| Salamander | dependency module `hysteria2/salamander.go` |
| Congestion-controller integration | `transport/tuic/common/`, dependency module `hysteria2/congestion.go` |
