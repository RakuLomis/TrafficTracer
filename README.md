# TrafficTracer

TrafficTracer Complete is a Linux desktop application for controlling a Mihomo proxy and correlating browser traffic across the proxy boundary.

It combines three pinned components in one build:

- a Clash Verge desktop UI for profiles, proxy selection, system proxy, TUN, capture, and analysis;
- a TrafficTracer Worker that coordinates Chrome, packet capture, Sessions, recovery, and analysis;
- a TrafficTracer-aware Mihomo core that records pre-proxy and post-proxy connection evidence.

The primary result is a request-aware flow pipeline:

```text
page URL
  -> Chrome CDP and NetLog evidence
  -> pre-proxy five-tuple
  -> Mihomo routing and terminal outcome
  -> post-proxy five-tuple, or an explicit no-socket reason
  -> packet evidence on the TUN and physical interfaces
```

TrafficTracer preserves uncertainty. Shared proxy transports, browser-internal requests, rejected connections, local endpoints, and unmatched evidence are reported explicitly rather than converted into invented one-to-one flows.

## Supported release

TrafficTracer Complete 1.0.2 supports Linux x86-64. The release is built and validated on Ubuntu 24.04 LTS.

Windows and other Linux architectures are not part of the 1.0.2 release scope.

## QuickStart

### 1. Install capture prerequisites

Install Chrome or Chromium and Wireshark CLI tools. On Ubuntu:

```bash
sudo apt update
sudo apt install tshark
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v dumpcap)"
dumpcap -D
```

If your distribution uses the `wireshark` group, follow its package prompt, add your desktop user to that group, and sign in again.

### 2. Install TrafficTracer Complete

Verify the release directory before installation:

```bash
cd /path/to/traffictracer-complete-v1.0.2-linux-x86_64
sha256sum -c SHA256SUMS
sudo apt install ./TrafficTracer-Complete_1.0.2_linux_x86_64.deb
```

The Deb uses the Clash Verge application identity so it can upgrade an existing installation and reuse its user configuration. Exit the old UI normally during a maintenance window before starting the installed version. Building or verifying TrafficTracer does not require stopping the currently running proxy.

Alternatively, run the AppImage:

```bash
chmod +x TrafficTracer-Complete_1.0.2_linux_x86_64.AppImage
./TrafficTracer-Complete_1.0.2_linux_x86_64.AppImage
```

### 3. Configure the proxy

1. Open **Profiles** and import a Mihomo YAML profile.
2. Activate the profile.
3. Open **Settings → Clash Core** and select `verge-mihomo-tt`.
4. Open **Proxies**, run a latency test, and select the desired node or policy.
5. Enable system proxy and TUN when required by the experiment.
6. Install the Clash Verge service if TUN controls report that the service is unavailable.

### 4. Capture and analyze

1. Open **Traffic Tracer**.
2. Select a writable Session output directory.
3. Leave the TUN interface empty to use the runtime/default interface, normally `Meta`; select the physical egress interface reported by `ip route show default`.
4. Enter one URL manually or load a target YAML file.
5. Run **Environment Check** and resolve every blocking diagnostic.
6. Start capture. YAML targets run serially in file order.
7. Open the completed Session to inspect request, connection, egress, packet, and integrity results.
8. Use the five-tuple query to look up all matching pre-proxy to post-proxy mappings.

A minimal target file is:

```yaml
sites:
  - domain: example.com
    url: https://example.com/
    page_type: main-page
    wait: 10
    wait_load_timeout: 30
    traffic_type: all
```

`page_type` is the readable page label. `traffic_type` is the network selector only when it is `tcp`, `udp`, or `all`; any other safe value is treated as a legacy run label and the network defaults to `all`.

## Build from source

```bash
git clone --branch Complete --recurse-submodules \
  git@github.com:RakuLomis/TrafficTracer.git
cd TrafficTracer
python -m pip install -r requirements.txt -r requirements-build.txt
corepack enable
pnpm --dir components/clash-verge-rev install --frozen-lockfile
make check-toolchain
make test-python
make test-contracts
make prepare-dev
```

Run `make dev` only when another Clash Verge instance is not using the same controller or service socket. Build Linux packages with `make package-linux`; use `make release-linux` for the stricter audited release path.

## Documentation

- [Documentation index](docs/README.md)
- [Complete UI guide](docs/complete/quickstart.md)
- [Architecture](docs/architecture.md)
- [Target configuration](docs/configuration.md)
- [Sessions and correlation data](docs/data-model.md)
- [Operations and troubleshooting](docs/operations.md)
- [Development and releases](docs/development.md)
- [TrafficTracer Complete 1.0.2 release notes](docs/releases/v1.0.2.md)

## License
