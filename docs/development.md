# Development and Releases

TrafficTracer Complete is developed from the `Complete` branch with pinned recursive submodules. The supported 1.0.7 release target is `x86_64-unknown-linux-gnu`.

## Clone and bootstrap

```bash
git clone --branch Complete --recurse-submodules \
  git@github.com:RakuLomis/TrafficTracer.git
cd TrafficTracer
make bootstrap
```

`make bootstrap` initializes the exact component paths declared in `complete/components.lock.yaml`. Do not replace them with sibling checkouts.

## Toolchain

Install Python dependencies and the pinned frontend dependencies:

```bash
python -m pip install -r requirements.txt -r requirements-build.txt
corepack enable
pnpm --dir components/clash-verge-rev install --frozen-lockfile
make check-toolchain
```

The toolchain check covers Python 3.12 or newer, Go, Rust/Cargo, pnpm, PyInstaller, Chrome/Chromium, tshark, and dumpcap. Release 1.0.7 is built and validated in the current Ubuntu 24.04 LTS environment.

## Component lock

`complete/components.lock.yaml` pins:

- product name, version, branch, and platform;
- Mihomo repository, branch, and commit;
- Clash Verge repository, branch, and commit;
- service repository, version, commit, archive checksum, IPC paths, and protocol compatibility;
- all cross-component contract versions.

After changing a component:

1. commit and push the component branch;
2. update the Complete submodule gitlink;
3. update the matching commit in the component lock;
4. update contract versions only when serialized compatibility changes;
5. run source and binary lock verification;
6. commit the Complete pin update.

Never point the lock at an unpushed commit. A release must be reproducible from remote sources.

## Common targets

```bash
make help
make test-python
make test-contracts
make test-e2e-direct
make test-recovery
make build-core
make build-worker
make check-component-lock
make prepare-dev
make dev
make package-linux
make release-linux
make test-package-linux
make audit-release
```

`make prepare-dev` rebuilds and injects sidecars without launching another desktop application. Use it while an installed Clash Verge instance must remain online.

`make dev` performs the same preparation and starts the Tauri development UI. Do not run it concurrently with an installed instance that owns the same controller or service socket.

## Test layers

### Python and contracts

```bash
PYTHONPATH=. pytest -q
make test-contracts
```

The suite covers configuration, Worker protocol, jobs, cancellation, recovery, capture orchestration, Chrome/CDP, tracing, correlation, packet mapping, Session compatibility, package scripts, and release audit behavior.

### Unprivileged integration

```bash
make test-e2e-direct
make test-recovery
```

These exercise direct-mode handshakes, Worker lifecycle, cancellation, and recovery without modifying the live host TUN configuration.

### Privileged isolated TUN integration

```bash
make test-e2e-tun
```

Run this only in the intended isolated test environment with explicit privilege approval. It must not reuse or disrupt a production proxy interface.

### UI gates

From `components/clash-verge-rev`:

```bash
cargo fmt --check
pnpm typecheck
pnpm lint
```

Run the relevant Rust and frontend tests for changed UI/backend modules.

## Build outputs

`make prepare-dev` produces:

```text
dist/core/verge-mihomo-tt-x86_64-unknown-linux-gnu
dist/worker/traffictracer-worker-x86_64-unknown-linux-gnu
components/clash-verge-rev/src-tauri/sidecar/
```

The build verifies the core marker, Worker hello/diagnostics response, service archive checksum, submodule commits, and injected sidecar hashes.

## Development packages

```bash
make package-linux
```

The wrapper rebuilds the core and Worker, prepares the pinned UI resources, invokes Tauri for Deb and AppImage, and verifies both bundles before atomically publishing the directory:

```text
dist/packages/traffictracer-complete-v1.0.7-linux-x86_64/
```

The output directory is never overwritten. Choose a new absolute path for another candidate:

```bash
TT_PACKAGE_OUTPUT_DIR="$PWD/dist/packages/local-candidate-2" \
  make package-linux
```

By default, preparation refreshes upstream Mihomo binaries, rule data, and the pinned service bundle. `TT_PREBUILD_FORCE=0` may reuse an already verified cache for a local retry, but a formal release should refresh dependencies from their locked sources.

## Formal release

A release candidate must start from a clean tracked worktree. Generated outputs are ignored, but source, submodule, or lock changes must be committed first.

```bash
make release-linux
make test-package-linux
make audit-release
```

`make release-linux` adds and verifies:

- Deb and AppImage SHA-256 checksums;
- `VERSION` product and bundle identity;
- `COMPONENTS` exact source and service revisions;
- GPL license and third-party notices;
- a CycloneDX 1.6 SBOM;
- metadata checksums;
- an extracted-package permission, path, executable, and secret scan;
- a machine-readable release audit report.

The independent package smoke extracts both formats outside source-sidecar paths, starts the Worker protocol, checks the embedded TrafficTracer core marker and tracing capabilities, and optionally launches the UI under a controlled desktop environment.

Complete every applicable item in [the release checklist](release-checklist.md) before publishing a tag or binary release.

## Versioning

TrafficTracer product version is defined by `traffictracer.version.COMPLETE_VERSION` and must equal `product.version` in the component lock.

The 1.0.7 Linux Deb retains the upstream package identity for upgrade compatibility while using bundle version:

```text
2.5.2+traffictracer.1.0.7
```

Public assets use product-centric names:

```text
TrafficTracer-Complete_1.0.7_linux_x86_64.deb
TrafficTracer-Complete_1.0.7_linux_x86_64.AppImage
```

Create the annotated product tag only after the final artifacts pass smoke and release audit. Rewriting a released tag invalidates commit provenance and package metadata.

## Signing

Without `TAURI_SIGNING_PRIVATE_KEY`, the build disables updater artifacts and produces verified but unsigned packages. Release notes must state that status accurately. If signing is enabled, verify signatures on a second clean machine and never expose the private key in source, logs, CI artifacts, or exception lists.

## Documentation changes

Documentation is maintained in English. Keep the root README short and move technical detail into this directory. When behavior or a serialized field changes:

1. update the machine-readable contract or component lock first;
2. update the corresponding focused document;
3. update QuickStart only when the user workflow changes;
4. update release notes or the changelog when users need migration context;
5. run documentation and link checks with the normal test suite.

Historical implementation plans are intentionally excluded from the active documentation tree. Git history remains the archive for obsolete design work.
