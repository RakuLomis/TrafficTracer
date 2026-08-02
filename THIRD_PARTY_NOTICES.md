# TrafficTracer Complete third-party notices

TrafficTracer Complete is distributed under GPL-3.0-only. The complete
machine-readable dependency inventory for a release is generated as
SBOM.cdx.json; package hashes are recorded in SHA256SUMS, and release
metadata hashes are recorded in METADATA.sha256.

## Bundled applications

| Component | Source | License |
|---|---|---|
| mihomo / verge-mihomo / verge-mihomo-alpha | <https://github.com/MetaCubeX/mihomo> and the pinned TrafficTracer fork | GPL-3.0 |
| Clash Verge Rev | <https://github.com/clash-verge-rev/clash-verge-rev> and the pinned TrafficTracer fork | GPL-3.0-only |
| TrafficTracer Worker | This repository | GPL-3.0-only |

The exact fork commits used by a package are stored in COMPONENTS and in the
CycloneDX SBOM.

## Bundled geographic data

Country.mmdb, geoip.dat, and geosite.dat are downloaded by the pinned Clash
Verge Rev build from:

<https://github.com/MetaCubeX/meta-rules-dat>

That project publishes the data bundle under GPL version 3. The exact files
included in each Deb/AppImage are covered by the package checksum and
permission audit.

## Python runtime and build dependencies

The packaged Worker includes Python libraries resolved from
requirements-build.txt, including PyYAML (MIT), websockets (BSD-3-Clause),
jsonschema (MIT), and PyInstaller. PyInstaller is licensed under GPL-2.0-or-later
with its bootloader exception.

## Go, Rust, and Node dependencies

Transitive dependency identities and versions are generated from these pinned
inputs:

- components/mihomo/go.sum
- components/clash-verge-rev/Cargo.lock
- components/clash-verge-rev/pnpm-lock.yaml
- requirements-build.txt

Individual third-party packages remain subject to their respective upstream
licenses and notices. Before publishing a release, review the generated SBOM
and preserve any additional attribution required by an updated dependency.

No subscription configuration, controller secret, capture session, browser
profile, packet capture, or user log is intended to be included in a release.
The automated release audit rejects common secret patterns and sensitive file
names in extracted package roots.
