# TrafficTracer Complete release checklist

This is the blocking release gate for Linux x86-64 release candidates. A
candidate is not approved merely because it builds; every automated command and
every release-specific sign-off below must be recorded for the exact commit and
artifacts being published.

## 1. Candidate identity

Record these values without abbreviating hashes:

| Field | Value |
|---|---|
| Release version | |
| TrafficTracer commit | |
| mihomo commit | |
| clash-verge-rev commit | |
| Linux Package Smoke run URL | |
| Privileged TUN E2E run URL | |
| Release operator and date | |

The values must match complete/components.lock.yaml, package COMPONENTS, and
SBOM.cdx.json.

## 2. Automated blocking gate

Run from a clean Complete checkout with recursive submodules:

    python -m pip install -r requirements-build.txt
    pnpm --dir components/clash-verge-rev install --frozen-lockfile
    make test-python
    make test-contracts
    make test-e2e-direct
    make test-recovery
    make release-linux
    make test-package-linux
    make audit-release

The release-linux target is intentionally stricter than package-linux. It
rejects tracked uncommitted changes and publishes the following files together:

- one Deb and one AppImage;
- SHA256SUMS for package binaries;
- COMPONENTS with the three exact source revisions;
- LICENSE, NOTICE, and THIRD_PARTY_NOTICES.md;
- CycloneDX 1.6 SBOM.cdx.json;
- METADATA.sha256 for release metadata;
- RELEASE-AUDIT.json with a pass/fail summary.

The clean Linux VM workflow must run release-linux, start the installed UI under
Xvfb/DBus, execute Worker diagnostics, probe tracing capabilities, re-run the
release audit, and upload the whole directory as one artifact.

## 3. License and third-party dependencies

- [x] Root project license is GPL-3.0-only.
- [x] Pinned mihomo and Clash Verge Rev license files are present.
- [x] THIRD_PARTY_NOTICES.md identifies bundled applications and geographic
      data.
- [x] Python, Go, Rust, and npm dependency locks are inventoried in CycloneDX.
- [ ] Release operator reviewed any new or changed SBOM component license.
- [ ] Required source offer/source archive accompanies public binary
      distribution as required by GPL.

Changing the root license requires an owner decision and corresponding updates
to LICENSE, NOTICE, THIRD_PARTY_NOTICES.md, SBOM generation, and this checklist.

## 4. Secrets and personal data

The automated audit extracts both package formats and rejects:

- private-key headers and common provider token formats;
- bearer authorization values and credential-like assignments;
- .env, private key/certificate containers, user config/profile files;
- capture sessions, recovery journals, and known user site configuration names.

Release operator additionally confirms:

- [ ] no subscription URL or proxy credentials appear in UI defaults;
- [ ] no Mihomo controller secret is present;
- [ ] no browser profile, NetLog, pcap, tracing log, or Session artifact exists;
- [ ] CI logs and uploaded artifacts contain no signing key or access token.

Do not paste real secrets into an exception list. Remove the source of the
secret and rebuild.

## 5. Paths and permissions

The automated audit rejects:

- group/world-writable installed paths and world-writable outer artifacts,
  except linuxdeploy's group-writable `AppRun.wrapped` launcher inside the
  read-only AppImage filesystem;
- setuid or setgid entries;
- symlinks escaping the package root;
- missing/non-executable UI, service helpers, cores, or Worker.

Release operator confirms on a clean non-root desktop account:

- [ ] GUI and Worker run as the desktop user;
- [ ] privilege elevation is limited to Clash Verge service installation;
- [ ] selected Session/log directory is user-controlled and writable;
- [ ] cancel, crash recovery, and app exit leave no managed child process;
- [ ] uninstall does not remove user-selected capture output.

## 6. Checksums, provenance, and signatures

- [x] SHA256SUMS covers both package binaries, including names with spaces.
- [x] METADATA.sha256 covers component metadata, licenses, notices, and SBOM.
- [x] COMPONENTS is compared with git HEAD and pinned submodule commits.
- [x] package smoke checks the embedded core build marker, Worker API, and
      tracing capabilities.
- [ ] Decide whether this candidate is signed or explicitly published as
      unsigned.
- [ ] If signed, verify signatures from a second clean machine without exposing
      the private key.

Unsigned local/test builds are supported. Public release notes must not imply an
unsigned package is signed.

## 7. Functional release acceptance

- [ ] Import a real YAML profile.
- [ ] Select the TrafficTracer core.
- [ ] Test node latency and choose a proxy node.
- [ ] Install the service and enable TUN/system proxy.
- [ ] Complete a capture and automatic analysis.
- [ ] Query a pre-proxy five-tuple and inspect every returned post_flow.
- [ ] Confirm shared outer connections display the non-one-to-one warning.
- [ ] Cancel during Chrome, packet capture, and analysis.
- [ ] Kill/restart Worker and confirm interrupted Session recovery.
- [ ] Restart the UI and confirm core/profile/TUN controls unlock correctly.

Record sanitized Session IDs and screenshots/log excerpts in the release record;
do not commit captures or credentials to the repository.

## 8. Approval

All unchecked blocking items require either completion or a documented,
owner-approved release exception. Exceptions must state scope, risk, expiry, and
owner; they must never suppress checksum, secret, component revision, or package
permission failures.

| Role | Name | Date | Result |
|---|---|---|---|
| Automated release audit | make audit-release | | |
| Clean VM package smoke | | | |
| Privileged TUN test | | | |
| License/SBOM reviewer | | | |
| Functional acceptance | | | |
| Release owner | | | |

The release owner marks the candidate approved only after all rows pass. This
per-candidate signature is operational release evidence; implementation of the
INT-007 gate itself is verified by the repository tests and CI workflow.
