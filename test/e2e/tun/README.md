# Privileged TUN E2E Runner

`make test-e2e-tun` is a release/manual gate for a dedicated Linux x86-64
self-hosted Runner labelled `traffictracer-tun`. It is intentionally not
triggered by pull requests.

The Runner account must remain unprivileged and have:

- Python, Go, PyInstaller, `iproute2`, `util-linux`, libcap and Wireshark CLI;
- `dumpcap -D` access without sudo;
- non-interactive sudo for the isolated `ip netns`/veth/route commands,
  `setcap` on the freshly built Complete core, and terminating fixture PIDs;
- no concurrent jobs that share the host network namespace.

Use a disposable or otherwise controlled Runner. Do not attach the privileged
label to a general-purpose Runner and do not enable this workflow for untrusted
fork or pull-request code.

The test itself runs Mihomo and the Worker as the Runner account. Sudo is used
only to create/delete a uniquely named target namespace and veth pair, install
the one-host route through Mihomo's TUN device, temporarily grant the built core
network capabilities, and clean up namespace fixture processes. Existing core
file capabilities are restored in all normal and exceptional exits.

Run manually with:

```bash
make test-e2e-tun
```

A passing run proves that both `tun.pcap` and `phys.pcap` contain fixture
traffic and that an exact normalized pre-proxy five-tuple query returns a
complete post-proxy flow.
