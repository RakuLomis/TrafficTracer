# Standalone Tools

TrafficTracer Complete UI is the supported end-user workflow. The repository also retains Python entry points for automation, compatibility, focused analysis, and development. They are not a substitute for the pinned Complete UI/Worker/core handshake.

## Install Python dependencies

```bash
python -m pip install -r requirements.txt
```

Run commands from the repository root with `PYTHONPATH=.` when the package is not installed into the active environment.

## Legacy capture pipeline

```bash
PYTHONPATH=. python capture.py --config /absolute/path/to/sites.yaml
PYTHONPATH=. python capture.py --config /absolute/path/to/sites.yaml --only example.com
```

The standalone configuration may include `global` runtime settings for a Mihomo binary/controller, Chrome, interfaces, and output root. See `sites.example.yaml` and `sites.clash-verge.example.yaml`.

When Clash Verge owns Mihomo, set `global.mihomo.managed: false` and use its effective controller endpoint. Do not let the standalone pipeline stop or replace a core owned by the desktop application.

The Complete UI is preferred because it validates the selected live core, service, TUN, interfaces, output root, and component versions before capture.

## Analyze a Session

```bash
PYTHONPATH=. python analyze.py --session /absolute/path/to/page-session
PYTHONPATH=. python analyze.py --session /absolute/path/to/page-session --json
```

Analysis reads registered raw artifacts, validates contracts, creates a new analysis generation, and updates the Session manifest atomically. Preserve the complete Session directory; do not point the command at the timestamp root or edit prior indexes in place.

## Query a persisted flow

```bash
PYTHONPATH=. python query_flow.py \
  --session /absolute/path/to/page-session \
  --network tcp \
  --src-ip 198.18.0.1 \
  --src-port 48126 \
  --dst-ip 203.0.113.10 \
  --dst-port 443 \
  --json
```

Use `--offset` and `--limit` for pagination. A query can return multiple results. A `null` post-flow is not automatically an error; inspect route and disposition fields.

For raw tracing compatibility, the command also accepts positional arguments:

```bash
PYTHONPATH=. python query_flow.py \
  /path/to/mihomo-trace.jsonl tcp \
  198.18.0.1 48126 203.0.113.10 443
```

Persisted Session queries are preferred because they include canonical normalization, URL attribution, route outcomes, and analysis generation identity.

## Manage serial batches

```bash
PYTHONPATH=. python batch.py --output-root /absolute/session/root list
PYTHONPATH=. python batch.py --output-root /absolute/session/root status <batch-id>
PYTHONPATH=. python batch.py --output-root /absolute/session/root start --help
PYTHONPATH=. python batch.py --output-root /absolute/session/root resume <batch-id>
PYTHONPATH=. python batch.py --output-root /absolute/session/root cancel <batch-id>
```

This CLI operates on persistent Worker batch state without relying on frontend state. It still enforces one active job and serial child execution. Use the same controller endpoint and output root as the owning Worker.

## Inspect a Chrome NetLog

`netlog_parser.py` is a legacy diagnostic parser for a standalone Chromium NetLog JSON file or ZIP archive:

```bash
python netlog_parser.py --summary chrome-net-export-log.json
python netlog_parser.py --chains --url "*.example.com*" chrome-net-export-log.json
python netlog_parser.py --domain example.com chrome-net-export-log.json
python netlog_parser.py --json --output parsed.json chrome-net-export-log.json
python netlog_parser.py log.zip
```

It can print connection chains, DNS resolver cache entries, and HTTP/2 or QUIC reuse information. It does not have Mihomo post-proxy evidence by itself and therefore cannot produce the Complete pre-proxy to post-proxy pipeline.

## Worker protocol process

`traffictracer_worker.py` exposes Worker API v2 over newline-delimited JSON for the Tauri backend and integration tests. It is normally launched from the package sidecar, not manually by users.

```bash
PYTHONPATH=. python traffictracer_worker.py --output-root /absolute/session/root
```

Each request and response is validated against `contracts/worker-api.schema.json`. Notifications report progress and lifecycle changes. Only one active job is permitted.

## Compatibility status

These tools remain covered by tests, but the desktop workflow is authoritative for:

- profile and node selection;
- service installation;
- TUN and system proxy control;
- runtime diagnostics and control locking;
- Session-root selection;
- capture progress, cancellation, recovery, and browsing;
- component-version compatibility.
