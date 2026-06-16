# NetLog Parser

Parse Chromium NetLog JSON dumps to extract connection chains, TCP/IP five-tuples, DNS cache records, session reuse information, and domain-level connection analysis with same-site / cross-site classification.

## Quick Start

```bash
# Full analysis
python netlog_parser.py chrome-net-export-log.json

# Domain analysis — group connections by site relationship
python netlog_parser.py -d bilibili.com log.json

# Domain analysis with JSON export
python netlog_parser.py -d bilibili.com --json log.json

# Summary only
python netlog_parser.py --summary log.json

# Connection chains only
python netlog_parser.py --chains log.json

# Chain filtering by URL pattern
python netlog_parser.py --chains --url "*bilibili*" log.json

# DNS records only
python netlog_parser.py --dns log.json

# Load from chrome://net-export ZIP
python netlog_parser.py net-export-log.zip
```

## Installation

No dependencies beyond Python 3.10+ standard library.

```bash
git clone <this-repo>
cd netlog_parser
```

## Usage

```
python netlog_parser.py [-h] [--summary] [--chains] [--dns] [--sessions]
                        [--json] [--output FILE] [--start-from TYPE]
                        [--url PATTERN] [--domain DOMAIN]
                        FILE
```

### Arguments

| Flag | Description |
|------|-------------|
| `FILE` | Path to a NetLog JSON file or ZIP archive (from `chrome://net-export`) |
| `-d`, `--domain` | **Analyze all connections for a specific domain.** Groups by name and same-site/cross-site relationship, showing local/remote address pairs. |
| `--summary` | Print source type breakdown and error counts |
| `--chains` | Print connection dependency chains (URL_REQUEST → TCP/TLS) |
| `--dns` | Print DNS resolver cache entries |
| `--sessions` | Print HTTP/2 and QUIC session reuse (multi-domain connections) |
| `--json` | Export parsed data as JSON |
| `--output`, `-o` | Write output to file instead of stdout |
| `--start-from` | Chain root type: `url_request` (default) or `socket` |
| `--url` | Filter chains by URL glob pattern (matches any chain member description) |

### Domain Analysis

The `--domain` / `-d` option is the core feature for investigating which connections a specific domain uses, whether they are same-site or cross-site, and what local/remote addresses are involved:

```bash
# Text output
python netlog_parser.py -d bilibili.com log.json
```

Example output:

```
  [SAME_SITE] https://www.bilibili.com
  Site:       https://bilibili.com
  Connections: 1
  Addresses:
    127.0.0.1:51891  ->  127.0.0.1:7890

  [CROSS_SITE] https://s1.hdslb.com
  Site:       https://bilibili.com
  Connections: 1
  Addresses:
    127.0.0.1:51924  ->  127.0.0.1:7890
```

JSON export for programmatic use:

```bash
python netlog_parser.py -d bilibili.com --json log.json
```

```json
[{
  "name": "https://www.bilibili.com",
  "site": "https://bilibili.com",
  "relation": "same_site",
  "connection_num": 1,
  "connection_detail": [
    {"local_address": "127.0.0.1:51891", "remote_address": "127.0.0.1:7890"}
  ]
}]
```

### URL Filtering

The `--url` option filters connection chains by a glob pattern. The pattern is matched against **any chain member's description** (URL_REQUEST, HTTP_STREAM_JOB, CONNECT_JOB, SOCKET, etc.):

```bash
# Show only bilibili-related chains
python netlog_parser.py --chains --url "*bilibili*" log.json

# Show only HTTPS requests
python netlog_parser.py --chains --url "https://*" log.json
```

### Chain Tracing Direction

By default chains are traced starting from `URL_REQUEST` entries (the high-level request). Use `--start-from socket` to trace from low-level socket entries instead:

```bash
python netlog_parser.py --chains --start-from socket log.json
```

## Output Sections

### Summary

Total sources, events, error counts, client info, and a breakdown by source type (URL_REQUEST, SOCKET, QUIC_SESSION, DNS_TRANSACTION, etc.).

### Connection Chains

Each chain traces a network request through its dependency graph:

```
-- Chain #1 --
  [URL_REQUEST      #113337]  https://www.bilibili.com/
  [HTTP_STREAM_JOB  #113345]  https://www.bilibili.com <https://bilibili.com same_site>
  [POOL_GROUP/JOB   #113343]  
  [CONNECT_JOB      #113346]  127.0.0.1:7890
  ------------------------------------------------------------
  Five-Tuple: (127.0.0.1:51891 -> 127.0.0.1:7890, HTTPS)
```

Nodes flagged with `[ERROR]` indicate a `net_error` was recorded. Nodes flagged with `(active)` indicate the operation had not completed when the log was captured. The Five-Tuple shows source and destination addresses extracted from SSL_CONNECT events.

### Domain Analysis

Groups all connections related to a target domain by name and site relationship (same_site / cross_site). Shows the number of unique connections and their local/remote address pairs. This is useful for:

- Understanding which subdomains share connections (connection coalescing)
- Identifying cross-site connection sharing
- Auditing proxy configuration (local addresses reveal proxy port usage)
- Debugging site isolation behavior

### DNS Resolver Cache

Lists cached DNS entries with addresses, TTL, and status (OK / EXPIRED / ERROR).

### Session Reuse

Shows HTTP/2 and QUIC sessions that served multiple domains (connection coalescing). Aliases indicate which additional hostnames were served over the same connection.

### JSON Export

The `--json` flag produces a structured document with sources, chains, DNS records, and session reuse data. When combined with `--domain`, it exports the domain analysis results instead.

## Programmatic API

You can call the domain analysis directly from Python code without going through the CLI:

```python
from parser.domain_analyzer import get_domain_connections

results = get_domain_connections("chrome-net-export-log.json", "bilibili.com")

# results is a plain list of dicts:
# [
#   {
#     "name": "https://www.bilibili.com",
#     "site": "https://bilibili.com",
#     "relation": "same_site",
#     "connection_num": 1,
#     "connection_detail": [
#       {"local_address": "127.0.0.1:51891", "remote_address": "127.0.0.1:7890"}
#     ]
#   },
#   ...
# ]

for item in results:
    print(f"[{item['relation']}] {item['name']}: {item['connection_num']} connections")
    for addr in item["connection_detail"]:
        print(f"  {addr['local_address']} -> {addr['remote_address']}")
```

If you already have parsed entries (e.g. to avoid re-parsing the same log for multiple domains), use the lower-level function:

```python
from parser.domain_analyzer import analyze_domain
from parser.event_processor import process_events
from parser.constants import NetLogConstants
import json

with open("log.json") as f:
    raw = json.load(f)

constants = NetLogConstants(raw.get("constants") or {})
entries = process_events(raw["events"], constants)

# Reuse `entries` for multiple domains without re-parsing
bilibili = analyze_domain(entries, "bilibili.com")
youtube = analyze_domain(entries, "youtube.com")
```

## Project Structure

```
netlog_parser.py              # CLI entry point
parser/
  __init__.py                 # Package marker
  constants.py                # Chromium source/event type constants (~85 named constants)
  source_entry.py             # Per-source event grouping and description extraction
  event_processor.py          # First-pass event grouping with dependency resolution
  dependency_graph.py         # Dependency chain tracing and five-tuple extraction
  dns_resolver.py             # DNS cache record extraction
  domain_analyzer.py          # Domain-level connection analysis (same-site/cross-site)
  output.py                   # Formatted output (summary, chains, DNS, domain, JSON)
test/
  test_parser.py              # Test suite
  sample_netlog.json          # Synthetic test data
```

## Capturing NetLogs

In Chromium/Chrome:

1. Navigate to `chrome://net-export`
2. Choose options (recommended: "Include cookies and credentials", "Strip private information")
3. Click **Start Logging to Disk**
4. Reproduce the network issue
5. Click **Stop Logging**
6. The log is saved as a JSON file or ZIP archive

## Running Tests

```bash
python test/test_parser.py
```
