#!/usr/bin/env python3
"""Read-only NetLog/PCAP equivalence benchmark; outputs live only in temp files."""

import argparse
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

from traffictracer.analyze.cdp_attribution import parse_cdp_attribution
from traffictracer.analyze.netlog_transport import trace_transport
from traffictracer.analyze.pcap_batch import BatchExtraction


@contextmanager
def eager(path, checkpoint):
    checkpoint()
    with open(path, encoding="utf-8") as stream:
        data = json.load(stream)
    yield data.get("constants") or {}, iter(data.get("events") or [])


def netlog(raw, mode):
    requests = parse_cdp_attribution(str(raw / "cdp.json"))
    started = time.monotonic()
    if mode == "eager":
        with patch("parser.netlog_reader.open_netlog", eager):
            connections = trace_transport(requests, str(raw / "netlog.json"))
    else:
        connections = trace_transport(requests, str(raw / "netlog.json"))
    digest = hashlib.sha256(json.dumps([asdict(c) for c in connections], sort_keys=True).encode()).hexdigest()
    print(json.dumps(dict(mode=mode, seconds=time.monotonic() - started,
                         peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                         connections=len(connections), sha256=digest)))


def packet_signature(path):
    # Ordered wire-visible fields and timestamps. Synthetic regression tests
    # additionally compare raw packet bytes (jsonraw) to the ordinary dumper.
    with tempfile.TemporaryFile() as output:
        subprocess.run(["tshark", "-r", str(path), "-T", "fields",
                        "-e", "frame.time_epoch", "-e", "frame.len", "-e", "frame.cap_len",
                        "-e", "ip.src", "-e", "ip.dst", "-e", "ipv6.src", "-e", "ipv6.dst",
                        "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.seq_raw",
                        "-e", "udp.srcport", "-e", "udp.dstport"],
                       stdout=output, stderr=subprocess.DEVNULL, check=True)
        output.seek(0)
        digest = hashlib.sha256()
        for chunk in iter(lambda: output.read(65536), b""):
            digest.update(chunk)
        return digest.hexdigest()


def pcaps(raw):
    filters = ["tcp", "udp", "tcp.port == 443", "udp.port == 443"]
    for name in ("tun.pcap", "phys.pcap"):
        source = str(raw / name)
        with BatchExtraction() as batch, tempfile.TemporaryDirectory(prefix="tt-pcap-reference-") as directory:
            started = time.monotonic()
            batch.prepare(source, filters)
            batch_seconds = time.monotonic() - started
            if len(batch.cache) != len(filters):
                raise RuntimeError("batch not supported; ordinary extraction fallback required")
            reference_seconds = 0
            for index, expression in enumerate(filters):
                reference = Path(directory) / f"{index}.pcapng"
                started = time.monotonic()
                subprocess.run(["tshark", "-r", source, "-Y", expression, "-w", str(reference)],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                reference_seconds += time.monotonic() - started
                actual, metrics = batch.cache[(source, expression)]
                if metrics[0]:
                    assert packet_signature(actual) == packet_signature(reference), (name, expression)
                else:
                    from traffictracer.analyze.pcap_metrics import classic_pcap_metrics
                    assert classic_pcap_metrics(reference) == (0, 0)
            print(json.dumps(dict(pcap=name, filters=len(filters), batch_seconds=batch_seconds,
                                  reference_seconds=reference_seconds, equivalent=True)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw", type=Path)
    parser.add_argument("--mode", choices=["stream", "eager", "pcap", "all"], default="all")
    args = parser.parse_args()
    if args.mode in {"stream", "eager"}:
        netlog(args.raw, args.mode)
    elif args.mode == "pcap":
        pcaps(args.raw)
    else:
        results = []
        for mode in ("eager", "stream"):
            output = subprocess.check_output([sys.executable, __file__, str(args.raw), "--mode", mode], text=True)
            result = json.loads(output)
            results.append(result)
            print(json.dumps(result), flush=True)
        assert results[0]["sha256"] == results[1]["sha256"], "NetLog semantic mismatch"
        pcaps(args.raw)
