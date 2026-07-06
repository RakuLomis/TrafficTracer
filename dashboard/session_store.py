"""Session discovery from filesystem output directories."""

from pathlib import Path
import json
import os


def list_sessions(base_dir: str) -> list[dict]:
    """Scan output directory and return all sessions sorted newest first."""
    base = Path(base_dir)
    if not base.exists():
        return []
    sessions = []
    for d in sorted(base.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        sid = d.name
        stats = _session_stats(d)
        status = _session_status(d, stats)
        sessions.append({
            "id": sid,
            "path": str(d),
            "status": status,
            "stats": stats,
        })
    return sessions


def get_session(base_dir: str, session_id: str) -> dict | None:
    """Get a single session with correlation data."""
    d = Path(base_dir) / session_id
    if not d.exists():
        return None
    stats = _session_stats(d)
    status = _session_status(d, stats)
    correlation = None
    corr_path = d / "results" / "correlation.json"
    if corr_path.exists():
        try:
            with open(corr_path) as f:
                correlation = json.load(f)
        except Exception:
            pass
    return {
        "id": session_id,
        "path": str(d),
        "status": status,
        "stats": stats,
        "correlation": correlation,
    }


def _session_stats(d: Path) -> dict:
    """Collect file sizes and flow counts for a session."""
    stats = {"tun_pcap_bytes": 0, "phys_pcap_bytes": 0, "netlog_bytes": 0, "trace_bytes": 0, "total_flows": 0, "subdomains": []}
    caps_dir = d / "captures"
    logs_dir = d / "logs"

    for domain_dir in caps_dir.glob("*"):
        if domain_dir.is_dir():
            tun = domain_dir / "tun.pcap"
            phys = domain_dir / "phys.pcap"
            if tun.exists():
                stats["tun_pcap_bytes"] += tun.stat().st_size
            if phys.exists():
                stats["phys_pcap_bytes"] += phys.stat().st_size
            flows_dir = domain_dir / "flows"
            if flows_dir.exists():
                for subdomain_dir in flows_dir.glob("*/*"):
                    if subdomain_dir.is_dir():
                        stats["total_flows"] += 1
                        stats["subdomains"].append(subdomain_dir.name)
                        break
                for subdomain_dir in flows_dir.glob("*/*"):
                    if subdomain_dir.is_dir() and subdomain_dir.name not in stats["subdomains"]:
                        stats["subdomains"].append(subdomain_dir.name)

    if logs_dir.exists():
        for f in logs_dir.glob("netlog_*.json"):
            stats["netlog_bytes"] += f.stat().st_size
        for f in logs_dir.glob("mihomo_trace_*.jsonl"):
            stats["trace_bytes"] += f.stat().st_size

    stats["subdomains"] = list(set(stats["subdomains"]))
    return stats


def _session_status(d: Path, stats: dict) -> str:
    """Determine session status."""
    if (d / "results" / "correlation.json").exists():
        return "analyzed"
    if any((d / "logs").glob("*.json*")):
        return "captured"
    caps = d / "captures"
    if caps.exists() and any(caps.glob("*/*.pcap")):
        return "captured"
    return "empty"
