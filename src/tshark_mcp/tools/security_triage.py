"""security_triage: scans, beacons, DNS tunnel hints, TLS fingerprints, ARP conflicts and cleartext
credentials (logic in :mod:`tshark_mcp.triage`)."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field
from typing_extensions import TypedDict

from .. import models, triage
from ..fields import field_catalogue
from ..limits import ToolError, clamp_limit, echo
from ..runner import check_result
from ..server import (READ_ONLY, _envelope, _fields_run, _guarded, _parse_capinfos, _parse_conversations, _resolve,
                      _tool, _window_clause, state)

Kinds = Annotated[list[str] | None, Field(
    description="Checks to run: scans, beacons, dns_tunnels, tls_fingerprints, arp, cleartext_credentials (default all)")]
Raw = Annotated[bool, Field(description="Also return JA4_r (the raw cipher and extension lists)")]


class TriageFinding(TypedDict, total=False):
    __pydantic_config__ = models._EXTRA_OK
    kind: str
    severity: str
    summary: str
    subject: dict[str, Any]
    evidence: dict[str, Any]


class SecurityTriageResult(models.RowsResult, total=False):
    findings: list[TriageFinding]
    kinds: list[str]
    scope: str
    verdict: str
    beacon_candidates: list[dict[str, Any]]
    tls_clients: list[dict[str, Any]]
    tls_servers: list[dict[str, Any]]
    dns_zones: list[dict[str, Any]]
    summary: dict[str, Any]
    notes: list[str]


def _known(fields: list[str], known: frozenset[str]) -> list[str]:
    return [f for f in fields if f in known]


def _padded(stdout: str, have: list[str], want: list[str]) -> list[dict[str, str]]:
    rows = triage.rows(stdout, have)
    return [{f: r.get(f, "") for f in want} for r in rows]


@_tool(title="Security triage: scans, beacons, DNS tunnels, JA4", annotations=READ_ONLY)
def security_triage(path: str, kinds: Kinds = None, raw: Raw = False, limit: int = 50,
                    offset: int = 0) -> SecurityTriageResult:
    """Is anything on this network scanning, beaconing, tunnelling over DNS, spoofing ARP or
    sending passwords in clear: `findings` ranked by severity, each with `kind` (port_scan,
    host_sweep, syn_flood, beacon, dns_tunnel_hint, rare_tls_client, arp_conflict,
    cleartext_credentials), `summary`, `subject` and `evidence` with frames. Also
    `beacon_candidates` (per client, server and service: count, interval median and MAD, Bowley
    skew, size statistics, `score`), `tls_clients` grouped by JA4 (JA3 when JA4 is missing) with
    hosts and SNIs, `tls_servers` by JA3S and `dns_zones`. `kinds` selects the checks.

    Details: Defensive triage only: no lookups, no attribution. Thresholds: 20 ports on one host
    or 20 hosts on one port from one source, 200 SYNs to one server port, 12 connections before a
    beacon score (RITA-style approximation: 0.45 interval, 0.35 size, 0.20 coverage), 30 distinct
    names under a zone with long or high-entropy labels. Credential values are never returned."""
    def run() -> dict[str, Any]:
        capture = _resolve(path)
        st = state()
        cap = clamp_limit(limit, st.limits.max_packets, 50)
        chosen = list(triage.KINDS) if not kinds else [str(k).strip().lower() for k in kinds]
        bad = [k for k in chosen if k not in triage.KINDS]
        if bad:
            raise ToolError("invalid_argument", f"unknown kind(s) {echo(bad)}; valid: {', '.join(triage.KINDS)}")
        known = field_catalogue(st.runner)
        notes: list[str] = []
        findings: list[dict[str, Any]] = []
        extra: dict[str, Any] = {}
        read = st.limits.max_scan_packets

        def fields_pass(flt: str, fields: list[str]) -> list[dict[str, str]]:
            have = _known(fields, known)
            stdout, scan = _fields_run(capture, flt, have, read, aggregator=triage.AGGREGATOR)
            if scan.truncated:
                notes.append(f"a pass stopped at a cap ({scan.reason()}): counts are lower bounds")
            return _padded(stdout, have, fields)

        starts: list[dict[str, Any]] = []
        if "scans" in chosen or "beacons" in chosen:
            scan_findings, starts = triage.scans(fields_pass(triage.TCP_FILTER, triage.TCP_FIELDS))
            if "scans" in chosen:
                findings += scan_findings
        sni_by_stream: dict[int, str] = {}
        if "tls_fingerprints" in chosen or "beacons" in chosen:
            if "tls.handshake.ja4" not in known:
                notes.append("this tshark has no JA4 field (added in 4.2.x/4.4): TLS clients are grouped by JA3")
            clients, servers, sni_by_stream = triage.tls_fingerprints(fields_pass(triage.TLS_FILTER, triage.TLS_FIELDS),
                                                                      bool(raw))
            if "tls_fingerprints" in chosen:
                extra["tls_clients"] = clients[:triage.TOP]
                extra["tls_servers"] = servers[:triage.TOP]
                findings += triage.rare_ja4_findings(clients)
        dns: list[dict[str, str]] = []
        if "dns_tunnels" in chosen or "beacons" in chosen:
            dns = fields_pass(triage.DNS_FILTER, triage.DNS_FIELDS)
        if "dns_tunnels" in chosen:
            zones = triage.dns_zones(dns)
            extra["dns_zones"] = zones[:triage.TOP]
            findings += triage.tunnel_findings(zones)
        if "beacons" in chosen:
            sizes = _connection_sizes(capture)
            series: dict[tuple[str, str, str], list[tuple[float, int | None, int | None]]] = {}
            for s in starts:
                service = sni_by_stream.get(s["stream"]) if s["stream"] is not None else None
                key = (s["client"], s["server"], f"tls {service}" if service else f"tcp/{s['port']}")
                size = sizes.get((f"{s['client']}:{s['sport']}", f"{s['server']}:{s['port']}"))
                series.setdefault(key, []).append((s["time"], size, s["frame"]))
            for r in dns:
                for name in r["dns.qry.name"].split(triage.AGGREGATOR)[:1]:
                    if name:
                        series.setdefault((triage._src(r), "dns", f"dns {name.lower()}"), []).append(
                            (float(r["frame.time_epoch"] or 0) or None, None, int(r["frame.number"] or 0)))
            candidates = triage.beacons(series, _span(capture))
            extra["beacon_candidates"] = [c for c in candidates if not c.get("insufficient_samples")][:triage.TOP]
            findings += triage.beacon_findings(candidates)
        if "arp" in chosen:
            findings += triage.arp_findings(fields_pass(triage.ARP_FILTER, triage.ARP_FIELDS))
        if "cleartext_credentials" in chosen:
            have = [f for f in triage.CRED_FIELDS if f in known]
            flt = " || ".join(c for c in triage.CRED_FILTER.split(" || ") if c.split(" ", 1)[0] in known)
            if flt:
                findings += triage.credential_findings(_padded(_fields_run(capture, flt, have, read,
                                                                           aggregator=triage.AGGREGATOR)[0],
                                                               have, triage.CRED_FIELDS))
        findings = triage.order(findings)
        by_kind: dict[str, int] = {}
        for f in findings:
            by_kind[f["kind"]] = by_kind.get(f["kind"], 0) + 1
        high = sum(1 for f in findings if f["severity"] == "high")
        verdict = (f"{len(findings)} finding(s), {high} high: " + ", ".join(f"{n} {k}" for k, n in sorted(by_kind.items()))
                   if findings else "no finding from the selected checks")
        if notes:
            extra["notes"] = notes
        return _envelope("findings", findings, cap, None, offset=offset, kinds=chosen, scope=triage.SCOPE,
                         verdict=verdict, summary={"by_kind": by_kind, "high": high}, **extra)
    return _guarded("security_triage", {"path": path, "kinds": kinds, "raw": raw, "limit": limit, "offset": offset}, run)


def _connection_sizes(capture: Any) -> dict[tuple[str, str], int]:
    """Bytes per TCP connection from ``-z conv,tcp``, keyed by (address:port, address:port) both ways."""
    win = _window_clause(capture)
    result = check_result(state().runner.read_capture(capture, ["-q", "-z", "conv,tcp" + (f",{win}" if win else "")],
                                                      stats_windowed=True))
    out: dict[tuple[str, str], int] = {}
    for r in _parse_conversations(result.stdout):
        out[(r["a"], r["b"])] = r["bytes_total"]
        out[(r["b"], r["a"])] = r["bytes_total"]
    return out


def _span(capture: Any) -> float | None:
    summary = state().runner.capinfos_summary(capture)
    if summary is None or summary.returncode != 0:
        return None
    info = _parse_capinfos(summary.stdout)
    first, last = info.get("first_packet_epoch"), info.get("last_packet_epoch")
    return (last - first) if isinstance(first, float) and isinstance(last, float) and last > first else None
