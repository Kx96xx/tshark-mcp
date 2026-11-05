"""tls_certificates: the certificate chains servers sent, read from the handshakes tls.py rebuilds.

Every certificate of the chain is parsed from its DER bytes (no private key, no decryption, no
trust store): subject and issuer, SANs, validity, public key algorithm and size, signature
algorithm, basic constraints, SHA-256 fingerprint. Chains are grouped per server address and
port, SNI and leaf fingerprint. TLS 1.3 encrypts the Certificate message, so only TLS 1.2 and
older chains are visible; the count of TLS 1.3 connections skipped is reported.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any

from .fields import compact, iso, to_int
from .tls import _children, _tlv, name_covered, parse_certificate

SECONDS_PER_DAY = 86_400
EXPIRING_SOON_DAYS = 30
# Alerts a client sends when it does not accept the server's certificate.
REJECTION_ALERTS = {"bad_certificate", "unsupported_certificate", "certificate_revoked", "certificate_expired",
                    "certificate_unknown", "unknown_ca", "access_denied"}

_OID_BASIC_CONSTRAINTS = bytes.fromhex("551d13")
_KEY_ALGORITHMS = {
    bytes.fromhex("2a864886f70d010101"): "RSA", bytes.fromhex("2a8648ce3d0201"): "EC",
    bytes.fromhex("2b6570"): "Ed25519", bytes.fromhex("2b6571"): "Ed448", bytes.fromhex("2a8648ce380401"): "DSA",
}
_CURVES = {bytes.fromhex("2a8648ce3d030107"): ("P-256", 256), bytes.fromhex("2b81040022"): ("P-384", 384),
           bytes.fromhex("2b81040023"): ("P-521", 521)}
_SIGNATURES = {
    bytes.fromhex("2a864886f70d010104"): "md5WithRSAEncryption",
    bytes.fromhex("2a864886f70d010105"): "sha1WithRSAEncryption",
    bytes.fromhex("2a864886f70d01010b"): "sha256WithRSAEncryption",
    bytes.fromhex("2a864886f70d01010c"): "sha384WithRSAEncryption",
    bytes.fromhex("2a864886f70d01010d"): "sha512WithRSAEncryption",
    bytes.fromhex("2a864886f70d01010a"): "RSASSA-PSS",
    bytes.fromhex("2a8648ce3d0401"): "ecdsa-with-SHA1",
    bytes.fromhex("2a8648ce3d040302"): "ecdsa-with-SHA256",
    bytes.fromhex("2a8648ce3d040303"): "ecdsa-with-SHA384",
    bytes.fromhex("2a8648ce3d040304"): "ecdsa-with-SHA512",
    bytes.fromhex("2b6570"): "Ed25519",
}
WEAK_SIGNATURES = {"md5WithRSAEncryption", "sha1WithRSAEncryption", "ecdsa-with-SHA1"}
MIN_RSA_BITS = 2048


def _oid_of_algorithm(der: bytes, start: int, end: int) -> tuple[bytes, list[tuple[int, int, int]]]:
    parts = _children(der, start, end)
    return (der[parts[0][1]:parts[0][2]] if parts and parts[0][0] == 0x06 else b""), parts


def _key(der: bytes, start: int, end: int) -> dict[str, Any]:
    """Public key algorithm and size from a SubjectPublicKeyInfo."""
    alg, key_bits = _children(der, start, end)[:2]
    oid, parts = _oid_of_algorithm(der, alg[1], alg[2])
    name = _KEY_ALGORITHMS.get(oid, oid.hex() or None)
    out: dict[str, Any] = {"key_algorithm": name}
    if name == "RSA":
        body = der[key_bits[1] + 1:key_bits[2]]  # skip the unused-bits byte of the BIT STRING
        _, ms, me = _tlv(body, 0)
        modulus = _children(body, ms, me)[0]
        out["key_bits"] = int.from_bytes(body[modulus[1]:modulus[2]], "big").bit_length()
    elif name == "EC" and len(parts) > 1 and parts[1][0] == 0x06:
        curve = _CURVES.get(der[parts[1][1]:parts[1][2]])
        if curve:
            out["key_curve"], out["key_bits"] = curve
    elif name in ("Ed25519", "Ed448"):
        out["key_bits"] = 256 if name == "Ed25519" else 456
    return out


def parse_full(der: bytes) -> dict[str, Any] | None:
    """tls.parse_certificate plus key, signature algorithm, self-signed, CA flag, serial and fingerprint."""
    base = parse_certificate(der)
    if base is None:
        return None
    try:
        _, s, e = _tlv(der, 0)
        top = _children(der, s, e)
        tbs, sig_alg = top[0], top[1]
        items = _children(der, tbs[1], tbs[2])
        if items and items[0][0] == 0xA0:
            items = items[1:]
        serial, issuer, subject, spki = items[0], items[2], items[4], items[5]
        sig_oid, _ = _oid_of_algorithm(der, sig_alg[1], sig_alg[2])
        out = dict(base)
        out["issuer_dn"] = der[issuer[1]:issuer[2]].hex()
        out["subject_dn"] = der[subject[1]:subject[2]].hex()
        out["self_signed"] = out["issuer_dn"] == out["subject_dn"]
        out["signature_algorithm"] = _SIGNATURES.get(sig_oid, sig_oid.hex() or None)
        out["serial"] = der[serial[1]:serial[2]].hex()
        out["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()
        out.update(_key(der, spki[1], spki[2]))
        out["is_ca"] = False
        for tag, xs, _ in items[6:]:
            if tag != 0xA3:
                continue
            for _, es, ee in _children(der, *_tlv(der, xs)[1:]):
                parts = _children(der, es, ee)
                if parts and der[parts[0][1]:parts[0][2]] == _OID_BASIC_CONSTRAINTS:
                    _, bs, be = _tlv(der, parts[-1][1])
                    inner = _children(der, bs, be)
                    out["is_ca"] = bool(inner and inner[0][0] == 0x01 and der[inner[0][1]:inner[0][2]] != b"\x00")
        return out
    except (ValueError, IndexError):
        return base


def _view(cert: dict[str, Any], at: float | None, now: float | None) -> dict[str, Any]:
    san = (cert.get("san_dns") or [])[:20] + (cert.get("san_ip") or [])[:5]
    after = cert.get("not_after")
    row = {
        "subject_cn": cert.get("subject_cn"), "subject_o": cert.get("subject_o"),
        "issuer_cn": cert.get("issuer_cn"), "issuer_o": cert.get("issuer_o"),
        "san": san or None, "san_total": len(cert.get("san_dns") or []) + len(cert.get("san_ip") or []) or None,
        "not_before": iso(cert.get("not_before")), "not_after": iso(after),
        "days_left": round((after - at) / SECONDS_PER_DAY, 1) if after is not None and at is not None else None,
        "days_left_now": round((after - now) / SECONDS_PER_DAY, 1) if after is not None and now is not None else None,
        "key_algorithm": cert.get("key_algorithm"), "key_bits": cert.get("key_bits"), "key_curve": cert.get("key_curve"),
        "signature_algorithm": cert.get("signature_algorithm"),
        "self_signed": cert.get("self_signed") or None, "is_ca": cert.get("is_ca") or None,
        "wildcard": any(n.startswith("*.") for n in cert.get("san_dns") or []) or None,
        "serial": cert.get("serial"), "fingerprint_sha256": cert.get("fingerprint_sha256"),
    }
    return compact(row)


def chains(conns: list[dict[str, Any]], rows: list[dict[str, Any]], now: float | None) -> dict[str, Any]:
    """Group the connections that carried a Certificate message into chains."""
    by_key = {(c["transport"], to_int(c["stream"])): c for c in conns}
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    tls13 = without_cert = 0
    versions: Counter = Counter()
    for row in rows:
        conn = by_key.get((row["transport"], row.get("stream")))
        if conn is None or row["transport"] != "tcp":
            continue
        version = (row.get("chosen") or {}).get("version")
        if version:
            versions[version] += 1
        chain_hex = conn.get("chain") or []
        if not chain_hex:
            if version == "TLS 1.3":
                tls13 += 1
            elif row.get("chosen"):
                without_cert += 1
            continue
        try:
            ders = [bytes.fromhex(h.replace(":", "")) for h in chain_hex]
        except ValueError:
            continue
        parsed = [parse_full(d) for d in ders]
        leaf = parsed[0]
        if leaf is None:
            continue
        sni = row.get("sni") or ""
        key = (row["server"], sni, leaf["fingerprint_sha256"])
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"server": row["server"], "sni": sni or None, "parsed": parsed, "connections": 0,
                               "frames": [], "first_time": None, "rejected": 0, "rejected_frames": [],
                               "stapled": 0, "versions": Counter(), "alerts": Counter()}
        g["connections"] += 1
        if len(g["frames"]) < 5 and row.get("frame") is not None:
            g["frames"].append(row["frame"])
        at = conn["hellos"][0]["time"] if conn["hellos"] and conn["hellos"][0].get("time") else conn.get("first")
        if at is not None and (g["first_time"] is None or at < g["first_time"]):
            g["first_time"] = at
        if conn.get("ocsp_stapled"):
            g["stapled"] += 1
        if version:
            g["versions"][version] += 1
        for a in row.get("alerts") or []:
            g["alerts"][f"{a['from']}: {a['description']}"] += 1
        client_alerts = {a["description"] for a in row.get("alerts") or [] if a["from"] == "client"}
        if client_alerts & REJECTION_ALERTS or row.get("outcome") == "client_rejected_likely":
            g["rejected"] += 1
            if len(g["rejected_frames"]) < 5:
                g["rejected_frames"].append(row.get("frame"))
    out_rows = [_chain_row(g, now) for g in groups.values()]
    out_rows.sort(key=lambda r: (not r.get("issues"), r.get("frames", [0])[0] if r.get("frames") else 0))
    return {"chains": out_rows, "tls13_connections_skipped": tls13, "connections_without_certificate": without_cert,
            "versions": dict(versions)}


def _chain_row(g: dict[str, Any], now: float | None) -> dict[str, Any]:
    parsed = g["parsed"]
    leaf = parsed[0]
    at = g["first_time"]
    sent = [c for c in parsed if c is not None]
    subjects = {c["subject_dn"] for c in sent if c.get("subject_dn")}
    order_ok = all(
        parsed[i] is not None and parsed[i + 1] is not None and parsed[i].get("issuer_dn") == parsed[i + 1].get("subject_dn")
        for i in range(len(parsed) - 1))
    missing = not leaf.get("self_signed") and leaf.get("issuer_dn") not in subjects
    expired = leaf.get("not_after") is not None and at is not None and leaf["not_after"] < at
    not_yet = leaf.get("not_before") is not None and at is not None and leaf["not_before"] > at
    sni = g["sni"]
    row: dict[str, Any] = {
        "server": g["server"], "sni": sni, "leaf": _view(leaf, at, now),
        "intermediates": [compact({"subject_cn": c.get("subject_cn"), "issuer_cn": c.get("issuer_cn"),
                                   "not_after": iso(c.get("not_after")), "signature_algorithm": c.get("signature_algorithm"),
                                   "is_ca": c.get("is_ca"), "self_signed": c.get("self_signed") or None})
                          if c is not None else {"unreadable": True} for c in parsed[1:]] or None,
        "chain_length": len(parsed), "order_ok": order_ok, "missing_intermediate": missing,
        "self_signed": bool(leaf.get("self_signed")), "expired": expired, "not_yet_valid": not_yet or None,
        "name_matches": name_covered(sni, leaf) if sni else None,
        "ocsp_stapled": g["stapled"] > 0, "connections": g["connections"], "frames": g["frames"],
        "tls_versions": dict(g["versions"]) or None, "alerts": dict(g["alerts"]) or None,
        "clients_rejected": g["rejected"] or None, "rejected_frames": g["rejected_frames"] or None,
    }
    row["issues"] = _issues(row, parsed, at)
    return compact(row)


def _issues(row: dict[str, Any], parsed: list[dict[str, Any] | None], at: float | None) -> list[str]:
    leaf = row["leaf"]
    who = row["sni"] or row["server"]
    out = []
    if row["expired"]:
        out.append(f"{who}: certificate expired {leaf.get('not_after')}, before the handshake")
    elif row.get("not_yet_valid"):
        out.append(f"{who}: certificate not valid until {leaf.get('not_before')}")
    elif leaf.get("days_left") is not None and leaf["days_left"] < EXPIRING_SOON_DAYS:
        out.append(f"{who}: certificate expires in {leaf['days_left']} days ({leaf.get('not_after')})")
    if row.get("name_matches") is False:
        out.append(f"{who}: the certificate does not name {row['sni']} (SAN/CN mismatch; it names "
                   f"{', '.join((leaf.get('san') or [leaf.get('subject_cn') or '?'])[:3])})")
    if row["self_signed"]:
        out.append(f"{who}: the certificate is self-signed; clients that do not pin it reject it")
    if row["missing_intermediate"]:
        out.append(f"{who}: the server sent {row['chain_length']} certificate(s) and none issued the leaf "
                   f"(issuer {leaf.get('issuer_cn') or '?'}): clients without that intermediate cached fail")
    if not row["order_ok"]:
        out.append(f"{who}: the chain is out of order (each certificate should be issued by the next one)")
    for i, c in enumerate(parsed):
        if c is None:
            continue
        sig = c.get("signature_algorithm")
        if sig in WEAK_SIGNATURES and not (i and c.get("self_signed")):
            what = "leaf" if i == 0 else f"intermediate {c.get('subject_cn') or i}"
            out.append(f"{who}: {what} is signed with {sig}, which clients reject")
        if c.get("key_algorithm") == "RSA" and (c.get("key_bits") or MIN_RSA_BITS) < MIN_RSA_BITS:
            out.append(f"{who}: {'leaf' if i == 0 else 'intermediate'} has a {c['key_bits']}-bit RSA key")
        if i and c.get("not_after") is not None and at is not None and c["not_after"] < at:
            out.append(f"{who}: intermediate {c.get('subject_cn') or i} expired {iso(c['not_after'])}")
    if row.get("clients_rejected"):
        out.append(f"{who}: {row['clients_rejected']} of {row['connections']} connections were refused by the client "
                   "after this certificate")
    return out


def summary(result: dict[str, Any]) -> dict[str, Any]:
    rows = result["chains"]
    return compact({
        "chains": len(rows), "connections": sum(r["connections"] for r in rows),
        "expired": sum(1 for r in rows if r.get("expired")),
        "expiring_within_30_days": sum(1 for r in rows if not r.get("expired") and (r["leaf"].get("days_left") or 1e9)
                                       < EXPIRING_SOON_DAYS),
        "self_signed": sum(1 for r in rows if r.get("self_signed")),
        "name_mismatch": sum(1 for r in rows if r.get("name_matches") is False),
        "missing_intermediate": sum(1 for r in rows if r.get("missing_intermediate")),
        "weak_signature": sum(1 for r in rows if any("signed with" in i for i in r.get("issues", []))),
        "tls13_connections_skipped": result["tls13_connections_skipped"],
        "connections_without_certificate": result["connections_without_certificate"] or None,
        "versions": result["versions"] or None,
    })

