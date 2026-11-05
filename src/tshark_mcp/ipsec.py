"""IPsec visibility for the SIP and IMS tools (the Gm interface between UE and P-CSCF).

After IMS registration the UE and the P-CSCF protect SIP with IPsec ESP (TS 33.203). With
NULL encryption (RFC 2410, common in labs and some networks) the SIP is still readable, but
tshark only looks inside ESP when the preference
``esp.enable_null_encryption_decode_heuristic`` is on. A SIP tool called with
``esp_null=True`` runs every tshark pass with that preference; every SIP tool reports an
``ipsec`` block counting the ESP it could and could not read, so "no REGISTER seen" next to
encrypted ESP becomes "the SIP may be inside these ESP packets".

Real ESP decryption (keys in an ESP SA table) is out of scope: no keys are accepted.
"""

from __future__ import annotations

from typing import Any

from .fields import to_int

PREFERENCE = "esp.enable_null_encryption_decode_heuristic:TRUE"
PREFERENCES: tuple[str, ...] = (PREFERENCE,)
DISPLAY_FILTER = "esp"
FIELDS = ["frame.number", "esp.spi", "frame.protocols"]
MAX_SPIS = 8


def parse(stdout: str) -> list[dict[str, Any]]:
    """One record per ESP packet: frame, SPI (int or None) and whether tshark read past ESP."""
    out: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        cols += [""] * (len(FIELDS) - len(cols))
        spi_text = cols[1].split(",")[0].strip()
        spi = to_int(spi_text, None) if spi_text else None
        if spi is None and spi_text.lower().startswith("0x"):
            try:
                spi = int(spi_text, 16)
            except ValueError:
                spi = None
        layers = cols[2].split(":")
        inner = layers[layers.index("esp") + 1:] if "esp" in layers else []
        out.append({"frame": to_int(cols[0].strip(), None), "spi": spi, "decoded": bool(inner)})
    return out


def block(records: list[dict[str, Any]], esp_null: bool, rows_found: int | None) -> dict[str, Any] | None:
    """The ``ipsec`` result block, or None when the capture has no ESP and ``esp_null`` is off.

    ``rows_found`` is the number of rows the SIP tool found (None when unknown); the hint
    says the SIP may be inside the ESP only when the tool found nothing."""
    if not records and not esp_null:
        return None
    per_spi: dict[int | None, int] = {}
    for rec in records:
        per_spi[rec["spi"]] = per_spi.get(rec["spi"], 0) + 1
    decoded = sum(1 for r in records if r["decoded"])
    unreadable = len(records) - decoded
    ranked = sorted(((spi, n) for spi, n in per_spi.items() if spi is not None), key=lambda kv: (-kv[1], kv[0]))
    out: dict[str, Any] = {
        "esp_packets": len(records),
        "spis": [{"spi": f"0x{spi:08x}", "packets": n} for spi, n in ranked[:MAX_SPIS]],
        "decoded_null": decoded,
        "unreadable": unreadable,
        "esp_null": esp_null,
    }
    if len(ranked) > MAX_SPIS:
        out["spis_more"] = len(ranked) - MAX_SPIS
    first_unreadable = next((r["frame"] for r in records if not r["decoded"]), None)
    if first_unreadable is not None:
        out["first_unreadable_frame"] = first_unreadable
    spi_text = ", ".join(s["spi"] for s in out["spis"][:3]) or "unknown SPIs"
    if not records:
        out["hint"] = "esp_null=true was set but the capture has no ESP packets"
    elif unreadable and not esp_null:
        lead = "SIP may be inside" if not rows_found else "more SIP may be inside"
        out["hint"] = (f"{lead} {unreadable} ESP packet(s) on SPI {spi_text}, not readable as captured "
                       "(call again with esp_null=true if the security association uses NULL encryption)")
    elif unreadable:
        out["hint"] = (f"{unreadable} ESP packet(s) on SPI {spi_text} stay unreadable with esp_null=true: "
                       "that traffic is encrypted, and decryption keys are not accepted")
    elif decoded and esp_null:
        out["hint"] = f"all {decoded} ESP packet(s) carried NULL encryption and were read; their SIP is included"
    elif decoded:
        out["hint"] = f"tshark already read inside all {decoded} ESP packet(s)"
    return out
