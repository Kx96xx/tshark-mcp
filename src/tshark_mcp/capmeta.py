"""capture_metadata: what the capture file says about itself, read without tshark.

tshark exposes no field for the pcapng Interface Statistics Block, and capinfos does
not print its drop counters, so this module walks the pcapng block headers in pure
Python: Section Header (writer application, OS, hardware, comment), Interface
Description (name, description, link type, snaplen, timestamp resolution and offset,
capture filter), Interface Statistics (packets received, dropped by the interface,
dropped by the OS, accepted by the filter, delivered) and the packet blocks, of which
only the 20-byte header (interface, timestamp, captured and original length) and the
options after the packet data (comments) are read. Packet bytes are skipped with a
seek and never decoded.

The walk is bounded by the file size cap the allowlist enforces, by a wall-clock
deadline and by a cap on the blocks visited; a damaged block ends the walk with a
warning, as tshark does. A legacy pcap file has no such metadata: the header (version,
snaplen, link type, timestamp precision) is returned with ``metadata_available:
false``. A gzip-compressed pcapng is walked through a decompressing reader; other
compressions are reported and not walked.
"""

from __future__ import annotations

import gzip
import struct
import time
from pathlib import Path
from typing import Any, BinaryIO

from .fields import compact, iso

SHB, IDB, PB_OBSOLETE, SPB, NRB, ISB, EPB = 0x0A0D0D0A, 1, 2, 3, 4, 5, 6
BYTE_ORDER_MAGIC = 0x1A2B3C4D
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", "microsecond"), b"\xa1\xb2\xc3\xd4": (">", "microsecond"),
    b"\x4d\x3c\xb2\xa1": ("<", "nanosecond"), b"\xa1\xb2\x3c\x4d": (">", "nanosecond"),
}
# LINKTYPE_* values from the pcap link-type registry, the ones seen in practice.
LINK_TYPES = {
    0: "NULL", 1: "ETHERNET", 101: "RAW", 105: "IEEE802_11", 113: "LINUX_SLL", 127: "IEEE802_11_RADIOTAP",
    228: "IPV4", 229: "IPV6", 276: "LINUX_SLL2", 12: "RAW", 14: "RAW", 9: "PPP", 104: "C_HDLC", 108: "LOOP",
    141: "MTP3", 147: "USER0", 192: "PPI", 249: "NETANALYZER", 252: "WIRESHARK_UPPER_PDU", 263: "ERF",
}
MAX_TEXT = 512
MAX_COMMENTS = 5
SMALL_SNAPLEN = 256


class _Damaged(Exception):
    pass


def _open(path: Path) -> tuple[BinaryIO, bool, str | None]:
    """(reader, gzip-compressed, other compression name or None)."""
    with path.open("rb") as fh:
        head = fh.read(4)
    if head[:2] == b"\x1f\x8b":
        return gzip.open(path, "rb"), True, None  # type: ignore[return-value]
    if head == b"\x28\xb5\x2f\xfd":
        return path.open("rb"), False, "zstd"
    if head == b"\x04\x22\x4d\x18":
        return path.open("rb"), False, "lz4"
    return path.open("rb"), False, None


def _text(raw: bytes) -> str:
    text = raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")
    return text[:MAX_TEXT]


def _options(body: bytes, bo: str) -> list[tuple[int, bytes]]:
    out = []
    i = 0
    while i + 4 <= len(body):
        code, length = struct.unpack_from(bo + "HH", body, i)
        i += 4
        if code == 0:
            break
        out.append((code, body[i:i + length]))
        i += length + (-length % 4)
    return out


def _tsresol(value: int) -> float:
    return 2.0 ** -(value & 0x7F) if value & 0x80 else 10.0 ** -value


def read(path: Path, deadline_s: float, max_blocks: int) -> dict[str, Any]:
    """Walk ``path`` and return the metadata (see the module docstring)."""
    reader, gz, other = _open(path)
    with reader:
        head = reader.read(24)
        if other:
            return {"file": {"format": "unknown", "compressed": other, "size_bytes": path.stat().st_size},
                    "metadata_available": False,
                    "note": f"{other}-compressed file: decompress it to read its metadata"}
        if head[:4] in PCAP_MAGICS:
            return _pcap(head, path, gz)
        if len(head) < 12 or struct.unpack("<I", head[:4])[0] != SHB:
            return {"file": {"format": "unknown", "compressed": "gzip" if gz else None, "size_bytes": path.stat().st_size},
                    "metadata_available": False, "note": "not a pcap or pcapng file"}
        reader.seek(0)
        return _walk(reader, path, gz, deadline_s, max_blocks)


def _pcap(head: bytes, path: Path, gz: bool) -> dict[str, Any]:
    bo, precision = PCAP_MAGICS[head[:4]]
    major, minor, _zone, _sig, snaplen, network = struct.unpack(bo + "HHiIII", head[4:24])
    link = network & 0x0FFFFFFF
    return {
        "file": compact({"format": "pcap", "version": f"{major}.{minor}", "byte_order": "little" if bo == "<" else "big",
                         "compressed": "gzip" if gz else None, "size_bytes": path.stat().st_size,
                         "timestamp_precision": precision}),
        "metadata_available": False,
        "interfaces": [compact({"id": 0, "link_type": link, "link_type_name": LINK_TYPES.get(link), "snaplen": snaplen})],
        "note": "legacy pcap: no writer, interface names, capture filter or drop counters are stored in this format",
    }


def _walk(reader: BinaryIO, path: Path, gz: bool, deadline_s: float, max_blocks: int) -> dict[str, Any]:
    started = time.monotonic()
    sections: list[dict[str, Any]] = []
    interfaces: list[dict[str, Any]] = []
    section_ifaces: list[int] = []  # global interface ids of the current section
    comments: list[dict[str, Any]] = []
    comment_count = 0
    packets = 0
    blocks = 0
    bo = "<"
    warnings: list[str] = []
    stopped = None
    offset = 0
    try:
        while True:
            hdr = reader.read(8)
            if not hdr:
                break
            if len(hdr) < 8:
                raise _Damaged(f"the file ends inside a block header at byte {offset}")
            btype_le = struct.unpack("<I", hdr[:4])[0]
            if btype_le == SHB:
                magic = reader.read(4)
                if len(magic) < 4:
                    raise _Damaged(f"the file ends inside a section header at byte {offset}")
                bo = "<" if struct.unpack("<I", magic)[0] == BYTE_ORDER_MAGIC else ">"
                total = struct.unpack(bo + "I", hdr[4:8])[0]
                if total < 28 or total % 4:
                    raise _Damaged(f"bad section header length {total} at byte {offset}")
                body = magic + _read(reader, total - 16, offset)
                _trailer(reader, bo, total, offset)
                major, minor = struct.unpack_from(bo + "HH", body, 4)
                sec: dict[str, Any] = {"index": len(sections), "version": f"{major}.{minor}",
                                       "byte_order": "little" if bo == "<" else "big"}
                writer: dict[str, Any] = {}
                for code, value in _options(body[16:], bo):
                    if code == 1:
                        writer.setdefault("comment", _text(value))
                    elif code == 2:
                        writer["hardware"] = _text(value)
                    elif code == 3:
                        writer["os"] = _text(value)
                    elif code == 4:
                        writer["application"] = _text(value)
                sec["writer"] = writer or None
                sections.append(sec)
                section_ifaces = []
                offset += total
                continue
            btype, total = struct.unpack(bo + "II", hdr)
            if total < 12 or total % 4:
                raise _Damaged(f"bad block length {total} at byte {offset}")
            blocks += 1
            if btype in (EPB, PB_OBSOLETE):
                packets += 1
                fixed = _read(reader, 20, offset)
                if btype == EPB:
                    iface_local, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(bo + "IIIII", fixed)
                else:
                    iface_local, _drops, ts_hi, ts_lo, cap_len, orig_len = struct.unpack(bo + "HHIIII", fixed)
                data_len = cap_len + (-cap_len % 4)
                opt_len = total - 32 - data_len
                if opt_len < 0:
                    raise _Damaged(f"packet block at byte {offset} claims {cap_len} bytes in a {total}-byte block")
                _skip(reader, data_len, offset)
                opts = _read(reader, opt_len, offset) if opt_len else b""
                _trailer(reader, bo, total, offset)
                iface = _iface(interfaces, section_ifaces, iface_local, offset)
                ts = (ts_hi << 32 | ts_lo) * iface["_resol"] + iface["_tsoffset"]
                _count(iface, ts, cap_len, orig_len)
                for code, value in _options(opts, bo):
                    if code == 1:
                        comment_count += 1
                        if len(comments) < MAX_COMMENTS:
                            comments.append({"frame": packets, "comment": _text(value)})
            elif btype == SPB:
                packets += 1
                orig_len = struct.unpack(bo + "I", _read(reader, 4, offset))[0]
                _skip(reader, total - 16, offset)
                _trailer(reader, bo, total, offset)
                iface = _iface(interfaces, section_ifaces, 0, offset)
                cap = min(orig_len, iface.get("snaplen") or orig_len, total - 16)
                _count(iface, None, cap, orig_len)
            elif btype == IDB:
                body = _read(reader, total - 12, offset)
                _trailer(reader, bo, total, offset)
                link, _res, snaplen = struct.unpack_from(bo + "HHI", body, 0)
                iface = {"id": len(interfaces), "section": len(sections) - 1, "link_type": link,
                         "link_type_name": LINK_TYPES.get(link), "snaplen": snaplen or None,
                         "_resol": 1e-6, "_tsoffset": 0, "packets": 0, "_bytes": 0, "_first": None, "_last": None,
                         "_truncated": 0, "_backwards": 0}
                for code, value in _options(body[8:], bo):
                    if code == 2:
                        iface["name"] = _text(value)
                    elif code == 3:
                        iface["description"] = _text(value)
                    elif code == 9 and value:
                        iface["_resol"] = _tsresol(value[0])
                        iface["timestamp_resolution"] = _resol_text(value[0])
                    elif code == 11 and value:
                        iface["capture_filter"] = _text(value[1:] if value[0] == 0 else value)
                    elif code == 14 and len(value) >= 8:
                        iface["_tsoffset"] = struct.unpack(bo + "q", value[:8])[0]
                        iface["timestamp_offset_s"] = iface["_tsoffset"]
                    elif code == 13 and value:
                        iface["fcs_length"] = value[0]
                    elif code == 8 and len(value) >= 8:
                        iface["speed_bps"] = struct.unpack(bo + "Q", value[:8])[0]
                interfaces.append(iface)
                section_ifaces.append(iface["id"])
            elif btype == ISB:
                body = _read(reader, total - 12, offset)
                _trailer(reader, bo, total, offset)
                iface_local, ts_hi, ts_lo = struct.unpack_from(bo + "III", body, 0)
                iface = _iface(interfaces, section_ifaces, iface_local, offset)
                stats: dict[str, Any] = {"timestamp": iso((ts_hi << 32 | ts_lo) * iface["_resol"] + iface["_tsoffset"])}
                names = {2: "start", 3: "end", 4: "received", 5: "dropped_by_interface", 6: "accepted_by_filter",
                         7: "dropped_by_os", 8: "delivered"}
                for code, value in _options(body[12:], bo):
                    if code in names and len(value) >= 8:
                        n = struct.unpack(bo + "Q", value[:8])[0]
                        if code in (2, 3):
                            hi, lo = struct.unpack(bo + "II", value[:8])
                            stats[names[code]] = iso((hi << 32 | lo) * iface["_resol"] + iface["_tsoffset"])
                        else:
                            stats[names[code]] = n
                    elif code == 1:
                        stats["comment"] = _text(value)
                iface["statistics"] = stats  # the last ISB holds the totals at the end of the capture
                iface["_isbs"] = iface.get("_isbs", 0) + 1
            else:
                _skip(reader, total - 12, offset)
            offset += total
            if blocks >= max_blocks:
                stopped = f"block cap reached: only the first {max_blocks} blocks were read"
                break
            if time.monotonic() - started > deadline_s:
                stopped = f"time budget of {deadline_s} s used up after {blocks} blocks"
                break
    except _Damaged as exc:
        warnings.append(f"{exc}: the file was read up to there")
    return _result(path, gz, sections, interfaces, comments, comment_count, packets, warnings, stopped)


def _read(reader: BinaryIO, n: int, offset: int) -> bytes:
    data = reader.read(n)
    if len(data) < n:
        raise _Damaged(f"the file ends inside the block at byte {offset}")
    return data


def _skip(reader: BinaryIO, n: int, offset: int) -> None:
    if n <= 0:
        return
    if isinstance(reader, gzip.GzipFile):
        _read(reader, n, offset)
        return
    here = reader.tell()
    reader.seek(n, 1)
    if reader.tell() != here + n:
        raise _Damaged(f"the file ends inside the block at byte {offset}")


def _trailer(reader: BinaryIO, bo: str, total: int, offset: int) -> None:
    trailer = _read(reader, 4, offset)
    if struct.unpack(bo + "I", trailer)[0] != total:
        raise _Damaged(f"the block at byte {offset} has a trailing length that does not match its header")


def _resol_text(value: int) -> str:
    if value & 0x80:
        return f"2^-{value & 0x7F} s"
    names = {6: "microsecond", 9: "nanosecond", 3: "millisecond", 0: "second"}
    return names.get(value, f"10^-{value} s")


def _iface(interfaces: list[dict[str, Any]], section_ifaces: list[int], local: int, offset: int) -> dict[str, Any]:
    if local >= len(section_ifaces):
        raise _Damaged(f"a block at byte {offset} names interface {local}, which its section does not describe")
    return interfaces[section_ifaces[local]]


def _count(iface: dict[str, Any], ts: float | None, cap_len: int, orig_len: int) -> None:
    iface["packets"] += 1
    iface["_bytes"] += orig_len
    if cap_len < orig_len:
        iface["_truncated"] += 1
    if ts is not None:
        if iface["_last"] is not None and ts < iface["_last"]:
            iface["_backwards"] += 1
        iface["_first"] = ts if iface["_first"] is None else min(iface["_first"], ts)
        iface["_last"] = ts if iface["_last"] is None else max(iface["_last"], ts)


def _result(path: Path, gz: bool, sections: list[dict[str, Any]], interfaces: list[dict[str, Any]],
            comments: list[dict[str, Any]], comment_count: int, packets: int, warnings: list[str],
            stopped: str | None) -> dict[str, Any]:
    issues: list[str] = []
    rows = []
    drops_total = 0
    for iface in interfaces:
        label = f"interface {iface['id']}" + (f" ({iface['name']})" if iface.get("name") else "")
        stats = iface.get("statistics") or {}
        if_drop, os_drop = stats.get("dropped_by_interface") or 0, stats.get("dropped_by_os") or 0
        drops_total += if_drop + os_drop
        if if_drop or os_drop:
            parts = []
            if if_drop:
                parts.append(f"{if_drop} dropped by the interface or capture buffer")
            if os_drop:
                parts.append(f"{os_drop} dropped by the operating system")
            issues.append(f"{label} reports {' and '.join(parts)}"
                          + (f" out of {stats['received']} received" if stats.get("received") else "")
                          + ": the capture is missing packets, so read loss with capture_quality before blaming the network")
        snaplen = iface.get("snaplen")
        if snaplen and snaplen <= SMALL_SNAPLEN:
            issues.append(f"{label} was captured with snaplen {snaplen}: headers only, payload analysis is impossible")
        if iface["_truncated"]:
            issues.append(f"{label}: {iface['_truncated']} packets were cut to the snapshot length")
        if iface.get("capture_filter"):
            issues.append(f"{label} was captured with the filter '{iface['capture_filter']}': traffic it excluded is "
                          "not in the file, so absence proves nothing outside it")
        if iface["_backwards"]:
            issues.append(f"{label}: timestamps go backwards {iface['_backwards']} times")
        row = {k: v for k, v in iface.items() if not k.startswith("_")}
        row["bytes"] = iface["_bytes"]
        row["first"], row["last"] = iso(iface["_first"]), iso(iface["_last"])
        row["truncated_packets"] = iface["_truncated"] or None
        row["timestamps_backwards"] = iface["_backwards"] or None
        row["statistics_blocks"] = iface.get("_isbs")
        rows.append(compact(row))
    firsts = [(i["id"], i["_first"]) for i in interfaces if i["_first"] is not None]
    if len(firsts) > 1:
        base_id, base = firsts[0]
        for iid, first in firsts[1:]:
            row = next(r for r in rows if r["id"] == iid)
            row["first_packet_after_interface_0_s"] = round(first - base, 6)
    if interfaces and not any(i.get("statistics") for i in interfaces):
        issues.append("no interface statistics block: the writer did not record drop counters (dumpcap writes them when "
                      "it stops cleanly; a killed capture or an editcap/mergecap rewrite may lose them), so capture drops "
                      "are unknown")
    if len(sections) > 1:
        issues.append(f"{len(sections)} sections: several captures were concatenated into this file")
    out: dict[str, Any] = {
        "file": compact({"format": "pcapng", "version": sections[0]["version"] if sections else None,
                         "byte_order": sections[0]["byte_order"] if sections else None,
                         "compressed": "gzip" if gz else None, "size_bytes": path.stat().st_size,
                         "sections": len(sections)}),
        "metadata_available": True,
        "sections": [compact({"index": s["index"], "version": s["version"], "writer": s.get("writer")}) for s in sections],
        "writer": (sections[0].get("writer") if sections else None) or None,
        "interfaces": rows,
        "packets": packets,
        "drops_total": drops_total if any(i.get("statistics") for i in interfaces) else None,
        "packet_comments": {"count": comment_count, "first": comments} if comment_count else None,
        "issues": issues,
    }
    if warnings:
        out["read_warnings"] = warnings
    if stopped:
        out["truncated"] = True
        out["truncated_reason"] = stopped
    return compact(out)
