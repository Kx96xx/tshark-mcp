"""Pseudonymise subscriber identifiers in tool results.

Telecom captures carry IMSIs, MSISDNs, IMEIs, SIP and tel URIs and UE IP
addresses. With redaction on (``--redact`` for the whole server, or the
``redact`` argument of one call) every result is rewritten before it leaves the
server: each identifier becomes a token such as ``imsi:001-01:3f2a9c1b0d``. The
hex part is the first 40 bits of an HMAC-SHA256 of the value under a key the
client never sees, so the same value gives the same token in every result of
the run: rows from different tools still join on it. The kind before the hex
(``imsi``, ``msisdn``, ``imei``, ``user``, ``ip``, ``id``) is a hint; the hex
alone identifies the value.

Tokens are accepted back as arguments: the server keeps a token-to-value table
in memory (never on disk) and swaps tokens in any string argument for the real
value before the tool runs. A token the server has not issued is refused.

Values are found in two passes over the result:

1. *collect*: values under keys that name an identifier (``imsi``, ``msisdn``,
   ``user_name``, ``ue_ip``, tshark fields such as ``e212.imsi``,
   ``e164.msisdn``, ``gtpv2.mei``, ``pfcp.ue_ip_addr_ipv4``, AVP names such as
   ``Subscription-Id-Data``), the user part of every ``sip:``/``tel:`` URI, and
   digits in front of an ``@`` (``<imsi>@realm`` NAIs);
2. *replace*: every string and every dict key is searched for those values, in
   plain digits (with or without ``+``), as ASCII hex and as TBCD hex (with or
   without colons), plus any run of 14 to 20 digits not seen before (an
   identifier the first pass did not recognise, kind ``id``). In ``ids+ips``
   mode every IPv4 and IPv6 address is replaced as well; in ``ids`` mode only
   the addresses found under UE-address keys.

What it cannot do: free text written by people (SIP display names, SMS text)
is not searched for names; a number shorter than 14 digits is only replaced
when the first pass saw it in a known field or URI (in this call or an earlier
one); identifiers in encodings other than the ones above (for example inside
compressed or encrypted payloads, or split across fields) are not found; host
names, realms and MAC addresses are kept.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
import threading
from typing import Any

MODES = ("off", "ids", "ids+ips")
_RANK = {mode: i for i, mode in enumerate(MODES)}

HEX_LEN = 10
MAX_KNOWN = 50_000
"""Values kept for reuse across calls; past it, new values are still replaced in
the result they appear in but are not remembered (and their tokens cannot be
passed back)."""

# MCCs whose MNCs are three digits (North America, the Caribbean and a few more);
# every other MCC is read with a two-digit MNC.
THREE_DIGIT_MNC = frozenset({
    302, 310, 311, 312, 313, 314, 315, 316, 334, 338, 342, 344, 346, 348, 352, 354, 356, 358,
    360, 365, 366, 376, 405, 708, 722, 732,
})

RESERVED_USERS = frozenset({"anonymous", "unknown", "unavailable", "restricted", "private", "sos", "invalid"})

TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:imsi|msisdn|imei|user|ip|id):(?:[0-9]{3}-[0-9]{2,3}:|[0-9]{8}:)?(?P<hex>[0-9a-f]{%d})(?![0-9a-f])" % HEX_LEN
)

_SCAN = re.compile(
    r"(?P<tok>" + TOKEN_RE.pattern.replace("(?P<hex>", "(?:") + r")"
    r"|(?P<sip>(?i:(?<![A-Za-z])sips?:))(?P<suser>[^\s@;:>?,\"'<]+)(?=@)"
    r"|(?P<tel>(?i:(?<![A-Za-z])tel:))(?P<tuser>\+?[0-9][0-9().\-]*[0-9])"
    r"|(?P<chex>(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){5,}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:]))"
    r"|(?P<ip4>(?<![0-9.])[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?![0-9]|\.[0-9]))"
    r"|(?P<ip6>(?<![0-9A-Fa-f:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f]{0,4})(?![0-9A-Fa-f:]))"
    r"|(?P<run>(?<![0-9A-Fa-f])(?<![0-9]\.)\+?[0-9A-Fa-f]{6,}(?![0-9A-Fa-f])(?!\.[0-9]))"
)

_URI_USERS = re.compile(
    r"(?i:(?<![A-Za-z])sips?:)(?P<suser>[^\s@;:>?,\"'<]+)(?=@)|(?i:(?<![A-Za-z])tel:)(?P<tuser>\+?[0-9][0-9().\-]*[0-9])"
)
_NAI = re.compile(r"(?<![0-9])([0-9]{6,16})@")
_DIGITS = re.compile(r"\+?[0-9]{6,20}")
_INNER_DIGITS = re.compile(r"(?<![0-9])[0-9]{6,}(?![0-9])")
_SPLIT = re.compile(r"[,;\s]+")
_VISUAL = re.compile(r"[().\-]")


def stronger(a: str | None, b: str | None) -> str:
    """The stricter of two modes (``None`` counts as off)."""
    a, b = a or "off", b or "off"
    return a if _RANK[a] >= _RANK[b] else b


def check_mode(value: Any, what: str = "redact") -> str:
    text = "off" if value is None else str(value).strip().lower()
    if text not in _RANK:
        raise ValueError(f"{what} must be one of {', '.join(MODES)}, got {value!r}")
    return text


def _norm(key: str) -> str:
    return re.sub(r"[-. ]", "_", key.lower())


def kind_for_key(key: str) -> str | None:
    """What a value under ``key`` identifies, or None. ``number`` covers MSISDNs,
    global titles and other E.164 numbers; ``subscriber`` is an IMSI or an MSISDN."""
    k = _norm(key)
    if "imei" in k or k == "mei" or k.endswith("_mei"):
        return "imei"
    if "imsi" in k:
        return "imsi"
    if any(p in k for p in ("ue_ip", "paa", "pdn_addr", "pdn_ipv4", "pdn_ipv6", "end_user_address", "framed_ip",
                            "served_party_ip", "user_ipv4", "user_ipv6", "ue_addr")) or k in ("inner_src", "inner_dst"):
        return "ip"  # inner_*: the packet inside a GTP-U tunnel, one end of which is the UE
    if (any(p in k for p in ("msisdn", "e164", "bcd_num", "subscription_id_data", "calling_station_id", "tp_oa",
                             "tp_da", "tp_ra", "sm_rp_oa", "sm_rp_da", "_digits", "calling_gt", "called_gt"))
            or k in ("number", "gt")):
        return "number"
    if k.endswith("user_name") or k in ("identity", "public_identity", "private_identity", "impi", "impu"):
        return "subscriber"
    if k.startswith("sip_") and k.endswith("_user"):  # sip.from.user, sip.to.user, sip.r-uri.user, ...
        return "sip_user"
    return None


def _tbcd(digits: str) -> str:
    padded = digits + "f" if len(digits) % 2 else digits
    return "".join(padded[i + 1] + padded[i] for i in range(0, len(padded), 2))


def _colon(hex_text: str) -> str:
    return ":".join(hex_text[i:i + 2] for i in range(0, len(hex_text), 2))


class Redactor:
    """Keyed pseudonyms for one server run, plus the in-memory table that maps
    tokens back to values for arguments."""

    def __init__(self, key: bytes | None = None, keep_prefix: bool = False):
        self.persistent_key = key is not None
        self._key = key if key is not None else secrets.token_bytes(32)
        self.keep_prefix = keep_prefix
        self._lock = threading.Lock()
        self._token: dict[str, str] = {}      # canonical value -> token
        self._value: dict[str, str] = {}      # hex -> canonical value
        self._variants: dict[str, str] = {}   # lower-case hex encodings of known digit values -> token

    # -------------------------------------------------------------- tokens
    def _hex(self, canonical: str) -> str:
        return hmac.new(self._key, canonical.encode(), hashlib.sha256).hexdigest()[:HEX_LEN]

    def _make(self, kind: str, canonical: str) -> str:
        hx = self._hex(canonical)
        if kind == "imsi" and self.keep_prefix and len(canonical) >= 6:
            mcc = canonical[:3]
            mnc_len = 3 if int(mcc) in THREE_DIGIT_MNC else 2
            return f"imsi:{mcc}-{canonical[3:3 + mnc_len]}:{hx}"
        if kind == "imei" and self.keep_prefix and len(canonical) >= 14:
            return f"imei:{canonical[:8]}:{hx}"
        return f"{kind}:{hx}"

    def _learn(self, kind: str, canonical: str, local: dict[str, str]) -> str:
        """The token for ``canonical``; remembered for the run while under ``MAX_KNOWN``.
        A value first seen as an unclassified ``id`` takes a more specific kind later."""
        token = local.get(canonical) or self._token.get(canonical)
        if token is not None and not (token.startswith("id:") and kind != "id"):
            return token
        token = self._make(kind, canonical)
        local[canonical] = token
        with self._lock:
            if canonical in self._token or len(self._token) < MAX_KNOWN:
                self._token[canonical] = token
                self._value.setdefault(token.rsplit(":", 1)[1], canonical)
                if canonical.isdigit():
                    ascii_hex = canonical.encode().hex()
                    for variant in (ascii_hex, _colon(ascii_hex), _tbcd(canonical), _colon(_tbcd(canonical))):
                        self._variants[variant] = token
        return token

    def lookup(self, token_hex: str) -> str | None:
        return self._value.get(token_hex)

    # -------------------------------------------------------------- arguments
    def unmask(self, text: str) -> tuple[str, bool]:
        """``text`` with every issued token replaced by its value; (text, whether any was).
        Raises ``KeyError`` naming a token this run never issued."""
        found = False

        def swap(m: re.Match[str]) -> str:
            nonlocal found
            value = self._value.get(m.group("hex"))
            if value is None:
                raise KeyError(m.group(0))
            found = True
            return value
        return TOKEN_RE.sub(swap, text), found

    # -------------------------------------------------------------- results
    def apply(self, obj: Any, mode: str) -> tuple[Any, dict[str, int]]:
        """``obj`` with identifiers replaced, and the number of distinct tokens per kind."""
        if mode == "off":
            return obj, {}
        local: dict[str, str] = {}
        self._collect(obj, None, local)
        used: dict[str, set[str]] = {}
        out = self._replace(obj, mode, local, used)
        return out, {kind: len(tokens) for kind, tokens in sorted(used.items())}

    def _collect(self, node: Any, kind: str | None, local: dict[str, str]) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str):
                    self._collect_text(key, None, local)
                # A key with no meaning of its own inherits its container's (inner_src: [{"addr": ...}]).
                self._collect(value, (kind_for_key(key) if isinstance(key, str) else None) or kind, local)
        elif isinstance(node, list):
            for item in node:
                self._collect(item, kind, local)
        elif isinstance(node, str):
            self._collect_text(node, kind, local)

    def _collect_text(self, text: str, kind: str | None, local: dict[str, str]) -> None:
        if kind == "ip":
            for piece in _SPLIT.split(text):
                ip = _ip(piece.split("/")[0])
                if ip is not None:
                    self._learn("ip", ip, local)
        elif kind == "sip_user":
            for piece in _SPLIT.split(text):
                if piece:
                    self._uri_token(piece, local)
        elif kind is not None:
            for piece in _SPLIT.split(text):
                m = _DIGITS.fullmatch(piece) or _NAI.match(piece)
                if m:
                    digits = m.group(1) if m.re is _NAI else piece.lstrip("+")
                    self._learn(_digit_kind(kind, digits, piece.startswith("+")), digits, local)
        if "@" in text or ":" in text:
            for m in _URI_USERS.finditer(text):
                self._uri_token(m.group("suser") or m.group("tuser"), local)
            for m in _NAI.finditer(text):
                self._learn(_digit_kind("subscriber", m.group(1), False), m.group(1), local)

    def _uri_token(self, user: str, local: dict[str, str]) -> str | None:
        if TOKEN_RE.fullmatch(user) or user.lower() in RESERVED_USERS:
            return None
        bare = _VISUAL.sub("", user)
        digits = bare.lstrip("+")
        if digits.isdigit() and len(digits) >= 3:
            return self._learn(_digit_kind("subscriber", digits, bare.startswith("+")), digits, local)
        return self._learn("user", user, local)

    def _replace(self, node: Any, mode: str, local: dict[str, str], used: dict[str, set[str]]) -> Any:
        if isinstance(node, dict):
            return {(self._text(k, mode, local, used) if isinstance(k, str) else k): self._replace(v, mode, local, used)
                    for k, v in node.items()}
        if isinstance(node, list):
            return [self._replace(item, mode, local, used) for item in node]
        if isinstance(node, str):
            return self._text(node, mode, local, used)
        return node

    def _text(self, text: str, mode: str, local: dict[str, str], used: dict[str, set[str]]) -> str:
        def note(token: str) -> str:
            used.setdefault(token.split(":", 1)[0], set()).add(token)
            return token

        def known(canonical: str) -> str | None:
            return local.get(canonical) or self._token.get(canonical)

        def hexes(blob: str) -> str:
            low = blob.lower()
            hits = [(v, t) for v, t in self._variants.items() if v in low]
            hits += [(v, t) for c, t in local.items() if c.isdigit()
                     for v in (c.encode().hex(), _colon(c.encode().hex()), _tbcd(c), _colon(_tbcd(c))) if v in low]
            for variant, token in sorted(hits, key=lambda h: -len(h[0])):
                low = low.replace(variant, note(token))
            out = low if hits else blob
            # Digits inside a longer hex run: a known value, or a 14-20 digit run.
            return _INNER_DIGITS.sub(lambda m: digits(m.group(0)) or m.group(0), out) if not hits else out

        def digits(body: str) -> str | None:
            token = known(body)
            if token is None and 14 <= len(body) <= 20:
                token = self._learn("id", body, local)
            return note(token) if token else None

        def swap(m: re.Match[str]) -> str:
            whole = m.group(0)
            if m.group("tok") is not None:
                return whole
            scheme = m.group("sip") or m.group("tel")
            if scheme is not None:
                user = m.group("suser") or m.group("tuser")
                token = self._uri_token(user, local)
                return scheme + (note(token) if token else user)
            if m.group("chex") is not None:
                return hexes(whole)
            if m.group("ip4") is not None or m.group("ip6") is not None:
                ip = _ip(whole)
                if ip is None or not any(c.isalnum() for c in whole):
                    return whole
                token = known(ip) or (self._learn("ip", ip, local) if mode == "ids+ips" else None)
                return note(token) if token else whole
            body = whole.lstrip("+")
            if not body.isdigit():
                return hexes(whole) if len(body) >= 12 else whole
            return digits(body) or (hexes(whole) if len(body) > 20 else whole)

        exact = known(text)  # a whole value learnt under a known key (a bare SIP user name, say)
        if exact is not None:
            return note(exact)
        return _SCAN.sub(swap, text)

    def describe(self, mode: str) -> dict[str, Any]:
        return {
            "mode": mode,
            "method": f"HMAC-SHA256, first {HEX_LEN * 4} bits; the hex part is the stable key",
            "stable": "across runs with the operator's key" if self.persistent_key else "for this server run",
            "prefix_kept": "IMSI MCC-MNC, IMEI TAC" if self.keep_prefix else "none",
            "tokens_as_arguments": True,
        }


def _digit_kind(kind: str, digits: str, plus: bool) -> str:
    if kind == "imsi" or kind == "imei":
        return kind
    if kind == "number":
        return "msisdn"
    return "imsi" if not plus and len(digits) in (14, 15) else "msisdn"


def _ip(text: str) -> str | None:
    try:
        return ipaddress.ip_address(text.strip("[]")).compressed
    except ValueError:
        return None
