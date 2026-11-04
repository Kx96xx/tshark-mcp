"""Redaction: subscriber identifiers in results become stable keyed tokens, tokens
work as arguments, and nothing raw reaches the client. Synthetic captures and
test-range identities only."""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from tshark_mcp import redact, server as server_module
from tshark_mcp.limits import Limits
from tshark_mcp.redact import Redactor

from . import pcapgen
from .conftest import TSHARK, requires_tshark

KEY = b"test-key-0123456789abcdef"

# Substrings that must never appear in a redacted result: the synthetic IMSIs, the
# E.164 numbers (subscribers and global titles all start 1555010), the IMEISV, the
# short number and the UE address.
FORBIDDEN = ("0010101", "0010109", "0010105", "1555010", "5550100", "0012345600", "100.64.0.7")
TOKEN = re.compile(r"(?:imsi|msisdn|imei|user|ip|id):(?:[0-9]{3}-[0-9]{2,3}:|[0-9]{8}:)?[0-9a-f]{10}")


def _leaks(obj: Any) -> list[str]:
    text = json.dumps(obj)
    return [s for s in FORBIDDEN if s in text]


# ------------------------------------------------------------------ the redactor alone
class TestTokens:
    def test_same_value_same_token_in_every_result(self):
        r = Redactor(KEY)
        a, _ = r.apply({"imsi": pcapgen.IMSI}, "ids")
        b, _ = r.apply({"rows": [{"user_name": pcapgen.IMSI}]}, "ids")
        c, _ = r.apply({"identity": pcapgen.IMSI}, "ids")
        assert a["imsi"] == b["rows"][0]["user_name"] == c["identity"]
        assert TOKEN.fullmatch(a["imsi"]) and a["imsi"].startswith("imsi:")

    def test_tokens_depend_on_the_key(self):
        one, _ = Redactor(KEY).apply({"imsi": pcapgen.IMSI}, "ids")
        same, _ = Redactor(KEY).apply({"imsi": pcapgen.IMSI}, "ids")
        other, _ = Redactor(b"another-key-0123456789").apply({"imsi": pcapgen.IMSI}, "ids")
        random_key, _ = Redactor().apply({"imsi": pcapgen.IMSI}, "ids")
        assert one == same
        assert one != other and one != random_key
        assert Redactor(KEY).describe("ids")["stable"].startswith("across runs")
        assert Redactor().describe("ids")["stable"] == "for this server run"

    def test_prefix_kept_on_request(self):
        r = Redactor(KEY, keep_prefix=True)
        out, _ = r.apply({"imsi": [pcapgen.IMSI, "316999000000001"], "imeisv": pcapgen.IMEISV}, "ids")
        assert out["imsi"][0].startswith("imsi:001-01:")
        assert out["imsi"][1].startswith("imsi:316-999:")  # a three-digit-MNC country
        assert out["imeisv"].startswith("imei:00123456:")
        plain, _ = Redactor(KEY).apply({"imsi": pcapgen.IMSI}, "ids")
        assert plain["imsi"].split(":")[-1] == out["imsi"][0].split(":")[-1]

    def test_kind_hint_does_not_change_the_hex(self):
        r = Redactor(KEY)
        loose, _ = r.apply({"text": f"seen {pcapgen.IMSI} here"}, "ids")
        typed, _ = r.apply({"imsi": pcapgen.IMSI}, "ids")
        assert loose["text"].split()[1].startswith("id:")
        assert typed["imsi"].startswith("imsi:")
        assert loose["text"].split()[1][-10:] == typed["imsi"][-10:]


class TestWhereIdentifiersAreFound:
    def test_sip_and_tel_users(self):
        out, replaced = Redactor(KEY).apply({
            "from": f"<sip:+{pcapgen.MSISDN}@ims.example>;tag=1", "p_asserted_identity": f"<tel:+{pcapgen.MSISDN}>",
            "to": "sip:alice@example.com", "contact": "sip:anonymous@anonymous.invalid", "route": "sip:ims.example;lr",
        }, "ids")
        msisdn = re.search(r"sip:(msisdn:[0-9a-f]{10})@ims\.example", out["from"]).group(1)
        assert out["p_asserted_identity"] == f"<tel:{msisdn}>"
        assert re.fullmatch(r"sip:user:[0-9a-f]{10}@example\.com", out["to"])
        assert out["contact"] == "sip:anonymous@anonymous.invalid"
        assert out["route"] == "sip:ims.example;lr"
        assert replaced == {"msisdn": 1, "user": 1}

    def test_imei_inside_a_sip_instance_urn(self):
        # RFC 7254 writes the IMEI as TAC-SNR-CD inside +sip.instance, so no digit run is long enough on its own.
        r = Redactor(KEY, keep_prefix=True)
        out, replaced = r.apply({
            "contact": '<sip:198.51.100.27:5060>;+sip.instance="<urn:gsma:imei:00123456-000001-0>";expires=600',
            "instance": "URN:GSMA:IMEI:00123456-000001-0;svn=12",
        }, "ids")
        assert "00123456-000001" not in json.dumps(out)
        token = re.search(r'urn:gsma:imei:(imei:00123456:[0-9a-f]{10})>', out["contact"]).group(1)
        assert out["instance"] == f"URN:GSMA:IMEI:{token};svn=12"
        assert replaced == {"imei": 1}
        plain, _ = r.apply({"imei": "001234560000010"}, "ids")  # the same IMEI as digits: the same token
        assert plain["imei"] == token

    def test_nai_and_tshark_field_names(self):
        out, _ = Redactor(KEY).apply({"layers": {
            "diameter.User-Name": f"{pcapgen.IMSI}@nai.epc.mnc001.mcc001.3gppnetwork.org",
            "e164.msisdn": pcapgen.MSISDN_SHORT, "gtpv2.mei": pcapgen.IMEISV,
            "gtpv2.pdn_addr_and_prefix.ipv4": pcapgen.UE_IP, "sccp.calling.digits": "15550109001",
        }}, "ids")
        assert not _leaks(out)
        layers = out["layers"]
        assert layers["gtpv2.mei"].startswith("imei:") and layers["gtpv2.pdn_addr_and_prefix.ipv4"].startswith("ip:")
        assert layers["diameter.User-Name"].startswith("imsi:") and layers["diameter.User-Name"].endswith("@nai.epc.mnc001.mcc001.3gppnetwork.org")

    def test_hex_encodings_of_a_known_value(self):
        ascii_hex = pcapgen.IMSI.encode().hex()
        tbcd = pcapgen._tbcd(pcapgen.IMSI).hex()
        colon = ":".join(ascii_hex[i:i + 2] for i in range(0, len(ascii_hex), 2))
        out, _ = Redactor(KEY).apply({"imsi": pcapgen.IMSI, "raw": [
            f"00:00:fd:e7:{colon}", ascii_hex, f"0108{tbcd}", ":".join(tbcd[i:i + 2] for i in range(0, len(tbcd), 2)),
        ]}, "ids")
        token = out["imsi"]
        for value in out["raw"]:
            assert token in value, value
            assert ascii_hex not in value and tbcd not in value

    def test_long_unrecognised_digit_runs(self):
        out, replaced = Redactor(KEY).apply({
            "path": f"/caps/imsi_{pcapgen.IMSI}_failing.pcapng", "iccid": "89001012345678901234",
            "session_id": "mme01.example;1700000000;1", "time": "2023-11-14T22:13:20.000000000Z",
            "epoch": "1700000000.123456789", "teid": "0x0000a001", "frame_count": 123456789012, "short": "5550100",
        }, "ids")
        assert re.fullmatch(r"/caps/imsi_id:[0-9a-f]{10}_failing\.pcapng", out["path"])
        assert out["iccid"].startswith("id:")
        for key in ("session_id", "time", "epoch", "teid", "frame_count", "short"):
            assert out[key] == {"session_id": "mme01.example;1700000000;1", "time": "2023-11-14T22:13:20.000000000Z",
                                "epoch": "1700000000.123456789", "teid": "0x0000a001", "frame_count": 123456789012,
                                "short": "5550100"}[key]
        assert replaced == {"id": 2}

    def test_file_names_lose_msisdn_sized_numbers(self):
        out, _ = Redactor(KEY).apply({"note": f"seen {pcapgen.MSISDN} once", "path": f"/caps/{pcapgen.MSISDN}.pcap",
                                      "files": [{"path": "/caps/ring_49216.pcap"}]}, "ids")
        assert re.fullmatch(r"/caps/id:[0-9a-f]{10}\.pcap", out["path"])
        assert out["files"][0]["path"] == "/caps/ring_49216.pcap"
        assert pcapgen.MSISDN not in json.dumps(out)  # learnt from the path, so found in the note too

    def test_unassigned_addresses_are_not_identifiers(self):
        out, _ = Redactor(KEY).apply({"paa": ["0.0.0.0", "::"], "dir": "0.0.0.0 > ::"}, "ids+ips")
        assert out == {"paa": ["0.0.0.0", "::"], "dir": "0.0.0.0 > ::"}

    def test_a_short_number_learnt_once_is_found_later(self):
        r = Redactor(KEY)
        first, _ = r.apply({"msisdn": pcapgen.MSISDN_SHORT}, "ids")
        later, _ = r.apply({"truncated_reason": f"nothing for {pcapgen.MSISDN_SHORT} in frame 12"}, "ids")
        assert later["truncated_reason"] == f"nothing for {first['msisdn']} in frame 12"

    def test_dict_keys_are_searched(self):
        out, _ = Redactor(KEY).apply({"by_imsi": {pcapgen.IMSI: 3},
                                      "layers": {f"User-Name: {pcapgen.IMSI}": {"x": "1"}}}, "ids")
        assert not _leaks(out)

    def test_ids_mode_hides_ue_addresses_only(self):
        out, _ = Redactor(KEY).apply({"paa": pcapgen.UE_IP, "rows": [
            {"src": pcapgen.UE_IP, "dst": pcapgen.SERVER_IP, "mac": pcapgen.MAC_A},
        ]}, "ids")
        assert out["rows"][0]["src"] == out["paa"] and out["paa"].startswith("ip:")
        assert out["rows"][0]["dst"] == pcapgen.SERVER_IP and out["rows"][0]["mac"] == pcapgen.MAC_A

    def test_ids_ips_mode_hides_every_address(self):
        out, replaced = Redactor(KEY).apply({"rows": [
            {"src": pcapgen.SGW_IP, "dst": "2001:db8::1", "dir": f"{pcapgen.SGW_IP}:2123 > [2001:db8::1]:2123",
             "mac": pcapgen.MAC_A, "time": "22:13:20.5"},
        ]}, "ids+ips")
        row = out["rows"][0]
        assert row["src"].startswith("ip:") and row["dst"].startswith("ip:")
        assert row["dir"] == f"{row['src']}:2123 > [{row['dst']}]:2123"
        assert row["mac"] == pcapgen.MAC_A and row["time"] == "22:13:20.5"
        assert replaced == {"ip": 2}

    def test_off_changes_nothing(self):
        data = {"imsi": pcapgen.IMSI}
        assert Redactor(KEY).apply(data, "off") == (data, {})


class TestArguments:
    def test_tokens_map_back(self):
        r = Redactor(KEY)
        out, _ = r.apply({"imsi": pcapgen.IMSI, "paa": pcapgen.UE_IP}, "ids")
        text, found = r.unmask(f'e212.imsi == "{out["imsi"]}" && ip.addr == {out["paa"]}')
        assert found and text == f'e212.imsi == "{pcapgen.IMSI}" && ip.addr == {pcapgen.UE_IP}'
        assert r.unmask("no tokens here") == ("no tokens here", False)

    def test_a_token_this_run_never_issued_is_refused(self):
        with pytest.raises(KeyError):
            Redactor(KEY).unmask("imsi:0123456789")

    def test_modes(self):
        assert redact.stronger("ids", "off") == "ids" and redact.stronger(None, "ids+ips") == "ids+ips"
        assert redact.check_mode(None) == "off" and redact.check_mode(" IDS ") == "ids"
        with pytest.raises(ValueError):
            redact.check_mode("all")


# ------------------------------------------------------------------ through the server
@pytest.fixture(scope="module")
def id_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("identity")
    pcapgen.write_identity_pcap(directory / "identity.pcap")
    return directory


@pytest.fixture
def redacting(pcap_dir: Path, id_dir: Path, tmp_path: Path):
    def _configure(mode: str = "ids", **kw: Any):
        server_module.configure([str(pcap_dir), str(id_dir)], limits=Limits(), tshark=TSHARK,
                                log_path=tmp_path / "audit.jsonl", redact_mode=mode, **kw)
        return server_module
    yield _configure
    server_module._STATE = None


def _identity_calls(id_dir: Path) -> list[tuple[str, dict[str, Any]]]:
    cap = str(id_dir / "identity.pcap")
    return [
        ("gtp_sessions", {"path": cap}),
        ("diameter_avps", {"path": cap}),
        ("diameter_sessions", {"path": cap}),
        ("sip_dialogs", {"path": cap}),
        ("packet_detail", {"path": cap, "frame": 3}),
        ("packet_detail", {"path": cap, "frame": 1, "layers": ["gtpv2"]}),
        ("filter_packets", {"path": cap, "display_filter": "gtpv2 || diameter || sip",
                            "fields": ["e212.imsi", "gtpv2.mei", "e164.msisdn", "gtpv2.pdn_addr_and_prefix.ipv4",
                                       "sip.from.user", "sip.to.user", "diameter.User-Name"]}),
        ("trace_subscriber", {"path": cap, "imsi": pcapgen.IMSI, "msisdn": pcapgen.MSISDN}),
        ("find_identifier", {"path": str(id_dir), "identifier": pcapgen.IMSI}),
        ("conversations", {"path": cap}),
    ]


def _all_calls(pcap_dir: Path, id_dir: Path) -> list[tuple[str, dict[str, Any]]]:
    from .test_mcp_client import _calls
    return [*_calls(pcap_dir), *_identity_calls(id_dir)]


@requires_tshark
def test_no_identifier_survives_any_tool(redacting, pcap_dir: Path, id_dir: Path):
    seen_raw = []
    for name, args in _all_calls(pcap_dir, id_dir):
        srv = redacting("ids")  # a fresh server each time: nothing learnt from an earlier call helps
        result = getattr(srv, name)(**args)
        assert "redaction" in result and result["redaction"]["mode"] == "ids", name
        assert not _leaks(result), (name, args, _leaks(result))
        seen_raw.append(name)
    assert len(seen_raw) == len(_all_calls(pcap_dir, id_dir))


@requires_tshark
def test_identity_capture_is_really_full_of_identifiers(redacting, id_dir: Path):
    """The leak test above means something only if the raw results carry the values."""
    srv = redacting("off")
    raw = json.dumps([getattr(srv, n)(**a) for n, a in _identity_calls(id_dir)])
    for value in (pcapgen.IMSI, pcapgen.MSISDN, pcapgen.IMEISV, pcapgen.MSISDN_SHORT, pcapgen.IMSI_IMPU, pcapgen.UE_IP):
        assert value in raw, value
    assert pcapgen.IMSI.encode().hex(":") in raw  # the undecodable AVP, as raw bytes


@requires_tshark
def test_the_same_subscriber_has_one_token_across_tools(redacting, pcap_dir: Path, id_dir: Path):
    srv = redacting("ids")
    diam = srv.diameter_sessions(path=str(pcap_dir / "diameter.pcap"), imsi=pcapgen.IMSI)
    token = diam["sessions"][0]["user_name"]
    assert token.startswith("imsi:")
    gtp = srv.gtp_sessions(path=str(pcap_dir / "gtpv2.pcap"))
    assert token in [t.get("imsi") for t in gtp["transactions"]]
    sigtran = srv.sigtran_messages(path=str(pcap_dir / "sigtran.pcap"))
    assert token in [m.get("imsi") for m in sigtran["messages"]]
    ident = srv.gtp_sessions(path=str(id_dir / "identity.pcap"))
    assert ident["transactions"][0]["imsi"] == token
    msisdns = {t["msisdn"] for t in gtp["transactions"] if t.get("msisdn")}
    assert ident["transactions"][0]["msisdn"] in msisdns


@requires_tshark
def test_tokens_work_as_arguments(redacting, pcap_dir: Path):
    srv = redacting("ids")
    all_pcap = str(pcap_dir / "all.pcap")
    by_value = srv.trace_subscriber(path=all_pcap, imsi=pcapgen.IMSI, msisdn=pcapgen.MSISDN)
    imsi_token, msisdn_token = by_value["identity"]["imsi"], by_value["identity"]["msisdn"]
    by_token = srv.trace_subscriber(path=all_pcap, imsi=imsi_token, msisdn=msisdn_token)
    assert by_token["timeline"] == by_value["timeline"] and by_token["identity"] == by_value["identity"]
    rows = srv.filter_packets(path=all_pcap, display_filter=f'e212.imsi == "{imsi_token}"', fields=["e212.imsi"])
    assert rows["total_matched"] >= 3 and {p["e212.imsi"] for p in rows["packets"]} == {imsi_token}
    found = srv.find_identifier(path=str(pcap_dir), identifier=imsi_token, max_files=3)
    assert found["files"] and not _leaks(found)
    sessions = srv.diameter_sessions(path=str(pcap_dir / "diameter.pcap"), imsi=imsi_token)
    assert sessions["total_matched"] >= 1


@requires_tshark
def test_a_path_with_a_token_opens_the_real_file(redacting, tmp_path: Path, id_dir: Path):
    named = id_dir / f"imsi_{pcapgen.IMSI}.pcap"
    named.write_bytes((id_dir / "identity.pcap").read_bytes())
    try:
        srv = redacting("ids")
        listed = srv.find_identifier(path=str(id_dir), identifier=pcapgen.IMSI)
        shown = [f["path"] for f in listed["files"] if "imsi_" in f["path"]][0]
        assert pcapgen.IMSI not in shown and TOKEN.search(shown)
        info = srv.pcap_info(path=shown)
        assert info.get("packets") == 4 and not _leaks(info)
    finally:
        named.unlink()


@requires_tshark
def test_unknown_token_is_refused(redacting, pcap_dir: Path):
    srv = redacting("ids")
    out = srv.trace_subscriber(path=str(pcap_dir / "all.pcap"), imsi="imsi:0123456789")
    assert out["error"]["type"] == "unknown_token"


@requires_tshark
def test_per_call_redaction_and_its_floor(redacting, pcap_dir: Path):
    diameter = str(pcap_dir / "diameter.pcap")
    srv = redacting("off")
    plain = srv.diameter_sessions(path=diameter, imsi=pcapgen.IMSI)
    assert "redaction" not in plain and pcapgen.IMSI in json.dumps(plain)
    hidden = srv.diameter_sessions(path=diameter, imsi=pcapgen.IMSI, redact="ids")
    assert hidden["redaction"]["mode"] == "ids" and not _leaks(hidden)
    # A call that passes a token is redacted even without asking.
    token = hidden["sessions"][0]["user_name"]
    again = srv.diameter_sessions(path=diameter, imsi=token)
    assert again["redaction"]["mode"] == "ids" and not _leaks(again)
    # A call cannot lower the server's level.
    srv = redacting("ids+ips")
    lowered = srv.conversations(path=diameter, redact="off")
    assert lowered["redaction"]["mode"] == "ids+ips" and pcapgen.MME_IP not in json.dumps(lowered)
    bad = srv.conversations(path=diameter, redact="everything")
    assert bad["error"]["type"] == "invalid_argument"


@requires_tshark
def test_audit_log_keeps_no_raw_identifier(redacting, pcap_dir: Path, tmp_path: Path):
    srv = redacting("ids")
    srv.trace_subscriber(path=str(pcap_dir / "all.pcap"), imsi=pcapgen.IMSI, msisdn=pcapgen.MSISDN)
    log = (tmp_path / "audit.jsonl").read_text()
    assert '"tool": "trace_subscriber"' in log and not [s for s in FORBIDDEN if s in log]


def test_the_text_cap_never_cuts_an_identifier_in_half(redacting):
    srv = redacting("ids")
    long_from = "x" * 250 + f" <sip:+{pcapgen.MSISDN}@ims.example>"
    out = srv._guarded("sip_dialogs", {}, lambda: {"dialogs": [{"from": long_from}]})
    cut = out["dialogs"][0]["from"]
    assert out["text_values_shortened"] == 1 and "...[+" in cut
    assert "1555" not in cut


def test_server_flags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    parser = server_module.build_parser()
    args = parser.parse_args(["--allow-dir", str(tmp_path), "--redact", "ids+ips", "--redact-keep-prefix"])
    assert args.redact == "ids+ips" and args.redact_keep_prefix
    monkeypatch.setenv("TSHARK_MCP_REDACT_KEY", "too-short")
    assert server_module.main(["--allow-dir", str(tmp_path), "--redact", "ids"]) == 2
    monkeypatch.delenv("TSHARK_MCP_REDACT_KEY")
    monkeypatch.setenv("TSHARK_MCP_REDACT", "everything")
    assert server_module.main(["--allow-dir", str(tmp_path)]) == 2
    server_module._STATE = None


# ------------------------------------------------------------------ over stdio
async def _stdio(pcap_dir: Path) -> list[Any]:
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    env = dict(os.environ, TSHARK_MCP_TSHARK=TSHARK, TSHARK_MCP_REDACT_KEY=KEY.decode())
    params = StdioServerParameters(command=sys.executable, env=env, args=[
        "-m", "tshark_mcp.server", "--allow-dir", str(pcap_dir), "--redact", "ids", "--redact-keep-prefix"])
    out = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            async def call(name: str, args: dict[str, Any]) -> dict[str, Any]:
                res = await session.call_tool(name, args)
                return getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
            first = await call("diameter_sessions", {"path": str(pcap_dir / "diameter.pcap"), "imsi": pcapgen.IMSI})
            out.append(first)
            token = first["sessions"][0]["user_name"]
            out.append(await call("trace_subscriber", {"path": str(pcap_dir / "all.pcap"), "imsi": token}))
            out.append(await call("sip_dialogs", {"path": str(pcap_dir / "sip.pcap")}))
    return out


@requires_tshark
def test_over_stdio_with_an_operator_key(pcap_dir: Path):
    first, trace, sip = asyncio.run(_stdio(pcap_dir))
    token = first["sessions"][0]["user_name"]
    assert token.startswith("imsi:001-01:") and first["redaction"]["prefix_kept"] != "none"
    assert first["redaction"]["stable"].startswith("across runs")
    # The operator key gives the same token as a redactor built with it here.
    assert token == Redactor(KEY, keep_prefix=True).apply({"imsi": pcapgen.IMSI}, "ids")[0]["imsi"]
    assert trace["identity"]["imsi"] == token and trace["total_matched"] >= 3
    for result in (first, trace, sip):
        assert not _leaks(result)
