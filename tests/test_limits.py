from __future__ import annotations

import os
from pathlib import Path

import pytest

from tshark_mcp.limits import (
    Allowlist, Limits, ToolError, clamp_limit, lint_digits, lint_display_filter, lint_field_name,
)


class TestLimits:
    def test_defaults_are_positive(self):
        lim = Limits()
        assert lim.max_file_bytes == 500 * 1024 * 1024
        assert lim.max_packets == 500
        assert lim.max_output_bytes == 200 * 1024
        assert lim.timeout_seconds == 60.0

    @pytest.mark.parametrize("field", ["max_file_bytes", "max_packets", "max_output_bytes", "timeout_seconds"])
    def test_limits_cannot_be_disabled(self, field):
        with pytest.raises(ValueError):
            Limits(**{field: 0})
        with pytest.raises(ValueError):
            Limits(**{field: -1})

    def test_from_env_overrides(self):
        env = {"TSHARK_MCP_MAX_FILE_MB": "10", "TSHARK_MCP_MAX_PACKETS": "50", "TSHARK_MCP_TIMEOUT": "5",
               "TSHARK_MCP_MAX_OUTPUT_KB": "16"}
        lim = Limits.from_env(env)
        assert lim.max_file_bytes == 10 * 1024 * 1024
        assert lim.max_packets == 50
        assert lim.timeout_seconds == 5.0
        assert lim.max_output_bytes == 16 * 1024

    def test_from_env_rejects_garbage(self):
        with pytest.raises(ValueError):
            Limits.from_env({"TSHARK_MCP_MAX_PACKETS": "lots"})

    def test_describe_is_json_friendly(self):
        d = Limits().describe()
        assert d["max_file_mb"] == 500.0 and d["max_packets"] == 500


class TestAllowlist:
    def test_empty_allowlist_refuses_everything(self, tmp_path: Path):
        f = tmp_path / "x.pcap"
        f.write_bytes(b"\x00" * 10)
        with pytest.raises(ToolError) as exc:
            Allowlist().resolve(str(f), Limits())
        assert exc.value.type == "no_allowed_dirs"

    def test_inside_root_is_allowed(self, tmp_path: Path):
        f = tmp_path / "x.pcap"
        f.write_bytes(b"\x00" * 10)
        resolved = Allowlist.from_strings([str(tmp_path)]).resolve(str(f), Limits())
        assert resolved == f.resolve()

    def test_outside_root_is_rejected(self, tmp_path: Path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        outside = tmp_path / "outside.pcap"
        outside.write_bytes(b"\x00" * 10)
        with pytest.raises(ToolError) as exc:
            Allowlist.from_strings([str(allowed)]).resolve(str(outside), Limits())
        assert exc.value.type == "path_not_allowed"
        assert exc.value.to_dict()["error"]["allowed_dirs"] == [str(allowed.resolve())]

    def test_dot_dot_traversal_is_rejected(self, tmp_path: Path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        (tmp_path / "secret.pcap").write_bytes(b"\x00" * 10)
        with pytest.raises(ToolError) as exc:
            Allowlist.from_strings([str(allowed)]).resolve(str(allowed / ".." / "secret.pcap"), Limits())
        assert exc.value.type == "path_not_allowed"

    def test_symlink_escaping_root_is_rejected(self, tmp_path: Path):
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        target = tmp_path / "secret.pcap"
        target.write_bytes(b"\x00" * 10)
        link = allowed / "innocent.pcap"
        os.symlink(target, link)
        with pytest.raises(ToolError) as exc:
            Allowlist.from_strings([str(allowed)]).resolve(str(link), Limits())
        assert exc.value.type == "path_not_allowed"

    def test_relative_path_resolves_against_first_root(self, tmp_path: Path):
        f = tmp_path / "x.pcap"
        f.write_bytes(b"\x00" * 10)
        assert Allowlist.from_strings([str(tmp_path)]).resolve("x.pcap", Limits()) == f.resolve()

    def test_missing_file(self, tmp_path: Path):
        with pytest.raises(ToolError) as exc:
            Allowlist.from_strings([str(tmp_path)]).resolve(str(tmp_path / "nope.pcap"), Limits())
        assert exc.value.type == "not_found"

    def test_directory_is_not_a_file(self, tmp_path: Path):
        sub = tmp_path / "sub"
        sub.mkdir()
        with pytest.raises(ToolError) as exc:
            Allowlist.from_strings([str(tmp_path)]).resolve(str(sub), Limits())
        assert exc.value.type == "not_a_file"

    def test_file_too_large(self, tmp_path: Path):
        f = tmp_path / "big.pcap"
        f.write_bytes(b"\x00" * 2048)
        with pytest.raises(ToolError) as exc:
            Allowlist.from_strings([str(tmp_path)]).resolve(str(f), Limits(max_file_bytes=1024))
        assert exc.value.type == "file_too_large"
        assert exc.value.details["size_bytes"] == 2048

    def test_nonexistent_root_is_an_error(self, tmp_path: Path):
        with pytest.raises(ValueError):
            Allowlist.from_strings([str(tmp_path / "missing")])

    def test_env_with_pathsep(self, tmp_path: Path):
        a, b = tmp_path / "a", tmp_path / "b"
        a.mkdir(), b.mkdir()
        al = Allowlist.from_env({"TSHARK_MCP_ALLOW_DIRS": f"{a}{os.pathsep}{b}"})
        assert al.describe() == [str(a.resolve()), str(b.resolve())]


class TestFilterLint:
    @pytest.mark.parametrize("good", [
        "diameter.cmd.code == 316",
        'e212.imsi == "001010123456789" || gtpv2.message_type == 32',
        "ip.len > 100 && !(tcp.port == 80)",
        "sip.Status-Code >= 400 or sip.Method == \"INVITE\"",
        "frame.number in {1, 2, 3}",
        'diameter.Session-Id == "mme01.example;1700000000;1"',
        'sip.Call-ID == "a|b&c;d@example"',
    ])
    def test_accepts_normal_filters(self, good):
        assert lint_display_filter(good) == good

    @pytest.mark.parametrize("bad", [
        "diameter; rm -rf /",
        'diameter.Session-Id == "x;1" ; rm -rf /',
        'sip.Call-ID == "unterminated; rm -rf /',
        "ip.src == 1.1.1.1 | cat /etc/passwd",
        "ip.src == 1.1.1.1 & sleep 10",
        "`id`",
        "$HOME",
        "ip\nframe",
        "",
        "   ",
        "x" * 5000,
    ])
    def test_rejects_metacharacters_and_junk(self, bad):
        with pytest.raises(ToolError) as exc:
            lint_display_filter(bad)
        assert exc.value.type == "invalid_filter"


class TestSmallLints:
    def test_field_name(self):
        assert lint_field_name("diameter.Session-Id") == "diameter.Session-Id"
        assert lint_field_name("_ws.col.info") == "_ws.col.info"
        with pytest.raises(ToolError):
            lint_field_name("diameter.Session-Id; x")
        with pytest.raises(ToolError):
            lint_field_name("-e")

    def test_digits(self):
        assert lint_digits("+1 555 0100123", "msisdn") == "15550100123"
        with pytest.raises(ToolError):
            lint_digits("12ab", "imsi")
        with pytest.raises(ToolError):
            lint_digits("1", "imsi")

    def test_clamp(self):
        assert clamp_limit(None, 500, 200) == 200
        assert clamp_limit(10_000, 500, 200) == 500
        assert clamp_limit(0, 500, 200) == 1
        with pytest.raises(ToolError):
            clamp_limit("ten", 500, 200)
