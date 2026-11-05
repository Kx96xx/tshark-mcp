"""evals/public: the opt-in re-run of the public-capture validation. No network here: the
manifest, the SHA-256 refusal and the scenario wiring are checked offline."""

from __future__ import annotations

import gzip
import hashlib
import re
from pathlib import Path

import pytest

from evals.harness import CaseResult, Call
from evals.public import __main__ as public
from evals.public.scenarios import SCENARIOS, TEXT_CHECKS


def test_manifest_entries_are_complete_and_https():
    entries = public.manifest()
    assert len({e["file"] for e in entries}) == len(entries)
    for e in entries:
        assert e["url"].startswith("https://") and re.fullmatch(r"[0-9a-f]{64}", e["sha256"])
        assert e["licence"] and e["gunzip"] == e["url"].endswith(".gz")


def test_every_scenario_reads_only_manifest_captures():
    files = {e["file"] for e in public.manifest()}
    for s in SCENARIOS:
        for step in s.steps:
            path = step.args.get("path", "")
            if path.startswith("{captures}/"):
                assert path.removeprefix("{captures}/") in files, (s.id, path)
    assert set(TEXT_CHECKS) <= {s.id for s in SCENARIOS}
    assert {public.DEFECTS[s.id] for s in SCENARIOS} >= {f"D{n}" for n in (2, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16,
                                                                             17, 18, 19, 20, 21, 22, 23)} - {"D9"}


def test_a_changed_sample_is_refused(tmp_path: Path):
    f = tmp_path / "x.pcap"
    f.write_bytes(b"not the sample")
    entry = {"file": "x.pcap", "url": "https://example.invalid/x.pcap", "sha256": "0" * 64, "gunzip": False}
    with pytest.raises(ValueError, match="differs"):
        public.verify(entry, f)
    entry["sha256"] = hashlib.sha256(b"not the sample").hexdigest()
    assert public.fetch(entry, tmp_path) == f  # present and matching: no download


def test_only_https_is_fetched(tmp_path: Path):
    entry = {"file": "y.pcap", "url": "file:///etc/hosts", "sha256": "0" * 64, "gunzip": False}
    with pytest.raises(ValueError, match="non-https"):
        public.fetch(entry, tmp_path)
    assert not (tmp_path / "y.pcap").exists()


def test_text_checks_and_table():
    good = CaseResult("D12_ussd_redaction", True, calls=[Call("filter_packets", {}, {
        "packets": [{"gsm_map.ussd_string": "*140*msisdn:0123456789#",
                     "gsm_map.ss.ussd_String": "<redacted: 14 bytes of packed text>"}]}, False, 0.1)])
    assert public.text_failures(good) == []
    bad = CaseResult("D12_ussd_redaction", True, calls=[Call("filter_packets", {}, {
        "packets": [{"gsm_map.ussd_string": "*140*15550100777#"}]}, False, 0.1)])
    assert len(public.text_failures(bad)) == 3
    out = public.table([good, CaseResult("D20_auto_interval", False, ["interval_auto eq True"])])
    assert "| D12 |" in out and "FAIL: interval_auto" in out and "1 of 2 checks pass." in out


def test_gzip_samples_are_verified_after_gunzip(tmp_path: Path, monkeypatch):
    raw = b"pcap bytes"
    entry = {"file": "z.pcap", "url": "https://example.invalid/z.pcap.gz", "sha256": hashlib.sha256(raw).hexdigest(),
             "gunzip": True}

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return gzip.compress(raw)

    monkeypatch.setattr(public.urllib.request, "urlopen", lambda url, timeout: Resp())
    assert public.fetch(entry, tmp_path).read_bytes() == raw
