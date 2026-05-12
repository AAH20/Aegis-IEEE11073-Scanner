"""Unit tests for :mod:`aegis.parser_11073` and :mod:`aegis.analyzer`.

These tests deliberately avoid touching :mod:`scapy` so they run fast in
CI without requiring libpcap. They exercise the byte-level parser and the
heuristic classifier directly.
"""

from __future__ import annotations

import os
import struct

import pytest

from aegis.analyzer import TelemetryAnalyzer
from aegis.parser_11073 import (
    APDU_TAGS,
    ParsedPacket,
    classify_payload,
    find_apdu_in_payload,
    parse_apdu,
    synthesize_apdu,
    synthesize_plaintext_pacing_payload,
)


# ---------------------------------------------------------------------------
# parse_apdu / find_apdu_in_payload
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tag,name", list(APDU_TAGS.items()))
def test_parse_apdu_recognises_all_choice_tags(tag: int, name: str) -> None:
    payload = b"\x01\x02\x03\x04"
    buf = struct.pack(">HH", tag, len(payload)) + payload
    apdu = parse_apdu(buf)
    assert apdu is not None
    assert apdu.apdu_type == name
    assert apdu.tag == tag
    assert apdu.length == len(payload)
    assert apdu.payload == payload


def test_parse_apdu_rejects_unknown_tag() -> None:
    assert parse_apdu(b"\x12\x34\x00\x00") is None


def test_parse_apdu_short_buffer_returns_none() -> None:
    assert parse_apdu(b"\xe7") is None
    assert parse_apdu(b"") is None


def test_find_apdu_in_payload_finds_offset_tag() -> None:
    prefix = b"\xde\xad\xbe\xef\x00"
    apdu_bytes = synthesize_apdu("PrstApdu", payload=b"\x4a\x14\x00\x48")
    buf = prefix + apdu_bytes
    apdu = find_apdu_in_payload(buf)
    assert apdu is not None
    assert apdu.apdu_type == "PrstApdu"


def test_find_apdu_in_payload_handles_garbage() -> None:
    assert find_apdu_in_payload(b"\x00" * 50) is None


# ---------------------------------------------------------------------------
# classify_payload
# ---------------------------------------------------------------------------


def test_classify_payload_flags_plaintext_pacing() -> None:
    payload = synthesize_plaintext_pacing_payload(rate_bpm=72)
    score, hits = classify_payload(payload)
    assert score >= 0.5
    assert "MDC_PACE_RATE_SET" in hits
    assert "MDC_HEART_RATE" in hits


def test_classify_payload_treats_random_bytes_as_ciphertext() -> None:
    payload = os.urandom(512)
    score, hits = classify_payload(payload)
    assert score < 0.5
    assert hits == []


def test_classify_payload_empty() -> None:
    score, hits = classify_payload(b"")
    assert score == 0.0
    assert hits == []


# ---------------------------------------------------------------------------
# TelemetryAnalyzer end-to-end (synthetic packets, no PCAP needed)
# ---------------------------------------------------------------------------


def _make_packet(
    index: int,
    timestamp: float,
    *,
    plaintext: bool,
    payload_size: int = 64,
    apdu_type: str = "PrstApdu",
) -> ParsedPacket:
    """Build a synthetic ParsedPacket for analyzer tests."""
    if plaintext:
        body = synthesize_plaintext_pacing_payload(rate_bpm=70 + index)
        body += b"\x00" * max(0, payload_size - len(body))
    else:
        body = os.urandom(payload_size)
    raw = synthesize_apdu(apdu_type, payload=body)
    apdu = parse_apdu(raw)
    assert apdu is not None
    score, hits = classify_payload(body)
    return ParsedPacket(
        index=index,
        timestamp=timestamp,
        src="10.0.0.1",
        dst="10.0.0.2",
        transport="TCP",
        apdu=apdu,
        plaintext_score=score,
        nomenclature_hits=hits,
    )


def test_analyzer_flags_plaintext_pacing_as_critical() -> None:
    pkts = [
        _make_packet(i, timestamp=1700000000.0 + i * 0.020, plaintext=True)
        for i in range(5)
    ]
    findings = TelemetryAnalyzer().analyze(pkts)

    plaintext = [f for f in findings if "Plaintext" in f.vulnerability]
    assert plaintext, "expected at least one plaintext finding"
    assert all(f.severity == "CRITICAL" for f in plaintext)


def test_analyzer_flags_short_payload_for_missing_mac() -> None:
    pkts = [
        _make_packet(0, 1.0, plaintext=False, payload_size=8),
    ]
    findings = TelemetryAnalyzer().analyze(pkts)
    assert any("Missing cryptographic MAC" in f.vulnerability for f in findings)


def test_analyzer_flags_jitter_exceeding_8ms() -> None:
    base = 1700000000.0
    timestamps = [base + i * 0.020 for i in range(10)]
    timestamps[5] += 0.050  # +50 ms spike between packets 4 and 5
    pkts = [
        _make_packet(i, ts, plaintext=False, payload_size=64)
        for i, ts in enumerate(timestamps)
    ]
    findings = TelemetryAnalyzer().analyze(pkts)
    jitter = [f for f in findings if "jitter" in f.vulnerability.lower()]
    assert jitter, "expected at least one jitter finding"
    assert all(f.severity == "CRITICAL" for f in jitter)


def test_analyzer_clean_ciphertext_produces_no_critical() -> None:
    base = 1700000000.0
    pkts = [
        _make_packet(i, base + i * 0.020, plaintext=False, payload_size=64)
        for i in range(10)
    ]
    findings = TelemetryAnalyzer().analyze(pkts)
    assert not any(f.severity == "CRITICAL" for f in findings)


def test_analyzer_findings_have_remediation_text() -> None:
    pkts = [
        _make_packet(0, 1.0, plaintext=True),
        _make_packet(1, 1.020, plaintext=True),
    ]
    findings = TelemetryAnalyzer().analyze(pkts)
    assert findings
    for f in findings:
        assert f.remediation
        assert f.e_cvss > 0.0
