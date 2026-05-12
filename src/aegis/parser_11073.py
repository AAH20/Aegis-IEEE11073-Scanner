"""IEEE 11073-20601 Application Protocol Data Unit (APDU) dissector.

This module is a deliberately lightweight, *non-conformant* parser. It does
not implement the full ASN.1 MDER (Medical Device Encoding Rules) decoder
defined in ISO/IEEE 11073-20601:2014. Instead, it provides:

  * Identification of standard APDU choice tags (AarqApdu, AareApdu, RlrqApdu,
    RlreApdu, AbrtApdu, PrstApdu) by their 16-bit BER/MDER outer tags.
  * Length-prefixed payload extraction.
  * A heuristic plaintext-vs-ciphertext classifier based on Shannon entropy
    and presence of well-known 11073 nomenclature OIDs / attribute IDs
    (heart-rate, pacing rate, blood pressure, etc).

It is intentionally robust to malformed input; the goal is auditing, not
strict decoding.
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

try:
    from scapy.all import rdpcap, Raw, IP, IPv6, TCP, UDP  # type: ignore[import-untyped]
    from scapy.packet import Packet  # type: ignore[import-untyped]

    _SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - scapy import guarded for unit tests
    _SCAPY_AVAILABLE = False
    Packet = object  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# IEEE 11073-20601 APDU choice tags (outer BER tag, 16-bit big-endian).
# These constants are taken from the published nomenclature in 11073-20601 §8.
# ---------------------------------------------------------------------------

APDU_TAGS: dict[int, str] = {
    0xE200: "AarqApdu",        # Association Request
    0xE300: "AareApdu",        # Association Response
    0xE400: "RlrqApdu",        # Release Request
    0xE500: "RlreApdu",        # Release Response
    0xE600: "AbrtApdu",        # Abort
    0xE700: "PrstApdu",        # Presentation (data) APDU
}

# Well-known IEEE 11073-10101 nomenclature codes that frequently appear in
# plaintext biometric / pacing telemetry. Hits on these inside an extracted
# payload are a *strong* signal the payload is not encrypted.
NOMENCLATURE_HINTS: dict[int, str] = {
    0x4182: "MDC_PULS_RATE_NON_INV",       # Non-invasive pulse rate
    0x4A14: "MDC_HEART_RATE",              # ECG heart rate
    0x4A15: "MDC_ECG_HEART_RATE_INST",     # Instantaneous ECG HR
    0x4A1A: "MDC_PRESS_BLD_NONINV_SYS",    # NIBP systolic
    0x4A1B: "MDC_PRESS_BLD_NONINV_DIA",    # NIBP diastolic
    0x4A1C: "MDC_PRESS_BLD_NONINV_MEAN",   # NIBP mean
    0xF093: "MDC_TEMP_BODY",               # Body temperature
    0x5000: "MDC_PACE_RATE_SET",           # Pacing rate setpoint
    0x5001: "MDC_PACE_AMP_SET",            # Pacing amplitude setpoint
    0x5002: "MDC_DEFIB_SHOCK_ENERGY",      # Defibrillator shock energy
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class APDU:
    """A parsed (or mock-parsed) IEEE 11073-20601 APDU."""

    apdu_type: str
    tag: int
    length: int
    payload: bytes
    raw: bytes = field(repr=False, default=b"")

    @property
    def is_pacing_or_telemetry(self) -> bool:
        """Heuristic: PrstApdu typically carries telemetry / pacing data."""
        return self.apdu_type == "PrstApdu"


@dataclass(slots=True)
class ParsedPacket:
    """A single IEEE 11073 packet parsed off a PCAP or live capture."""

    index: int
    timestamp: float
    src: str
    dst: str
    transport: str
    apdu: APDU | None
    plaintext_score: float  # 0.0 = clearly ciphertext, 1.0 = clearly plaintext
    nomenclature_hits: list[str] = field(default_factory=list)

    @property
    def looks_plaintext(self) -> bool:
        return self.plaintext_score >= 0.5


# ---------------------------------------------------------------------------
# Core parsing primitives
# ---------------------------------------------------------------------------


def _shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy of ``data`` in bits/byte (0.0 .. 8.0).

    Random / encrypted data tends toward 8.0; structured plaintext (ASN.1
    with repeating fields, ASCII, nomenclature codes) tends toward 4.0–6.5.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _find_nomenclature_hits(payload: bytes) -> list[str]:
    """Scan ``payload`` for well-known 11073 nomenclature codes."""
    hits: list[str] = []
    if len(payload) < 2:
        return hits
    for i in range(len(payload) - 1):
        code = (payload[i] << 8) | payload[i + 1]
        name = NOMENCLATURE_HINTS.get(code)
        if name and name not in hits:
            hits.append(name)
    return hits


def classify_payload(payload: bytes) -> tuple[float, list[str]]:
    """Classify ``payload`` as plaintext-telemetry vs high-entropy ciphertext.

    Returns ``(plaintext_score, nomenclature_hits)`` where ``plaintext_score``
    is in [0.0, 1.0]. The score combines:

      * Shannon entropy (lower => more plaintext-like).
      * Hits on the IEEE 11073-10101 nomenclature dictionary.
      * Presence of long zero runs (typical of structured ASN.1 fields).
    """
    if not payload:
        return (0.0, [])

    entropy = _shannon_entropy(payload)
    nomenclature_hits = _find_nomenclature_hits(payload)

    entropy_score = max(0.0, min(1.0, (7.5 - entropy) / 3.5))
    nomenclature_score = 1.0 if nomenclature_hits else 0.0
    zero_run = 0
    longest_zero_run = 0
    for b in payload:
        if b == 0:
            zero_run += 1
            longest_zero_run = max(longest_zero_run, zero_run)
        else:
            zero_run = 0
    structure_score = min(1.0, longest_zero_run / 8.0)

    score = max(entropy_score * 0.5 + structure_score * 0.2, nomenclature_score)
    return (min(1.0, score), nomenclature_hits)


def parse_apdu(buf: bytes) -> APDU | None:
    """Attempt to parse a single IEEE 11073-20601 APDU from ``buf``.

    The outer encoding per 11073-20601 is::

        +--------+--------+--------+--------+--------------+
        |    choice tag   |     length      |   value...   |
        +--------+--------+--------+--------+--------------+
             16 bits           16 bits           N bytes

    Returns ``None`` if the buffer does not begin with a recognised tag.
    """
    if len(buf) < 4:
        return None

    tag = struct.unpack(">H", buf[0:2])[0]
    apdu_type = APDU_TAGS.get(tag)
    if apdu_type is None:
        return None

    length = struct.unpack(">H", buf[2:4])[0]
    payload = buf[4 : 4 + length]
    return APDU(
        apdu_type=apdu_type,
        tag=tag,
        length=length,
        payload=payload,
        raw=buf[: 4 + length],
    )


def find_apdu_in_payload(payload: bytes) -> APDU | None:
    """Scan ``payload`` for the first recognisable 11073 APDU tag.

    Real captures often carry the APDU encapsulated inside another framing
    layer (BTLE L2CAP, MLLP, USB Personal Healthcare, etc). Rather than try
    to decode every transport, we *probe* the first 256 bytes for one of
    the known choice tags.
    """
    if not payload:
        return None
    horizon = min(len(payload) - 4, 256)
    for offset in range(horizon + 1):
        candidate = parse_apdu(payload[offset:])
        if candidate is not None:
            return candidate
    return None


# ---------------------------------------------------------------------------
# Public API: PCAP iteration
# ---------------------------------------------------------------------------


def _extract_l4_payload(pkt: "Packet") -> tuple[str, str, str, bytes]:
    """Pull the L4 payload + endpoints out of a scapy packet."""
    src = dst = transport = ""
    payload = b""

    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
    elif IPv6 in pkt:
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst

    if TCP in pkt:
        transport = "TCP"
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
    elif UDP in pkt:
        transport = "UDP"
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
    elif Raw in pkt:
        transport = "RAW"
        payload = bytes(pkt[Raw].load)

    return src, dst, transport, payload


def iter_pcap(pcap_path: str | Path) -> Iterator[ParsedPacket]:
    """Yield :class:`ParsedPacket` records from a PCAP file.

    Packets that do not contain a recognisable 11073 APDU are still yielded
    so the analyzer can flag bare cleartext telemetry (e.g., a vendor
    proprietary frame leaking pacing parameters).
    """
    if not _SCAPY_AVAILABLE:
        raise RuntimeError(
            "scapy is not installed. Install it with `pip install scapy>=2.5.0`."
        )

    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP not found: {path}")

    packets = rdpcap(str(path))
    for idx, pkt in enumerate(packets):
        timestamp = float(getattr(pkt, "time", 0.0))
        src, dst, transport, raw_payload = _extract_l4_payload(pkt)
        apdu = find_apdu_in_payload(raw_payload)

        if apdu is not None:
            plaintext_score, nomenclature_hits = classify_payload(apdu.payload)
        else:
            plaintext_score, nomenclature_hits = classify_payload(raw_payload)

        yield ParsedPacket(
            index=idx,
            timestamp=timestamp,
            src=src or "?",
            dst=dst or "?",
            transport=transport or "?",
            apdu=apdu,
            plaintext_score=plaintext_score,
            nomenclature_hits=nomenclature_hits,
        )


def parse_pcap(pcap_path: str | Path) -> list[ParsedPacket]:
    """Eagerly read a whole PCAP into memory."""
    return list(iter_pcap(pcap_path))


# ---------------------------------------------------------------------------
# Convenience: synthetic packet generator for unit tests / demos.
# ---------------------------------------------------------------------------


def synthesize_apdu(
    apdu_type: str = "PrstApdu",
    payload: bytes | None = None,
) -> bytes:
    """Build a synthetic 11073 APDU byte-string for tests / demos."""
    tag = next((t for t, n in APDU_TAGS.items() if n == apdu_type), 0xE700)
    body = payload if payload is not None else b""
    return struct.pack(">HH", tag, len(body)) + body


def synthesize_plaintext_pacing_payload(rate_bpm: int = 72) -> bytes:
    """Construct a payload that *looks* like plaintext pacing telemetry.

    Embeds the MDC_PACE_RATE_SET nomenclature code so the classifier will
    flag it as plaintext.
    """
    return (
        b"\x00\x00\x50\x00"            # MDC_PACE_RATE_SET nomenclature code
        + struct.pack(">H", rate_bpm)  # current pacing rate (BPM)
        + b"\x00" * 16                 # padding (ASN.1 zero-runs)
        + b"\x4A\x14"                  # MDC_HEART_RATE
        + struct.pack(">H", rate_bpm)
    )


__all__ = [
    "APDU",
    "APDU_TAGS",
    "NOMENCLATURE_HINTS",
    "ParsedPacket",
    "classify_payload",
    "find_apdu_in_payload",
    "iter_pcap",
    "parse_apdu",
    "parse_pcap",
    "synthesize_apdu",
    "synthesize_plaintext_pacing_payload",
]


def _iter_chunked(items: Iterable[ParsedPacket], size: int) -> Iterator[list[ParsedPacket]]:
    """Internal helper kept for symmetry with future streaming analyzers."""
    chunk: list[ParsedPacket] = []
    for item in items:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk
