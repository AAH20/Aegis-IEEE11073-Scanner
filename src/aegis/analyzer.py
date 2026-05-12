"""Vulnerability detection engine for Aegis-11073-Scanner.

Given a stream of :class:`aegis.parser_11073.ParsedPacket` records, the
:class:`TelemetryAnalyzer` runs three independent audits:

1.  **Plaintext payload check** — any pacing / telemetry APDU whose payload
    fails the high-entropy ciphertext heuristic is flagged. IEEE 11073-40101
    explicitly requires AES-GCM at the application layer for life-critical
    devices; plaintext biometric or pacing fields are a CRITICAL finding.

2.  **MAC integrity check** — IEEE 11073-40101 §6.4 mandates an AEAD MAC tag
    (typically a 16-byte GCM tag) appended to every PrstApdu. The analyzer
    flags packets whose payload is too short to carry a tag, or whose
    trailing 16 bytes show low entropy (i.e., not a real MAC).

3.  **8 ms latency / jitter anomaly check** — for streams of pacing or
    telemetry packets between the same endpoint pair, the analyzer computes
    inter-arrival deltas and flags any delta whose deviation from the
    rolling median exceeds 8 ms. This is the canonical signature of the
    "8 ms Cardiac Exploit" class of localized DoS / flooding attacks.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Literal

from .parser_11073 import ParsedPacket


Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


# ---------------------------------------------------------------------------
# Tunables — these are deliberately exposed so an auditor can override them
# from the CLI if a particular device class has different timing budgets.
# ---------------------------------------------------------------------------

DEFAULT_JITTER_THRESHOLD_MS: float = 8.0
DEFAULT_MIN_MAC_BYTES: int = 16              # AES-GCM tag
DEFAULT_MAC_UNIQUE_BYTES_THRESHOLD: int = 10  # tag of 16 bytes < 10 unique = suspect
DEFAULT_PLAINTEXT_SCORE_THRESHOLD: float = 0.5


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Finding:
    """A single vulnerability finding raised against a parsed packet."""

    timestamp: float
    packet_index: int
    apdu_type: str
    vulnerability: str
    severity: Severity
    e_cvss: float
    remediation: str
    details: str = ""

    def as_row(self) -> tuple[str, str, str, str, str]:
        """Render as a 5-tuple for the rich report table."""
        return (
            f"{self.timestamp:.6f}",
            self.apdu_type,
            self.vulnerability,
            f"{self.severity} ({self.e_cvss:.1f})",
            self.remediation,
        )


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


@dataclass
class TelemetryAnalyzer:
    """Run the three Aegis vulnerability checks over a packet stream."""

    jitter_threshold_ms: float = DEFAULT_JITTER_THRESHOLD_MS
    min_mac_bytes: int = DEFAULT_MIN_MAC_BYTES
    mac_unique_bytes_threshold: int = DEFAULT_MAC_UNIQUE_BYTES_THRESHOLD
    plaintext_score_threshold: float = DEFAULT_PLAINTEXT_SCORE_THRESHOLD

    findings: list[Finding] = field(default_factory=list)

    # ------------------------------------------------------------------ API

    def analyze(self, packets: Iterable[ParsedPacket]) -> list[Finding]:
        """Run all checks and return the accumulated findings list."""
        materialized = list(packets)

        for pkt in materialized:
            self._check_plaintext(pkt)
            self._check_mac_integrity(pkt)

        self._check_jitter(materialized)
        return self.findings

    # ---------------------------------------------------------------- check 1

    def _check_plaintext(self, pkt: ParsedPacket) -> None:
        if pkt.apdu is None:
            return

        if pkt.plaintext_score < self.plaintext_score_threshold:
            return

        is_critical_apdu = pkt.apdu.is_pacing_or_telemetry
        severity: Severity = "CRITICAL" if is_critical_apdu else "HIGH"
        e_cvss = 9.6 if is_critical_apdu else 7.8

        hits = ", ".join(pkt.nomenclature_hits) or "no nomenclature codes recovered"

        self.findings.append(
            Finding(
                timestamp=pkt.timestamp,
                packet_index=pkt.index,
                apdu_type=pkt.apdu.apdu_type,
                vulnerability=(
                    "Plaintext medical payload — application-layer "
                    "AES-GCM encryption is missing"
                ),
                severity=severity,
                e_cvss=e_cvss,
                remediation=(
                    "Enforce IEEE 11073-40101:2022 AES-128-GCM at the APDU "
                    "boundary. Reject any PrstApdu lacking an AEAD wrapper."
                ),
                details=(
                    f"plaintext_score={pkt.plaintext_score:.2f}; "
                    f"nomenclature_hits=[{hits}]"
                ),
            )
        )

    # ---------------------------------------------------------------- check 2

    def _check_mac_integrity(self, pkt: ParsedPacket) -> None:
        if pkt.apdu is None or not pkt.apdu.is_pacing_or_telemetry:
            return

        payload = pkt.apdu.payload

        if len(payload) < self.min_mac_bytes:
            self.findings.append(
                Finding(
                    timestamp=pkt.timestamp,
                    packet_index=pkt.index,
                    apdu_type=pkt.apdu.apdu_type,
                    vulnerability=(
                        "Missing cryptographic MAC — payload too short to "
                        f"carry a {self.min_mac_bytes}-byte AEAD tag"
                    ),
                    severity="HIGH",
                    e_cvss=8.1,
                    remediation=(
                        "Append a 16-byte AES-GCM authentication tag to "
                        "every PrstApdu per IEEE 11073-40101 §6.4."
                    ),
                    details=f"payload_len={len(payload)}",
                )
            )
            return

        trailing = payload[-self.min_mac_bytes :]
        unique_bytes = len(set(trailing))
        if unique_bytes < self.mac_unique_bytes_threshold:
            self.findings.append(
                Finding(
                    timestamp=pkt.timestamp,
                    packet_index=pkt.index,
                    apdu_type=pkt.apdu.apdu_type,
                    vulnerability=(
                        "Suspect MAC trailer — trailing bytes lack the "
                        "uniqueness profile of a genuine AEAD tag"
                    ),
                    severity="MEDIUM",
                    e_cvss=6.5,
                    remediation=(
                        "Verify MAC construction. Re-key using HKDF-derived "
                        "session keys and confirm GCM tag length = 128 bits."
                    ),
                    details=(
                        f"trailing_unique_bytes={unique_bytes}/"
                        f"{self.min_mac_bytes}"
                    ),
                )
            )

    # ---------------------------------------------------------------- check 3

    def _check_jitter(self, packets: list[ParsedPacket]) -> None:
        streams: dict[tuple[str, str], list[ParsedPacket]] = defaultdict(list)
        for pkt in packets:
            if pkt.apdu is None or not pkt.apdu.is_pacing_or_telemetry:
                continue
            streams[(pkt.src, pkt.dst)].append(pkt)

        for (src, dst), stream in streams.items():
            if len(stream) < 3:
                continue

            stream.sort(key=lambda p: p.timestamp)
            deltas_ms = [
                (stream[i].timestamp - stream[i - 1].timestamp) * 1000.0
                for i in range(1, len(stream))
            ]

            try:
                median = statistics.median(deltas_ms)
            except statistics.StatisticsError:
                continue

            for i, delta in enumerate(deltas_ms, start=1):
                jitter = abs(delta - median)
                if jitter > self.jitter_threshold_ms:
                    offender = stream[i]
                    assert offender.apdu is not None  # narrowed above
                    self.findings.append(
                        Finding(
                            timestamp=offender.timestamp,
                            packet_index=offender.index,
                            apdu_type=offender.apdu.apdu_type,
                            vulnerability=(
                                f"Inter-arrival jitter {jitter:.2f} ms exceeds "
                                f"{self.jitter_threshold_ms:.1f} ms budget — "
                                f"cyber-physical DoS / flooding exposure on "
                                f"{src} -> {dst}"
                            ),
                            severity="CRITICAL",
                            e_cvss=9.8,
                            remediation=(
                                "Apply rate-limiting at the gateway, enable "
                                "BLE L2CAP flow control, and pin a hard "
                                "real-time scheduler on the pacing thread."
                            ),
                            details=(
                                f"median_delta_ms={median:.2f}; "
                                f"observed_delta_ms={delta:.2f}"
                            ),
                        )
                    )


__all__ = [
    "DEFAULT_JITTER_THRESHOLD_MS",
    "DEFAULT_MAC_UNIQUE_BYTES_THRESHOLD",
    "DEFAULT_MIN_MAC_BYTES",
    "DEFAULT_PLAINTEXT_SCORE_THRESHOLD",
    "Finding",
    "Severity",
    "TelemetryAnalyzer",
]
