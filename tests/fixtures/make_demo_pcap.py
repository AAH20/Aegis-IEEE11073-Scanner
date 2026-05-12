"""Generate a synthetic IEEE 11073-20601 demonstration PCAP.

The resulting capture contains a mix of:

* PrstApdus carrying plaintext pacing telemetry (MDC_PACE_RATE_SET +
  MDC_HEART_RATE nomenclature codes embedded in the payload).
* PrstApdus carrying high-entropy "encrypted" payloads.
* A 50 ms inter-arrival spike — the canonical "8 ms Cardiac Exploit"
  jitter signature — between two telemetry packets.
* AarqApdu / AareApdu association handshakes for realism.

This file is only used for end-to-end demonstration and is not part of
the unit test suite.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, wrpcap

# Allow running directly from the project root without an install.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from aegis.parser_11073 import (  # noqa: E402  (path manipulation above)
    synthesize_apdu,
    synthesize_plaintext_pacing_payload,
)


SRC_IP = "10.0.0.7"      # implant gateway
DST_IP = "10.0.0.2"      # monitoring station
SRC_PORT = 49152
DST_PORT = 11073         # IANA-registered IEEE 11073-20601


def _frame(payload: bytes, *, src: str = SRC_IP, dst: str = DST_IP) -> Ether:
    return (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / IP(src=src, dst=dst)
        / TCP(sport=SRC_PORT, dport=DST_PORT, flags="PA")
        / Raw(load=payload)
    )


def build_packets() -> list[Ether]:
    packets: list[Ether] = []

    aarq = synthesize_apdu("AarqApdu", payload=b"\x80\x00\x00\x00" + b"\x01" * 12)
    aare = synthesize_apdu("AareApdu", payload=b"\x80\x00\x00\x00" + b"\x02" * 12)
    packets.append(_frame(aarq))
    packets.append(_frame(aare, src=DST_IP, dst=SRC_IP))

    base = 1_726_401_123.000
    for i in range(20):
        plaintext = (i % 3 != 0)
        if plaintext:
            body = synthesize_plaintext_pacing_payload(rate_bpm=70 + (i % 5))
            body += b"\x00" * 16
        else:
            body = os.urandom(64)
        packets.append(_frame(synthesize_apdu("PrstApdu", payload=body)))

    rlrq = synthesize_apdu("RlrqApdu", payload=b"\x00\x00")
    rlre = synthesize_apdu("RlreApdu", payload=b"\x00\x00")
    packets.append(_frame(rlrq))
    packets.append(_frame(rlre, src=DST_IP, dst=SRC_IP))

    timestamps: list[float] = []
    timestamps.append(base - 0.100)
    timestamps.append(base - 0.090)
    for i in range(20):
        timestamps.append(base + i * 0.020)
    timestamps.append(base + 20 * 0.020 + 0.010)
    timestamps.append(base + 20 * 0.020 + 0.020)

    timestamps[2 + 10] += 0.050

    for pkt, ts in zip(packets, timestamps, strict=True):
        pkt.time = ts

    return packets


def main() -> None:
    out = Path(__file__).parent / "demo_icu_telemetry.pcap"
    packets = build_packets()
    wrpcap(str(out), packets)
    print(f"wrote {len(packets)} packets -> {out}")


if __name__ == "__main__":
    main()
