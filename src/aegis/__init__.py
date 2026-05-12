"""Aegis-11073-Scanner.

A brutally technical, lightweight Python CLI tool for auditing IEEE 11073
PCAP files and Medical Body Area Network (MBAN) traffic for plaintext
telemetry leaks, missing application-layer encryption, missing message
authentication codes, and latency / jitter anomalies that enable
cyber-physical attacks (e.g., the "8 ms Cardiac Exploit" class).

This package is intentionally modular:

    aegis.parser_11073  -- protocol dissection of IEEE 11073-20601 APDUs
    aegis.analyzer      -- vulnerability detection engine
    aegis.reporter      -- rich terminal reporting
    aegis.cli           -- click-based command-line entry point
"""

from __future__ import annotations

__all__ = [
    "__version__",
]

__version__: str = "0.1.0"
