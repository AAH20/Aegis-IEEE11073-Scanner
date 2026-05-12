# Aegis-11073-Scanner

> **A brutally technical, lightweight Python CLI for auditing IEEE 11073 (MBAN / WBAN) traffic for plaintext biometric telemetry, missing application-layer authentication, and cyber-physical latency anomalies.**

`Aegis-11073-Scanner` ingests offline PCAP captures of IEEE 11073-20601 and 104xx device traffic, dissects the application-layer APDUs, and audits them against three classes of vulnerability that medical-device OEMs ship with embarrassing frequency:

1. **Plaintext biometric / pacing telemetry** — payloads that lack the AES-128-GCM wrapper mandated by IEEE 11073-40101:2022.
2. **Missing or weak Message Authentication Codes** — PrstApdus shipped without a 128-bit AEAD tag.
3. **The "8 ms Cardiac Exploit" jitter window** — inter-arrival deltas that exceed the safe scheduling budget for a pacing-class device, enabling localized DoS / flooding attacks.

The output is intentionally styled to look like a serious commercial audit deliverable. Drop it on a regulator's desk and watch the room go quiet.

---

## Disclaimer

> **This tool is for authorized WBAN / MBAN auditing only.** Unauthorized use against active medical implants, in-vivo telemetry links, or any clinical network constitutes a severe federal crime under (at minimum) the Computer Fraud and Abuse Act, HIPAA, and the FD&C Act's medical-device tampering provisions. Use only on lab-bench equipment, simulators, or networks for which you hold written authorization and IRB/FDA approval where applicable.

The author and contributors accept no liability for misuse. If you are not sure whether your use is authorized, **stop and consult counsel**.

---

## Features

- **Zero-config PCAP audit** — point it at a capture, get a colour-coded findings table.
- **Heuristic plaintext detector** — Shannon entropy + IEEE 11073-10101 nomenclature lookups (MDC_HEART_RATE, MDC_PACE_RATE_SET, MDC_DEFIB_SHOCK_ENERGY, …).
- **eCVSS-style severity scoring** — CRITICAL findings exit non-zero so it drops into CI gates without ceremony.
- **Pure Python, three deps** — `scapy`, `click`, `rich`. No native build, no JVM, no Docker.
- **Modular** — the parser, analyzer, and reporter are independently importable; embed them in your SBOM / SOUP pipeline.
- **Stubbed `live` mode** — refuses to sniff a real interface until you've documented FDA 21 CFR Part 820 change-control and IRB sign-off. By design.

---

## Installation

```bash
git clone https://github.com/your-org/aegis-11073-scanner.git
cd aegis-11073-scanner
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

Verify:

```bash
aegis version
```

---

## Usage

### Offline PCAP audit

```bash
aegis scan -f captures/icu_telemetry.pcap --verbose
```

Common flags:

| Flag | Description |
| --- | --- |
| `-f / --file` | Path to a PCAP / PCAPNG file. |
| `--jitter-threshold-ms` | Override the default 8 ms jitter budget. |
| `--plaintext-threshold` | Override the plaintext-score threshold (0.0–1.0). |
| `--verbose` | Include entropy scores, nomenclature hits, and median deltas. |

### Live mode (stubbed in MVP)

```bash
aegis live --interface bnep0
```

Live medical-network sniffing is **disabled by default**. The command prints the pre-flight checklist (root / CAP_NET_RAW, FDA change-control, IRB sign-off, patient-safety abort procedure, RF spectrum coordination) and exits.

---

## Example output

```text
╭──────────────────────────────────────────────────────────────╮
│ AEGIS-11073-SCANNER                                          │
│ IEEE 11073-20601 / 104xx Cyber-Physical Audit Report         │
│                                                              │
│ source: captures/icu_telemetry.pcap                          │
│ packets analysed: 1284                                       │
╰──────────────────────────────────────────────────────────────╯

                       Aegis Vulnerability Findings
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Timestamp      ┃ APDU Type  ┃ Vulnerability                            ┃ Severity (eCVSS)    ┃ Remediation                              ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1726401123.041 │ PrstApdu   │ Plaintext medical payload — application- │ CRITICAL (9.6)      │ Enforce IEEE 11073-40101:2022 AES-128-   │
│                │            │ layer AES-GCM encryption is missing      │                     │ GCM at the APDU boundary.                │
│ 1726401123.061 │ PrstApdu   │ Inter-arrival jitter 47.21 ms exceeds    │ CRITICAL (9.8)      │ Apply rate-limiting at the gateway,      │
│                │            │ 8.0 ms budget — cyber-physical DoS       │                     │ enable BLE L2CAP flow control, and pin   │
│                │            │ exposure on 10.0.0.7 -> 10.0.0.2         │                     │ a hard real-time scheduler.              │
│ 1726401123.081 │ PrstApdu   │ Missing cryptographic MAC — payload too  │ HIGH (8.1)          │ Append a 16-byte AES-GCM tag per IEEE    │
│                │            │ short to carry a 16-byte AEAD tag        │                     │ 11073-40101 §6.4.                        │
└────────────────┴────────────┴──────────────────────────────────────────┴─────────────────────┴──────────────────────────────────────────┘
╭───────────────────────────── VERDICT ─────────────────────────────╮
│ Findings by severity:  CRITICAL=2  HIGH=1  MEDIUM=0  LOW=0  INFO=0│
│                                                                   │
│  DEVICE FAILS CYBER-PHYSICAL SAFETY REVIEW  — at least one        │
│  CRITICAL exposure detected. Halt clinical deployment pending     │
│  remediation.                                                     │
╰───────────────────────────────────────────────────────────────────╯
```

Exit codes: `0` clean, `1` at least one CRITICAL, `2`/`3` operational error, `64` live-mode refused.

---

## Architecture

```text
src/aegis/
├── parser_11073.py   # APDU dissector + plaintext/ciphertext classifier
├── analyzer.py       # TelemetryAnalyzer — plaintext, MAC, jitter checks
├── reporter.py       # rich-based terminal report
└── cli.py            # click entry point (`aegis scan`, `aegis live`)
```

Embed in your own tooling:

```python
from aegis.parser_11073 import parse_pcap
from aegis.analyzer import TelemetryAnalyzer
from aegis.reporter import generate_report

packets = parse_pcap("captures/icu.pcap")
findings = TelemetryAnalyzer(jitter_threshold_ms=8.0).analyze(packets)
generate_report(findings, source="captures/icu.pcap", packet_count=len(packets))
```

---

## Testing

```bash
pip install -e ".[dev]"
pytest -q
```

The unit tests do not require a live PCAP and run in under a second.

---

## Roadmap

- Full ASN.1 MDER decoder (replace the byte-level probe).
- IEEE 11073-40101 conformance fuzzing harness.
- BLE GATT / L2CAP transport unwrap.
- JSON / SARIF report exporters for CI ingestion.
- Optional `--enable-live` build flag with documented safety interlocks.

---

## Need professional help?

> **Need help implementing IEEE 11073-40101:2022 compliant cryptography, hardware-level HSM key custody, or a defensible localized threat assessment for your medical-device program?**
>
> Contact **[Insert Your Firm's Name]** at **[insert@yourfirm.tld]** for a one-week localized threat assessment, regulator-grade reporting, and remediation engineering.

---

## License

MIT. See `pyproject.toml`.
