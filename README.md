# 🔬 Memory Forensics Triage Tool

Automated memory dump triage: Volatility 3 + detection rules + IOC extraction + report generation.

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![Volatility 3](https://img.shields.io/badge/Volatility-3-orange)
![License](https://img.shields.io/badge/License-MIT-green)

## Features
- 🖥️ Process list + hidden process detection (pslist vs psscan)
- 🌐 Network connections extraction
- 🔑 Credential dumping indicators (lsass)
- 🧬 Malware injection detection (malfind)
- 📋 Auto-generated Markdown/HTML/JSON report
- 🔍 IOC extraction (IPs, domains, hashes, paths → STIX/JSON)

## Quick Start
```bash
pip install -r requirements.txt
triage --dump mem.raw --profile auto --output report.md
```

## Architecture
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Status
🚧 Design phase — scaffolding in progress.

## Author
Amdjed Salhi

## License
MIT
