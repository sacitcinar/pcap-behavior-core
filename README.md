# 🔎 PCAP Behavior Core

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Interface](https://img.shields.io/badge/Interface-CLI-555555)
![License](https://img.shields.io/badge/License-MIT-008000)
![Dependencies](https://img.shields.io/badge/Runtime-Standard%20Library-555555)

PCAP Behavior Core is a Python command-line application for analyzing network
behavior in `.pcap` files. It generates a structured JSON file and a standalone
HTML report that can be opened without a server or internet connection.

## ✨ Features

- **TCP connection scanning patterns:** Repeated SYN attempts across destination ports or IP addresses, evaluated using target diversity, timing and observed responses.
- **Periodic TCP connections:** Repeated communications with measurable timing consistency.
- **DNS observations:** Matched DNS query/response records and concentrated NXDOMAIN activity.
- **Traffic observations:** Long-duration TCP flows and outbound traffic volumes.
- **FTP control observations:** Commands and server reply codes observed on TCP port 21. Credentials and file paths are excluded from the report.
- **Evidence details:** Connection counts, time windows, endpoints and linked packet references.

The tool does not use threat signatures, external threat-intelligence services or cloud APIs.

## 📦 Installation

**Requirements:** Python 3.10 or later.

Clone or download the repository, then run the following commands in its root directory:

```bash
python -m pip install .
```

You can also run the source directly without installing it:

```bash
python -m pcapcore capture.pcap
```

## 🚀 Usage

```bash
python -m pcapcore capture.pcap
```

For a full analysis, the default outputs are written next to the input file:

```text
capture.pcap.observations.json
capture.pcap.observations.html
```

To choose a location for both outputs:

```bash
python -m pcapcore capture.pcap -o results/analysis.json
```

This creates `results/analysis.json` and `results/analysis.html`. The `-o` option is optional. With a successful full analysis, HTML output is enabled by default.

If installed with `pip`, the CLI command is also available:

```bash
pcap-behavior-core capture.pcap
```

Additional options:

```bash
python -m pcapcore --help
python -m pcapcore capture.pcap --local-cidr 192.168.1.0/24
python -m pcapcore capture.pcap --overwrite
```

The input PCAP is not modified. Existing report files are not overwritten unless `--overwrite` is specified.

## 📊 Output

| File | Content |
| --- | --- |
| **JSON** | Structured capture summary, observations and finding previews. |
| **HTML** | Offline report with the full set of findings, supporting evidence and traffic tables. |

Open the `.html` file in any modern browser to inspect the results. Captures are processed locally.

## 📸 Screenshots
### Overview
<img width="1353" height="764" alt="Screenshot_8" src="https://github.com/user-attachments/assets/ed537f1e-aa3f-43bb-a8fa-2ba73b7d27af" />

### Behavior Findings
<img width="1348" height="767" alt="Screenshot_9" src="https://github.com/user-attachments/assets/cd73f0af-1e04-442a-81bb-b1ade2299551" />

## 📁 Project Structure

```text
pcap-behavior-core/
├── pcapcore/
│   ├── __init__.py
│   ├── __main__.py
│   ├── artifacts.py
│   ├── beaconing.py
│   ├── cli.py
│   ├── context_pipeline.py
│   ├── correlation.py
│   ├── correlation_pipeline.py
│   ├── dashboard_data.py
│   ├── decoders.py
│   ├── detection_pipeline.py
│   ├── dns_behavior.py
│   ├── dns_events.py
│   ├── dns_pipeline.py
│   ├── engine.py
│   ├── episode_pipeline.py
│   ├── episodes.py
│   ├── features.py
│   ├── flows.py
│   ├── ftp_control.py
│   ├── host_dns_context.py
│   ├── pipeline.py
│   ├── reader.py
│   ├── report_html.py
│   ├── scan_pipeline.py
│   ├── scanning.py
│   ├── traffic_behavior.py
│   └── traffic_pipeline.py
├── pyproject.toml
├── README.md
├── LICENSE
└── .gitignore
```

## 📄 License

This project is licensed under the [MIT License](LICENSE).

## ⚠️ Disclaimer

PCAP Behavior Core reports observable network behavior, not confirmed attacks,
malware infections or malicious intent. Incomplete captures, encrypted traffic,
asymmetric visibility and legitimate automated traffic can affect the results.
A finding should be interpreted alongside other evidence. Reports can contain
capture-derived addresses and metadata; review them before sharing.
