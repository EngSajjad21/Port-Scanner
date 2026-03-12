# 🕵️‍♂️ Python Port Scanner & Vulnerability Detector

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/badge/license-GPLv3-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20|%20Windows-lightgrey.svg)

A professional, lightweight, and incredibly fast multi-threaded TCP Port Scanner written in Python. This tool not only discovers open ports but also performs **banner grabbing** and checks detected services against a **mini Vulnerability Database** (CVEs) on the fly.

Designed to be a rapid reconnaissance utility for penetration testing, server auditing, and general network diagnostics.

---

## ✨ Features

- **🚀 Insanely Fast Multi-Threading:** Uses Python's `concurrent.futures` to scan hundreds of ports simultaneously.
- **🎯 Banner Grabbing:** Protocol-specific requests to extract software versions (HTTP, FTP, SSH, etc.).
- **🛡️ Vulnerability Detection:** Compares grabbed banners against an internal CVE database for instant risk awareness.
- **🎨 Beautiful Terminal UI:** Real-time port discovery and clean progress tracking using `colorama`.
- **📂 Export to JSON:** Output structured JSON to the terminal or directly save it to a file for parsing in other tools.
- **🔌 Cross-Platform:** Works completely flawlessly on both Linux and Windows.

---

## 🛠️ Prerequisites

- Python 3.8+
- The `colorama` library (for cross-platform colored terminal output).

---

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/python-port-scanner.git
   cd python-port-scanner
   ```

2. **Install the required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Usage

You can use the built-in help menu to see all available options:
```bash
python scanner.py -h
```

### Basic Scan
Scans the default ports (1-1000) on the target IP:
```bash
python scanner.py -t 192.168.1.10
```

### Scan Specific Ports or Ranges
You can specify a single range or multiple specific ports:
```bash
python scanner.py -t example.com -p 21,22,80,443,1-100
```

### High-Speed Scan
Increase the number of concurrent worker threads (default is 100) for faster scanning across large ranges:
```bash
python scanner.py -t 192.168.1.1 -p 1-65535 -w 300
```

### Export to JSON File
Save the scan results into a structured `.json` file for future analysis:
```bash
python scanner.py -t 10.0.0.5 -p 1-1000 -s scan_results.json
```

### Output JSON to Terminal
Useful for piping into `jq` or other command-line tools:
```bash
python scanner.py -t 10.0.0.5 -p 80,443 -o json
```

---

## 📸 Example Output

**Terminal Output:**
```text
[*] Starting scan on target 192.168.1.10 (192.168.1.10)
[*] Scanning 1000 ports with 100 threads...

PORT     STATE    SERVICE              BANNER                         VULNERABILITIES
-------------------------------------------------------------------------------------
22       Open     OpenSSH 7.2          SSH-2.0-OpenSSH_7.2p2          CVE-2016-0777 Information Leak
80       Open     Apache 2.4.49        HTTP/1.1 400 Bad Request       CVE-2021-41773 Path Traversal
-------------------------------------------------------------------------------------
[*] Scan completed. Found 2 open ports.
```

**JSON Output:**
```json
{
    "target": "192.168.1.10",
    "hostname": "192.168.1.10",
    "open_ports": [
        {
            "port": 22,
            "state": "Open",
            "service": "OpenSSH 7.2",
            "banner": "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.1",
            "vulnerabilities": [
                "CVE-2016-0777 Information Leak"
            ]
        }
    ]
}
```

---

## ⚠️ Disclaimer

This tool is designed for **educational and professional use only**. You should only use this port scanner on systems, networks, and applications that you have explicit permission to audit. The authors take no responsibility and assume no liability for any misuse or damage caused by this program.

---

## 📝 License

Distributed under the GNU General Public License v3.0 (GPLv3). See `LICENSE` for more information.
