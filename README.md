# PE File Parser

A C++ tool for analyzing Portable Executable (PE) files, designed to help security researchers and malware analysts perform offline malware detection and threat analysis.

> **Inspired by [@adamhlt/PE-Explorer](https://github.com/adamhlt/PE-Explorer): This project expands on Adam’s original idea and implementation.**

---

## Features

- **PE Header Parsing:** DOS, NT, and Optional headers
- **Section Analysis:** Entropy calculations, RWX detection, packer identification
- **Import/Export Analysis:** Lists imported/exported functions, flags suspicious APIs
- **Resource & Signature Analysis:** Checks for embedded resources and digital signatures
- **Malware Detection Algorithms:** Timestamp analysis, overlay anomaly detection, section anomalies, suspicious strings, anti-analysis techniques
- **Cryptographic Analysis:** Generates MD5, SHA-1, SHA-256, and fuzzy hashes (ssdeep)
- **Reporting:** Risk scoring, detailed analysis reports, performance metrics, multiple output formats

---

## Installation

**Ubuntu/Debian**
```bash
sudo apt-get update
sudo apt-get install build-essential libfuzzy-dev
```
**CentOS/RHEL**
```bash
sudo yum install gcc-c++ libfuzzy-devel
```

**Build**
```bash
git clone <repository>
cd peFileParser
make clean && make
```

---

## Usage

**Basic Analysis**
```bash
./peFileParser /path/to/file.exe
```

**Verbose Output**
```bash
./peFileParser -v /path/to/file.exe
```

**Options**
- `-h`, `--help`: Show help
- `-v`, `--verbose`: Detailed analysis

---

## Example Output

```
ANALYSIS SUMMARY
File: malware_sample.exe
Size: 0.12 MB
Architecture: x86

Quick Security Assessment:
Digital Signature: Not Present
Entropy Analysis: Normal
Packing Detection: None Detected

Suspicious Techniques:
1. Entry Point Outside Code Section
2. Entropy Variance Anomaly

Risk Assessment: MEDIUM

Fuzzy Hash (ssdeep): 3072:...
TLSH: T1aae0c69242b438f2b42f...
```

---

## Supported File Types

- .exe, .dll, .sys, .scr, .com, .ocx (PE format files)

---

## Project Status

- **Still in Development**

---

## License

MIT License — Free for professional security research & cybersecurity operations.

---

**Attribution:**  
This project was inspired by [@adamhlt/PE-Explorer](https://github.com/adamhlt/PE-Explorer). Expanded and enhanced by yours truly.
