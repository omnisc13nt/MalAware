# PE File Parser

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++17](https://img.shields.io/badge/C++-17-blue.svg)](https://isocpp.org/)

A C++ tool for analyzing Portable Executable (PE) files with advanced malware detection capabilities.

> **Inspired by [@adamhlt/PE-Explorer](https://github.com/adamhlt/PE-Explorer)**: This project expands on the original concept with additional malware detection features.

---

## Features

### Core PE Analysis
- **Complete PE Structure Parsing** - DOS, NT, File, and Optional headers
- **Section Analysis** - Entropy calculations, RWX detection, size analysis
- **Import/Export Analysis** - Function analysis with suspicious API detection
- **Resource Analysis** - Version info, icons, manifests, embedded resources
- **Digital Signature Verification** - Certificate validation and trust analysis

### Malware Detection
- **Timestamp Analysis** - Detects modified compilation timestamps and known malware signatures
- **Overlay Detection** - Identifies hidden payloads beyond PE structure
- **Structural Validation** - PE format integrity and corruption detection
- **Section Anomalies** - RWX section detection and packer identification
- **String Analysis** - Suspicious pattern matching and obfuscation detection

### Cryptographic Analysis
- **Hash Generation** - MD5, SHA-1, SHA-256, Import hash (Imphash)
- **Fuzzy Hashing** - SSDeep, TLSH, VHash for malware family identification
- **Entropy Analysis** - Mathematical entropy calculation for each section
- **Section Hashing** - Individual section analysis for forensic investigation

### Reporting
- **Multiple Output Levels** - From summary to detailed forensic analysis
- **Performance Metrics** - Analysis timing and memory usage
- **File Output** - Save results to text files
- **Threat Assessment** - Risk scoring and security recommendations

---

## Installation

### Requirements
- **Operating System**: Linux (Ubuntu 18.04+, CentOS 7+, Debian 9+)
- **Compiler**: GCC 7.0+ with C++17 support
- **Dependencies**: libfuzzy (for fuzzy hashing)

### Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install build-essential libfuzzy-dev
```

**CentOS/RHEL:**
```bash
sudo yum install gcc-c++ libfuzzy-devel
```

**Fedora:**
```bash
sudo dnf install gcc-c++ libfuzzy-devel
```

### Build
```bash
git clone https://github.com/michaelangelo23/peParse.git
cd peParse
make clean && make
```

---

## Usage

### Basic Syntax
```bash
./peFileParser [OPTIONS] <PE_FILE>
```

### Common Options
| Option | Description |
|--------|-------------|
| `-h`, `--help` | Show help information |
| `-v`, `--verbose` | Detailed analysis output |
| `-s`, `--summary` | Summary analysis only |
| `--malware` | Comprehensive malware analysis |
| `-o <file>` | Save output to file |
| `--only-threats` | Show only threat detections |

### Usage Examples

**Basic Analysis:**
```bash
./peFileParser malware.exe
```

**Summary Analysis:**
```bash
./peFileParser -s malware.exe
```

**Detailed Analysis with File Output:**
```bash
./peFileParser -v malware.exe -o analysis_report.txt
```

**Threat-Only Analysis:**
```bash
./peFileParser --only-threats malware.exe
```

---

## Sample Output

### Basic Analysis
```
[INFO] Starting PE file analysis for: malware.exe
[+] Successfully loaded PE file: malware.exe
[+] Architecture: x86

[+] PE IMAGE SECTIONS
	SECTION : .text
		VirtualAddress : 0x1000
		SizeOfRawData : 0x8000
		Characteristics : 0x60000020 (EXECUTE | READ)

	SECTION : .rdata
		VirtualAddress : 0x9000
		SizeOfRawData : 0x12000
		Characteristics : 0x40000040 (READ)

[+] IMPORTED DLL
	DLL NAME : KERNEL32.dll
	Imported Functions : 
		IsDebuggerPresent
		GetCurrentProcess
		[+] Found 16 imported functions.

[+] PE file parsing completed successfully!
```

### Threat Analysis
```
[+] SUSPICIOUS TECHNIQUE ANALYSIS
=================================================
Techniques Detected: 2
Total Threat Score: 14/100
Threat Level: MEDIUM

Technique #1: Entry Point Outside Code Section
├─ Severity Level: 8/10 (HIGH)
├─ Description: Entry point is located outside the main code section
├─ Evidence Found: Entry Point: 0x33648, Code Size: 0x32768
└─ Analysis: This indicates potential code injection

Technique #2: Entropy Variance Anomaly  
├─ Severity Level: 6/10 (MEDIUM)
├─ Description: Large entropy variance between sections
├─ Evidence Found: Entropy range: 0.59 - 6.02
└─ Analysis: Mixed entropy suggests selective packing
=================================================
```

### Hash Analysis
```
[+] FILE HASHES
	MD5: 250b77dfbb1b666e95b3bcda082de287
	SHA-1: 5a699a8f64046d3d7fb5014d0242c159a04b8eed
	SHA-256: 3639e8cc463922b427ea20dce8f237c0c0e82aa51d2502c48662e60fb405f677
	Imphash: da66ef376b879ce11d1bbaa919914462
	SSDeep: 3072:cAVBCZJlDSFqUjJsS4ImRuCdtId2kf7eyg91WBuCdEkOrSmUCqQelwkqsJfee7Wy
```

---

## Detection Capabilities

The tool implements several malware detection techniques:

### Timestamp Analysis
- Detects modified compilation timestamps
- Identifies known malware signatures (including WannaCry timestamp: 0x4D4E196B)
- Flags anachronistic and future timestamps

### Overlay Detection
- Identifies data appended beyond PE structure
- Calculates entropy of overlay data
- Detects embedded PE files in overlays

### Packer Detection
- Recognizes common packers: UPX, ASPack, Themida, PECompact
- Analyzes section names for packer signatures
- Detects suspicious entry points

### Section Analysis
- Identifies RWX (read/write/execute) sections
- Calculates entropy for each section
- Detects unusual section characteristics

### Import Analysis
- Flags suspicious API functions
- Detects anti-debugging imports
- Analyzes import obfuscation techniques

---

## Supported File Types

The tool supports all standard PE file formats:

| Extension | Type | Description |
|-----------|------|-------------|
| `.exe` | Executable | Windows executable files |
| `.dll` | Dynamic Library | Windows library files |
| `.sys` | System Driver | Windows system drivers |
| `.scr` | Screen Saver | Windows screen saver files |
| `.com` | COM Executable | COM executable files |
| `.ocx` | ActiveX Control | ActiveX control files |
| `.cpl` | Control Panel | Control panel applets |

## Performance

Typical performance characteristics:

| File Size | Analysis Time | Memory Usage |
|-----------|---------------|--------------|
| < 1MB | 0.02-0.1s | 0.5-2MB |
| 1-10MB | 0.1-0.5s | 2-8MB |
| 10-50MB | 0.5-2s | 8-32MB |

## Security Notes

- **Always analyze suspicious files in isolated environments**
- **Use virtual machines for malware analysis**
- **Never execute analyzed files on production systems**
- **Analysis results may contain sensitive information**

---

## Troubleshooting

### Build Issues
```bash
# Install missing dependencies
sudo apt-get install build-essential libfuzzy-dev

# Check compiler version (requires GCC 7.0+)
gcc --version
```

### Runtime Issues
```bash
# Make executable
chmod +x peFileParser

# Check file exists
ls -la testFolder/

# Increase memory limit if needed
ulimit -v 2097152
```

### Library Issues
```bash
# Verify libfuzzy installation
ldconfig -p | grep fuzzy

# Reinstall if missing
sudo apt-get install libfuzzy-dev
```
## Acknowledgments

- **[@adamhlt/PE-Explorer](https://github.com/adamhlt/PE-Explorer)** - Original inspiration and foundation
- **Security research community** - Feedback and contributions on reddit

---

For issues and feature requests, please use the [GitHub Issues](https://github.com/michaelangelo23/peParse/issues) page.

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

---

## Supported File Types

- .exe, .dll, .sys, .scr, .com, .ocx (PE format files)

---

## Project Status

- **Still in Development**

---

**Attribution:**  
This project was inspired by [@adamhlt/PE-Explorer](https://github.com/adamhlt/PE-Explorer). 
Expanded and enhanced on personal endeavors by yours truly.
