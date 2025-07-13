# PE File Parser

A cross-platform C++ tool for comprehensive analysis of Portable Executable (PE) files. Provides cryptographic hash calculation, import/export analysis, security feature detection, and malware threat assessment.

## Features

- **Cryptographic Hashes**: MD5, SHA-1, SHA-256, Import Hash (Imphash)
- **PE Structure Analysis**: Headers, sections, imports, exports, resources
- **Security Assessment**: ASLR/DEP detection, threat scoring, anomaly detection
- **Import Analysis**: Function enumeration with obfuscation detection
- **Digital Signatures**: PKCS#7 parsing and certificate extraction
- **Cross-Platform**: Native Linux execution for Windows PE analysis

## Quick Start

### Installation

#### Prerequisites
- C++ compiler with C++17 support
- Make utility

#### Build
```bash
# Clone and build
git clone <repository-url>
cd peFileParser
make clean && make

# Windows cross-compilation (requires MinGW)
make windows
```

### Basic Usage
```bash
# Analyze a PE file
./peFileParserLinux sample.exe

# Save to custom output file
./peFileParserLinux sample.exe -o analysis_report.txt

# Help information
./peFileParserLinux -h
```

## Output Example
```
=== PE File Analysis Report ===
File: example.exe
MD5: 4d126a74212250584edad0f21daaf06c
SHA-1: cac28f26e1d89c0c71ea954e5d79c72e5402f1a0
SHA-256: ce397d1a47b24efe2b90da9e565386dbb69175d5e170468f498b82e5cd394b60

=== Security Assessment ===
Risk Score: 0/100
Classification: Clean/Low Risk
ASLR: Enabled | DEP: Enabled | Digital Signature: Present
```

## Documentation

- **[DOCUMENTATION.md](DOCUMENTATION.md)** - Complete user guide and usage reference

## Attribution

This project was originally inspired by and built upon the [PE-Explorer](https://github.com/adamhlt/PE-Explorer) repository by adamhlt.

## License

MIT License - see [LICENSE](LICENSE) file for details.
