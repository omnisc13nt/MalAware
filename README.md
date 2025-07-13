# PE File Parser

A comprehensive, cross-platform C++ tool for advanced Portable Executable (PE) file analysis and malware detection. Designed for security researchers, reverse engineers, and malware analysts.

## 🚀 Features

### Core PE Analysis
- **Complete Header Parsing**: DOS, NT, File, and Optional headers with detailed analysis
- **Section Analysis**: Comprehensive section characteristics, properties, and flags
- **Import/Export Tables**: Complete function listings, dependency analysis, and forwarded exports
- **Data Directories**: All 16 data directory entries with RVA validation and integrity checks
- **Architecture Detection**: Accurate x86/x64 detection using PE Magic field
- **Resource Parsing**: Complete resource directory tree with type identification

### Advanced Security Analysis
- **TLS Analysis**: Thread Local Storage directory and callback detection
- **Malware Detection Engine**: Multi-vector threat analysis with 0-100 risk scoring system
- **Digital Signature Verification**: Complete certificate chain validation and trust analysis
- **Entropy Analysis**: Statistical analysis for detecting packed/encrypted content
- **Anti-Analysis Detection**: Identifies anti-debugging and anti-VM techniques
- **Obfuscation Detection**: Recognizes import table corruption and code obfuscation

### Hash & Integrity Analysis
- **Multi-Algorithm Hashing**: MD5, SHA-1, SHA-256, Imphash, Authentihash, SSDeep, TLSH, VHash
- **Section-Level Hashing**: Individual section integrity verification
- **Fuzzy Hashing**: SSDeep for similarity analysis and variant detection
- **Import Hashing**: Imphash for malware family classification

### Debug & Metadata Analysis
- **Debug Information**: Symbol tables, CodeView data, and compilation artifacts
- **Rich Header Analysis**: Compiler and linker version detection for attribution
- **Overlay Detection**: Identifies and analyzes appended data beyond PE structure
- **Anomaly Detection**: Structural inconsistencies and malformation detection

### Threat Intelligence
- **Packer Detection**: Identifies known packers (UPX, ASPack, PECompact, Themida, VMProtect)
- **Code Injection Indicators**: Process hollowing and DLL injection technique detection
- **Suspicious Import Analysis**: Identifies malicious API usage patterns
- **Risk Classification**: Automated threat categorization (Clean/Suspicious/Malicious)

## 🔧 Quick Start

### Build
```bash
make          # Build for Linux
make windows  # Cross-compile for Windows
make clean    # Clean build artifacts
```

### Usage
```bash
./peFileParserLinux <pe_file>
```

### Output
- **Console**: Real-time analysis with detailed logging
- **ParseResults.txt**: Complete analysis report
- **Logs.txt**: Technical debugging information

## 📊 Sample Analysis Output

For a complete example of the parser's output when analyzing a malware sample, see: [Sample Output Example](SAMPLE_OUTPUT.md)

The analysis includes:
- Complete PE structure breakdown
- Malware risk assessment (0-100 score)
- Threat indicator identification
- TLS callback analysis
- Import/export table examination
- Hash fingerprinting

## 🏗️ Architecture

### Core Components
- **peParser**: Main PE parsing and validation engine
- **PEMalwareAnalysisEngine**: Advanced threat detection and risk scoring
- **PETLSAnalyzer**: Thread Local Storage analysis and callback detection
- **PESecurityAnalyzer**: Security feature and anomaly detection
- **PEHashCalculator**: Multi-algorithm hash computation and integrity verification

### Cross-Platform Design
- **Linux**: Native GCC compilation
- **Windows**: MinGW cross-compilation support
- **Dependencies**: Standard C++ libraries only - no external dependencies

## 🎯 Use Cases

### Malware Analysis
- Threat assessment and triage
- Malware family classification
- Packer identification and unpacking preparation
- Anti-analysis technique detection

### Digital Forensics
- File authenticity verification
- Evidence integrity validation
- Timeline analysis via compilation timestamps
- Malware attribution through metadata analysis

### Reverse Engineering
- PE structure exploration and understanding
- Import/export dependency mapping
- Resource extraction and analysis planning
- Debug symbol availability assessment

### Security Research
- Vulnerability research preparation
- Binary analysis automation
- Threat intelligence gathering
- Attack technique identification

## � Detection Capabilities

### Malware Indicators
- **Packers**: UPX, ASPack, PECompact, Themida, VMProtect, and custom packers
- **Anti-Debug**: IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess
- **Anti-VM**: VMware, VirtualBox, Sandboxie detection techniques
- **Code Injection**: Process hollowing, DLL injection, manual DLL loading
- **Obfuscation**: Import table corruption, string obfuscation, control flow obfuscation

### Risk Assessment Metrics
- **Risk Score**: 0-100 numerical assessment
- **Severity Levels**: Individual indicator severity (1-10 scale)
- **Classification**: Clean, Suspicious, Malicious categories
- **Confidence**: Analysis confidence indicators

## 📋 System Requirements

### Minimum Requirements
- **OS**: Linux (Ubuntu 18.04+) or Windows 10+
- **Compiler**: GCC 7.0+ or MinGW-w64
- **RAM**: 512MB available memory
- **Storage**: 50MB for binaries and temporary files

### Recommended
- **OS**: Recent Linux distribution or Windows 10/11
- **RAM**: 2GB+ for large file analysis
- **Storage**: 1GB+ for extensive logging and output files

## 🛡️ Security Considerations

### Safe Analysis Practices
- **Isolated Environment**: Always analyze unknown files in sandboxed environments
- **Network Isolation**: Disconnect from networks when analyzing active malware
- **Backup Systems**: Maintain clean system snapshots before analysis
- **Access Controls**: Limit tool access to authorized personnel only

### Handling Malicious Files
- Use virtual machines for malware analysis
- Implement proper containment procedures
- Maintain updated antivirus definitions
- Follow organizational incident response procedures

## 📄 License

MIT License - see LICENSE file for complete terms.

## 🙏 Attribution

This project enhances and extends the original [PE-Explorer](https://github.com/adamhlt/PE-Explorer) by adamhlt, adding comprehensive malware analysis capabilities and cross-platform support.
