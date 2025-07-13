# PE File Parser

A comprehensive cross-platform PE (Portable Executable) file parser and analyzer written in C++. This tool provides detailed analysis of Windows PE files including headers, sections, imports, exports, and resources with **advanced malware detection capabilities** featuring import obfuscation detection, security assessment, and evidence-based threat classification.

> 📊 **Quick Start**: See [sampleOutput.md](sampleOutput.md) for comprehensive analysis examples

## Features

### Core PE Analysis
- **PE Header Analysis**: DOS header, NT headers, optional headers, and data directories
- **Section Analysis**: Detailed section information including entropy analysis
- **Import/Export Table Analysis**: Complete import and export function enumeration with corruption detection
- **Resource Parsing**: Extraction and analysis of embedded resources
- **Digital Signature Verification**: Certificate chain validation and signature analysis
- **Security Features Detection**: ASLR, DEP, SEH, CFG status analysis

### Advanced Security Analysis
- **Malware Detection Engine**: Multi-vector threat analysis with calibrated risk scoring (0-100 scale)
- **Import Obfuscation Detection**: Identifies corrupted import tables with 119+ invalid entries in malware samples
- **Security Feature Assessment**: ASLR/DEP/SEH/CFG analysis with compliance checking
- **Anomaly Detection**: Suspicious characteristics identification and security violations
- **Entropy Analysis**: Section-by-section entropy calculation for packed/encrypted content detection
- **Hash Generation**: Multiple algorithms (MD5, SHA-1, SHA-256, Imphash) plus fuzzy hashing support
- **Overlay Detection**: Analysis of data appended to PE files with entropy assessment
- **Threat Classification**: Evidence-based assessment with actionable security recommendations

### Output and Integration
- **Flexible Output Options**: Customizable output file naming with `-o` option
- **Cross-Platform**: Native support for Linux and Windows analysis environments
- **Command-Line Interface**: Easy integration into security workflows
- **Detailed Reporting**: Structured analysis with evidence-based threat assessment

## Installation

### Prerequisites
- C++ compiler with C++11 support (GCC/Clang/MSVC)
- Make utility

### Linux Build
```bash
# Clone the repository
git clone <repository-url>
cd peFileParser

# Build using Make
make clean
make
```

### Windows Build
```bash
# Using MinGW or Visual Studio
make clean
make
```

## Usage

### Basic Syntax
```bash
./peFileParserLinux <pe-file> [options]
```

### Command Line Options
- `-o <filename>` : Specify custom output file name
- `-h` : Display help information

### Example Usage

#### Basic Analysis
```bash
./peFileParserLinux sample.exe
```

#### Custom Output File
```bash
./peFileParserLinux sample.exe -o custom_analysis.txt
```

#### Cross-Platform Analysis
```bash
# Linux
./peFileParserLinux target.exe -o linux_analysis.txt

# Windows  
peFileParserLinux.exe target.exe -o windows_analysis.txt
```

> 💡 **Tip**: See [sampleOutput.md](sampleOutput.md) for real analysis examples comparing legitimate software (0/100 risk) vs malware (20/100 risk) with detailed technical breakdowns.

## Real-World Analysis Examples

> 📊 **For comprehensive side-by-side analysis examples, see [sampleOutput.md](sampleOutput.md)**

The following examples demonstrate the parser's capabilities on real-world samples:
### Legitimate Software Analysis
Analysis of Telegram Desktop installer (`tsetup-x64.5.9.0.exe`):

```
[+] PE IMAGE INFORMATION
Architecture: x64
File Type: Win32 EXE
File Size: 47.85 MB (50,184,728 bytes)
Compilation Time: 2024-04-30 10:15:30 UTC

[+] SECURITY FEATURES
ASLR (Address Space Layout Randomization): ENABLED
DEP (Data Execution Prevention): ENABLED
SEH (Structured Exception Handling): ENABLED
CFG (Control Flow Guard): ENABLED

[+] IMPORTED DLL ANALYSIS
- 146 imported functions across 5 legitimate DLLs
- All import entries valid and properly structured
- No obfuscation detected

[+] DIGITAL SIGNATURE ANALYSIS
File is digitally signed: YES
Signature Valid: YES
Signer: Telegram FZ-LLC
Certificate Chain: Valid

[+] MALWARE ANALYSIS
Risk Score: 0/100
Classification: Clean/Low Risk
Suspicious: NO
Threat Indicators: None detected
Recommendation: File appears legitimate and safe.
```

### Malware Analysis
Analysis of suspicious executable with obfuscated imports:

```
[+] PE IMAGE INFORMATION
Architecture: x86
File Type: Win32 EXE
File Size: 0.36 MB (379,056 bytes)
Compilation Time: 2007-12-24 21:04:20 UTC

[+] SECURITY FEATURES
ASLR (Address Space Layout Randomization): DISABLED
DEP (Data Execution Prevention): DISABLED
SEH (Structured Exception Handling): ENABLED

[+] IMPORTED DLL ANALYSIS
DLL NAME: emTextA [INVALID]
- 589 imported functions (19 invalid/corrupted)
- [POSSIBLE OBFUSCATION DETECTED]
- Import table shows signs of obfuscation

DLL NAME: [Invalid] [SUSPICIOUS]
- 522 imported functions (17 invalid/corrupted)
- Import obfuscation commonly used by malware

[+] ANOMALY DETECTION
Anomalies found: 2
[1] ASLR is disabled - potential security risk
[2] DEP is disabled - potential security risk

[+] MALWARE ANALYSIS
Risk Score: 20/100
Classification: Suspicious
Suspicious: YES
Threat Indicators (1 found):
  [Obfuscation] Import table obfuscation detected (Severity: 8/10)
  Evidence: Corrupted import table entries detected during parsing
Recommendation: Exercise caution. Consider additional analysis with behavioral tools.
```

> 🔍 **See [sampleOutput.md](sampleOutput.md) for detailed side-by-side comparison** showing how the parser differentiates between legitimate software and malware with comprehensive analysis results.

## Documentation

### Sample Analysis Showcase
📋 **[sampleOutput.md](sampleOutput.md)** - Comprehensive side-by-side analysis comparison
- Legitimate software vs malware sample analysis
- Detailed feature-by-feature comparison tables
- Security assessment methodology demonstration
- Import obfuscation detection examples
- Risk scoring and threat classification examples

### Analysis Reports
- **Import/Export Analysis**: Function enumeration with corruption detection
- **Security Assessment**: Evidence-based threat indicators with severity scoring
- **Malware Detection**: Multi-vector analysis with calibrated risk assessment
- **Cross-Platform Compatibility**: Consistent results across Linux and Windows environments

## Key Capabilities

### Import/Export Analysis
- Complete function enumeration with corruption detection
- Obfuscation detection in import tables using statistical analysis
- Invalid DLL name identification
- Import address table (IAT) analysis with integrity checking

### Security Assessment
- Calibrated risk scoring system (0-100 scale)
- Evidence-based threat indicator classification
- Security feature compliance checking
- Comprehensive anomaly detection and reporting

### Hash Generation
- Complete hash suite: MD5, SHA-1, SHA-256, Imphash
- Fuzzy hashing (SSDeep) for similarity analysis
- Locality-sensitive hashing (TLSH) for clustering
- Section-level hash calculation

### Cross-Platform Support
- Native Linux execution for Windows PE analysis
- Consistent output format across platforms
- Flexible output file management with `-o` option
- Command-line integration ready for automation

## Technical Details

### Supported PE Features
- 32-bit and 64-bit PE files
- DLL and EXE analysis
- Resource extraction and enumeration
- Digital signature verification
- Rich header parsing
- Overlay detection and analysis

### Security Analysis Engine
- Heuristic-based threat detection with configurable thresholds
- Multi-vector analysis approach combining static indicators
- Evidence-based reporting with severity scoring
- Reduced false positives through statistical analysis

### Output Formats
- Human-readable text analysis
- Structured data presentation with clear categorization
- Detailed technical information for security researchers
- Security-focused summaries with actionable recommendations

## Build System

### Makefile Targets
```bash
make          # Build for Linux
make windows  # Cross-compile for Windows (requires MinGW)
make clean    # Clean build artifacts
```

### Dependencies
- Standard C++ libraries only
- No external dependencies required
- Cross-platform compatibility with GCC/MinGW

## Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest improvements.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

Built with focus on practical malware analysis and security research applications. Designed for both automated analysis pipelines and manual security assessment workflows with emphasis on accuracy and reduced false positives.
