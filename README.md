# PE File Parser

A static analysis tool for Windows PE files. Analyzes file structure, computes hashes, and detects suspicious characteristics.

## Build

Requirements:
- Linux with GCC (C++17)
- libfuzzy-dev

```bash
make
```

## Usage

```bash
./peFileParser [options] <file.exe>
```

Options:
- `-v` : Verbose output
- `-h` : Help

## Features

- PE structure parsing (headers, sections, imports/exports)
- Hash computation (MD5, SHA-1, SHA-256, SSDeep, imphash)
- Packer detection (UPX, ASPack, Themida)
- Suspicious pattern analysis
- Entropy analysis

## Example Output

```
File: sample.exe
Size: 122880 bytes
Architecture: x86

Hashes:
MD5:    250b77dfbb1b666e95b3bcda082de287
SHA-1:  5a699a8f64046d3d7fb5014d0242c159a04b8eed

Sections:
.text   : executable, entropy 6.2
.rdata  : read-only, entropy 4.8  
.data   : writable, entropy 2.1

Imports: kernel32.dll, user32.dll
```

## Installation

Ubuntu/Debian:
```bash
sudo apt-get install build-essential libfuzzy-dev
```

CentOS/RHEL:
```bash
sudo yum install gcc-c++ libfuzzy-devel
```

## Note

This tool performs static analysis only. Use in isolated environments when analyzing suspicious files.
