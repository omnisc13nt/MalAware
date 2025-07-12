
# PE File Parser

PE File Parser is a cross-platform C++ tool for analyzing Portable Executable (PE) files. It supports both 32-bit and 64-bit executables, DLLs, and drivers. The project is modular, maintainable, and suitable for reverse engineering, malware analysis, and research.

## Features

- Parse DOS, NT, File, and Optional headers
- List all PE sections and their characteristics
- Analyze Import and Export tables
- Show all Data Directory entries
- Detect architecture (x86/x64)
- Error handling with clear codes
- Cross-platform: Windows, Linux, macOS

## Project Structure

```
peFileParser/
├── include/                 # Header files
│   ├── pe_common.h         # Common definitions
│   ├── pe_file_handler.h   # File I/O
│   ├── pe_header_parser.h  # Header parsing
│   ├── pe_section_parser.h # Section parsing
│   ├── pe_import_export.h  # Import/Export parsing
│   └── pe_parser.h         # Main orchestration
├── src/                    # Source files
│   ├── pe_file_handler.cpp
│   ├── pe_header_parser.cpp
│   ├── pe_section_parser.cpp
│   ├── pe_import_export.cpp
│   └── pe_parser.cpp
├── main.cpp                # Original version
├── main_new.cpp            # Modular version
├── Makefile                # GNU Make build
├── CMakeLists.txt          # CMake build
└── README.md
```

## Build Instructions

### Using Make
```bash
make            # Build modular version (default)
make peFileParser  # Build original version
make clean      # Remove build files
make help       # Show available targets
```

### Using CMake
```bash
mkdir build && cd build
cmake ..
make
# Executables will be in bin/
```

### Manual Compilation
```bash
g++ -std=c++17 -O2 -Iinclude main_new.cpp src/*.cpp -o peFileParser_modular
```

## Usage

```bash
# Analyze a PE file
./peFileParser_modular <path_to_pe_file>

# Get help
./peFileParser_modular
```

## Example Output


### tsetup-x64.5.9.0.exe Analysis Example
```
[+] Successfully loaded PE file: tsetup-x64.5.9.0.exe
[+] Architecture: x86
[+] PE IMAGE INFORMATION

[+] Architecture x86

[+] DOS HEADER
    e_magic : 0x5A4D
    e_cblp : 0x50
    e_cp : 0x2
    e_crlc : 0x0
    e_cparhdr : 0x4
    e_minalloc : 0xF
    e_maxalloc : 0xFFFF
    e_ss : 0x0
    e_sp : 0xB8
    e_csum : 0x0
    e_ip : 0x0
    e_cs : 0x0
    e_lfarlc : 0x40
    e_ovno : 0x1A
    e_oemid : 0x0
    e_oeminfo : 0x0
    e_lfanew : 0x100

[+] NT HEADER
    Signature : 0x4550

[+] FILE HEADER
    Machine : 0x14C
    NumberOfSections : 0xB
    TimeDateStamp : 0x6690DABD
    PointerToSymbolTable : 0x0
    NumberOfSymbols : 0x0
    SizeOfOptionalHeader : 0xE0
    Characteristics : 0x102 (EXE)

[+] OPTIONAL HEADER
    Magic : 0x10B
    MajorLinkerVersion : 0x2
    MinorLinkerVersion : 0x19
    SizeOfCode : 0xA7400
    SizeOfInitializedData : 0x22A00
    SizeOfUninitializedData : 0x0
    AddressOfEntryPoint : 0xA83BC
    BaseOfCode : 0x1000
    BaseOfData : 0xA9000
    ImageBase : 0x400000
    SectionAlignment : 0x1000
    FileAlignment : 0x200
    MajorOperatingSystemVersion : 0x6
    MinorOperatingSystemVersion : 0x1
    MajorImageVersion : 0x0
    MinorImageVersion : 0x0
    MajorSubsystemVersion : 0x6
    MinorSubsystemVersion : 0x1
    Win32VersionValue : 0x0
    SizeOfImage : 0xD8000
    SizeOfHeaders : 0x400
    CheckSum : 0x2C7D71B
    Subsystem : 0x2 (GUI APP)
    DllCharacteristics : 0x8140
    SizeOfStackReserve : 0x100000
    SizeOfStackCommit : 0x4000
    SizeOfHeapReserve : 0x100000
    SizeOfHeapCommit : 0x1000
    LoaderFlags : 0x0
    NumberOfRvaAndSizes : 0x10

[+] DATA DIRECTORIES
    DataDirectory (Export Table) VirtualAddress : 0xB7000
    DataDirectory (Export Table) Size : 0x71

    DataDirectory (Import Table) VirtualAddress : 0xB5000
    DataDirectory (Import Table) Size : 0xFEC

    DataDirectory (Resource Table) VirtualAddress : 0xCB000
    DataDirectory (Resource Table) Size : 0xC9F0

    DataDirectory (Security Entry) VirtualAddress : 0x2C76E98
    DataDirectory (Security Entry) Size : 0x2B08

    DataDirectory (Relocation Table) VirtualAddress : 0xBA000
    DataDirectory (Relocation Table) Size : 0x10FA8

    DataDirectory (TLS Entry) VirtualAddress : 0xB9000
    DataDirectory (TLS Entry) Size : 0x18

    DataDirectory (IAT) VirtualAddress : 0xB52D4
    DataDirectory (IAT) Size : 0x25C

    DataDirectory (Delay Import Descriptor) VirtualAddress : 0xB6000
    DataDirectory (Delay Import Descriptor) Size : 0x1A4


[+] PE IMAGE SECTIONS

    SECTION : .text
        Misc (PhysicalAddress) : 0xA568C
        Misc (VirtualSize) : 0xA568C
        VirtualAddress : 0x1000
        SizeOfRawData : 0xA5800
        PointerToRawData : 0x400
        PointerToRelocations : 0x0
        PointerToLinenumbers : 0x0
        NumberOfRelocations : 0x0
        NumberOfLinenumbers : 0x0
        Characteristics : 0x60000020 (EXECUTE | READ)

    SECTION : .itext
        Misc (PhysicalAddress) : 0x1B64
        Misc (VirtualSize) : 0x1B64
        VirtualAddress : 0xA7000
        SizeOfRawData : 0x1C00
        PointerToRawData : 0xA5C00
        PointerToRelocations : 0x0
        PointerToLinenumbers : 0x0
        NumberOfRelocations : 0x0
        NumberOfLinenumbers : 0x0
        Characteristics : 0x60000020 (EXECUTE | READ)

    SECTION : .data
        Misc (PhysicalAddress) : 0x3838
        Misc (VirtualSize) : 0x3838
        VirtualAddress : 0xA9000
        SizeOfRawData : 0x3A00
        PointerToRawData : 0xA7800
        PointerToRelocations : 0x0
        PointerToLinenumbers : 0x0
        NumberOfRelocations : 0x0
        NumberOfLinenumbers : 0x0
        Characteristics : 0xC0000040 (READ | WRITE)

    SECTION : .bss
        Misc (PhysicalAddress) : 0x7258
        Misc (VirtualSize) : 0x7258
        VirtualAddress : 0xAD000
        SizeOfRawData : 0x0
        PointerToRawData : 0x0
        PointerToRelocations : 0x0
        PointerToLinenumbers : 0x0
        NumberOfRelocations : 0x0
        NumberOfLinenumbers : 0x0
        Characteristics : 0xC0000000 (READ | WRITE)

    SECTION : .idata
        Misc (PhysicalAddress) : 0xFEC
        Misc (VirtualSize) : 0xFEC
        VirtualAddress : 0xB5000
        SizeOfRawData : 0x1000
        PointerToRawData : 0xAB200
        PointerToRelocations : 0x0
        PointerToLinenumbers : 0x0
        NumberOfRelocations : 0x0
        NumberOfLinenumbers : 0x0
        Characteristics : 0xC0000040 (READ | WRITE)

    SECTION : .didata
        Misc (PhysicalAddress) : 0x1A4
        Misc (VirtualSize) : 0x1A4
        VirtualAddress : 0xB6000
        SizeOfRawData : 0x200
        PointerToRawData : 0xAC200
        PointerToRelocations : 0x0
        PointerToLinenumbers : 0x0
        NumberOfRelocations : 0x0
        NumberOfLinenumbers : 0x0
        Characteristics : 0xC0000040 (READ | WRITE)

    SECTION : .edata
        Misc (PhysicalAddress) : 0x71
        Misc (VirtualSize) : 0x71
        VirtualAddress : 0xB7000
        SizeOfRawData : 0x200
        PointerToRawData : 0xAC400
        PointerToRelocations : 0x0
        PointerToLinenumbers : 0x0
        NumberOfRelocations : 0x0
        NumberOfLinenumbers : 0x0
        Characteristics : 0x40000040 (READ)

    SECTION : .tls
        Misc (PhysicalAddress) : 0x18
        Misc (VirtualSize) : 0x18
        VirtualAddress : 0xB8000
        SizeOfRawData : 0x0
        PointerToRawData : 0x0
        PointerToRelocations : 0x0
        PointerToLinenumbers : 0x0
        NumberOfRelocations : 0x0
        NumberOfLinenumbers : 0x0
        Characteristics : 0xC0000000 (READ | WRITE)

    SECTION : .rdata
        Misc (PhysicalAddress) : 0x5D
        Misc (VirtualSize) : 0x5D
        VirtualAddress : 0xB9000
        SizeOfRawData : 0x200
        PointerToRawData : 0xAC600
        PointerToRelocations : 0x0
        PointerToLinenumbers : 0x0
        NumberOfRelocations : 0x0
        NumberOfLinenumbers : 0x0
        Characteristics : 0x40000040 (READ)

    SECTION : .reloc
        Misc (PhysicalAddress) : 0x10FA8
        Misc (VirtualSize) : 0x10FA8
        VirtualAddress : 0xBA000
        SizeOfRawData : 0x11000
        PointerToRawData : 0xAC800
        PointerToRelocations : 0x0
        PointerToLinenumbers : 0x0
        NumberOfRelocations : 0x0
        NumberOfLinenumbers : 0x0
        Characteristics : 0x42000040 (READ)

    SECTION : .rsrc
        Misc (PhysicalAddress) : 0xC9F0
        Misc (VirtualSize) : 0xC9F0
        VirtualAddress : 0xCB000
        SizeOfRawData : 0xCA00
        PointerToRawData : 0xBD800
        PointerToRelocations : 0x0
        PointerToLinenumbers : 0x0
        NumberOfRelocations : 0x0
        NumberOfLinenumbers : 0x0
        Characteristics : 0x40000040 (READ)

[+] IMPORTED DLL

    DLL NAME : kernel32.dll
    Characteristics : 0xC8856288
    OriginalFirstThunk : 0xC8856288
    TimeDateStamp : 0xC87A1210
    ForwarderChain : 0xC87A1210
    FirstThunk : 0xC88564E4

    Imported Functions : 

Segmentation fault (core dumped)
```

## Error Codes

| Code | Constant | Description |
|------|----------|-------------|
| 0    | PE_SUCCESS | Operation completed successfully |
| -1   | PE_ERROR_FILE_OPEN | File access error |
| -2   | PE_ERROR_INVALID_PE | Invalid PE format |
| -3   | PE_ERROR_MEMORY_ALLOCATION | Memory allocation failed |
| -4   | PE_ERROR_PARSING | Parsing error occurred |

## Technical Notes

- The parser uses custom PE structure definitions for cross-platform compatibility.
- All parsing is done in-memory; no dependencies on Windows API.
- Output is printed to stdout in a readable format.

## License

MIT License. See [LICENSE](LICENSE) for details.

## References

- [Microsoft PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [MODULARIZATION_IMPROVEMENTS.md](MODULARIZATION_IMPROVEMENTS.md)
