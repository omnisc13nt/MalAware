# PE File Parser

PE File Parser is a cross-platform C++ tool for analyzing Portable Executable (PE) files. It supports both 32-bit and 64-bit executables, DLLs, and drivers with comprehensive logging capabilities.

---

**Attribution:**
This project is a remake and modular refactor of the original [PE-Explorer](https://github.com/adamhlt/PE-Explorer) repository by adamhlt.

## Features

- **Complete PE Analysis**: Parse DOS, NT, File, and Optional headers
- **Section Analysis**: List all PE sections with detailed characteristics
- **Import/Export Tables**: Analyze import and export tables with function listings
- **Data Directories**: Show all Data Directory entries with RVA and size
- **Architecture Detection**: Automatically detect x86/x64 architecture
- **Resource Parsing**: Extract and display resource information
- **Dual Logging System**: 
  - Clean console output for users
  - Comprehensive debug logs in `Logs.txt` with timestamps
  - Session-based logging with start/end markers
- **Error Handling**: Robust error handling with clear error codes
- **Cross-Platform**: Windows, Linux, macOS support
- **No Dependencies**: Pure C++ implementation, no external libraries

## Project Structure

```
peFileParser/
├── include/                 # Header files
│   ├── peCommon.h          # Common definitions and Logger system
│   ├── peFileHandler.h     # File I/O operations
│   ├── peHeaderParser.h    # Header parsing functions
│   ├── peSectionParser.h   # Section parsing functions
│   ├── peImportExport.h    # Import/Export table parsing
│   ├── peParser.h          # Main parser orchestration
│   ├── PEParser.h          # PE parsing class
│   ├── PERelocationParser.h # Relocation table parsing
│   └── PEResourceParser.h  # Resource parsing
├── src/                    # Source files
│   ├── peFileHandler.cpp
│   ├── peHeaderParser.cpp
│   ├── peSectionParser.cpp
│   ├── peImportExport.cpp
│   ├── peParser.cpp
│   ├── PEParser.cpp
│   ├── PERelocationParser.cpp
│   ├── PEResourceParser.cpp
│   └── Logger.cpp          # Logging system implementation
├── main.cpp                # Main application entry point
├── Makefile                # Build system (Linux & Windows)
├── testFolder/             # Test PE files
│   └── LosslessScaling.exe # Sample 64-bit executable
├── Logs.txt                # Debug logs (auto-generated)
├── ParseResults.txt        # Complete parsing output (auto-generated)
└── README.md
```

## Build Instructions

### Prerequisites
You need a C++17-compatible compiler and build tools:

#### Linux/WSL
```bash
sudo apt-get update
sudo apt-get install build-essential g++ mingw-w64
```

#### Windows
Install [MSYS2](https://www.msys2.org/) and run:
```bash
pacman -S mingw-w64-x86_64-gcc make
```

### Building

#### Using Makefile (Recommended)
```bash
make              # Build Linux version
make windows      # Build Windows version
make cross        # Build both versions
make clean        # Clean build artifacts
```

#### Manual Build
```bash
# Linux
g++ -std=c++17 -O2 -Iinclude main.cpp src/*.cpp -o peFileParserLinux

# Windows cross-compilation (from Linux)
x86_64-w64-mingw32-g++ -std=c++17 -O2 -Iinclude main.cpp src/*.cpp -o peFileParserWindows.exe -static-libgcc -static-libstdc++
```

## Usage

```bash
# Analyze a PE file (Linux)
./peFileParserLinux <path_to_pe_file>

# Analyze a PE file (Windows)
./peFileParserWindows.exe <path_to_pe_file>

# Example
./peFileParserLinux testFolder/LosslessScaling.exe

# Get help
./peFileParserLinux
```

### Output Files
The parser automatically generates separate output files for different purposes:

1. **Console Output**: Clean, user-friendly analysis results displayed in terminal
2. **Logs.txt**: Comprehensive debug logs with timestamps
   - Session markers for multiple runs
   - Detailed parsing steps and memory addresses
   - Error diagnostics and troubleshooting information
3. **ParseResults.txt**: Complete parsing output for reference (auto-generated)
   - Contains the same information as console output but saved to file
   - Useful for documentation, further analysis, and sharing results
   - Generated automatically with each analysis
4. **ParseOutput.txt**: Structured output from Logger system (internal use)

## Example Output

### LosslessScaling.exe Analysis Example
```
[INFO] Starting PE file analysis for: testFolder/LosslessScaling.exe
[+] Successfully loaded PE file: testFolder/LosslessScaling.exe
[+] Architecture: x64
[+] PE IMAGE INFORMATION

[+] Architecture x64

[+] DOS HEADER
	e_magic : 0x5A4D
	e_cblp : 0x90
	e_cp : 0x3
	e_crlc : 0x0
	e_cparhdr : 0x4
	e_minalloc : 0x0
	e_maxalloc : 0xFFFF
	e_ss : 0x0
	e_sp : 0xB8
	e_csum : 0x0
	e_ip : 0x0
	e_cs : 0x0
	e_lfarlc : 0x40
	e_ovno : 0x0
	e_oemid : 0x0
	e_oeminfo : 0x0
	e_lfanew : 0xE8

[+] NT HEADER
	Signature : 0x4550

[+] FILE HEADER
	Machine : 0x8664
	NumberOfSections : 0x6
	TimeDateStamp : 0x67FE0000
	PointerToSymbolTable : 0x0
	NumberOfSymbols : 0x0
	SizeOfOptionalHeader : 0xF0
	Characteristics : 0x22 (EXE)

[+] OPTIONAL HEADER
	Magic : 0x20B
	MajorLinkerVersion : 0xE
	MinorLinkerVersion : 0x2A
	SizeOfCode : 0x17000
	SizeOfInitializedData : 0x10400
	SizeOfUninitializedData : 0x0
	AddressOfEntryPoint : 0x12880
	BaseOfCode : 0x1000
	ImageBase : 0x140000000
	SectionAlignment : 0x1000
	FileAlignment : 0x200
	MajorOperatingSystemVersion : 0x6
	MinorOperatingSystemVersion : 0x0
	MajorImageVersion : 0x0
	MinorImageVersion : 0x0
	MajorSubsystemVersion : 0x6
	MinorSubsystemVersion : 0x0
	Win32VersionValue : 0x0
	SizeOfImage : 0x2A000
	SizeOfHeaders : 0x400
	CheckSum : 0x0
	Subsystem : 0x2 (GUI APP)
	DllCharacteristics : 0xC160
	SizeOfStackReserve : 0x180000
	SizeOfStackCommit : 0x1000
	SizeOfHeapReserve : 0x100000
	SizeOfHeapCommit : 0x1000
	LoaderFlags : 0x0
	NumberOfRvaAndSizes : 0x10

[+] DATA DIRECTORIES
	DataDirectory (Import Table) VirtualAddress : 0x20FD4
	DataDirectory (Import Table) Size : 0x104

	DataDirectory (Resource Table) VirtualAddress : 0x27000
	DataDirectory (Resource Table) Size : 0x2C0C

	DataDirectory (Exception Entry) VirtualAddress : 0x24000
	DataDirectory (Exception Entry) Size : 0x1440

	DataDirectory (Relocation Table) VirtualAddress : 0x26000
	DataDirectory (Relocation Table) Size : 0x328

	DataDirectory (Debug Entry) VirtualAddress : 0x1D980
	DataDirectory (Debug Entry) Size : 0x70

	DataDirectory (TLS Entry) VirtualAddress : 0x1DB80
	DataDirectory (TLS Entry) Size : 0x28

	DataDirectory (Configuration Entry) VirtualAddress : 0x1D840
	DataDirectory (Configuration Entry) Size : 0x140

	DataDirectory (IAT) VirtualAddress : 0x18000
	DataDirectory (IAT) Size : 0x448

[+] PE IMAGE SECTIONS

	SECTION : .text
		Misc (PhysicalAddress) : 0x16FEC
		Misc (VirtualSize) : 0x16FEC
		VirtualAddress : 0x1000
		SizeOfRawData : 0x17000
		PointerToRawData : 0x400
		PointerToRelocations : 0x0
		PointerToLinenumbers : 0x0
		NumberOfRelocations : 0x0
		NumberOfLinenumbers : 0x0
		Characteristics : 0x60000020 (EXECUTE | READ)

	SECTION : .rdata
		Misc (PhysicalAddress) : 0x9F48
		Misc (VirtualSize) : 0x9F48
		VirtualAddress : 0x18000
		SizeOfRawData : 0xA000
		PointerToRawData : 0x17400
		PointerToRelocations : 0x0
		PointerToLinenumbers : 0x0
		NumberOfRelocations : 0x0
		NumberOfLinenumbers : 0x0
		Characteristics : 0x40000040 (READ)

	SECTION : .data
		Misc (PhysicalAddress) : 0x1A90
		Misc (VirtualSize) : 0x1A90
		VirtualAddress : 0x22000
		SizeOfRawData : 0xC00
		PointerToRawData : 0x21400
		PointerToRelocations : 0x0
		PointerToLinenumbers : 0x0
		NumberOfRelocations : 0x0
		NumberOfLinenumbers : 0x0
		Characteristics : 0xC0000040 (READ | WRITE)

	SECTION : .pdata
		Misc (PhysicalAddress) : 0x1440
		Misc (VirtualSize) : 0x1440
		VirtualAddress : 0x24000
		SizeOfRawData : 0x1600
		PointerToRawData : 0x22000
		PointerToRelocations : 0x0
		PointerToLinenumbers : 0x0
		NumberOfRelocations : 0x0
		NumberOfLinenumbers : 0x0
		Characteristics : 0x40000040 (READ)

	SECTION : .reloc
		Misc (PhysicalAddress) : 0x328
		Misc (VirtualSize) : 0x328
		VirtualAddress : 0x26000
		SizeOfRawData : 0x400
		PointerToRawData : 0x23600
		PointerToRelocations : 0x0
		PointerToLinenumbers : 0x0
		NumberOfRelocations : 0x0
		NumberOfLinenumbers : 0x0
		Characteristics : 0x42000040 (READ)

	SECTION : .rsrc
		Misc (PhysicalAddress) : 0x2C0C
		Misc (VirtualSize) : 0x2C0C
		VirtualAddress : 0x27000
		SizeOfRawData : 0x2E00
		PointerToRawData : 0x23A00
		PointerToRelocations : 0x0
		PointerToLinenumbers : 0x0
		NumberOfRelocations : 0x0
		NumberOfLinenumbers : 0x0
		Characteristics : 0x40000040 (READ)

[+] IMPORTED DLL

	DLL NAME : SHELL32.dll
	Characteristics : 0x212F8
	OriginalFirstThunk : 0x212F8
	TimeDateStamp : 0x0
	ForwarderChain : 0x0
	FirstThunk : 0x18220

	Imported Functions : 

		ShellExecuteW
		[+] Found 1 imported functions.

	DLL NAME : ADVAPI32.dll
	Characteristics : 0x210D8
	OriginalFirstThunk : 0x210D8
	TimeDateStamp : 0x0
	ForwarderChain : 0x0
	FirstThunk : 0x18000

	Imported Functions : 

		RegCloseKey
		ReportEventW
		RegisterEventSourceW
		RegOpenKeyExW
		RegGetValueW
		DeregisterEventSource
		[+] Found 6 imported functions.

	DLL NAME : KERNEL32.dll
	Characteristics : 0x21110
	OriginalFirstThunk : 0x21110
	TimeDateStamp : 0x0
	ForwarderChain : 0x0
	FirstThunk : 0x18038

	Imported Functions : 

		TlsFree
		CreateActCtxW
		ActivateActCtx
		GetLastError
		FindResourceW
		GetWindowsDirectoryW
		GetProcAddress
		GetModuleHandleW
		FreeLibrary
		LoadLibraryExW
		FindFirstFileExW
		EnterCriticalSection
		GetFullPathNameW
		FindNextFileW
		GetCurrentProcess
		GetStdHandle
		GetModuleHandleExW
		GetFinalPathNameByHandleW
		GetModuleFileNameW
		LeaveCriticalSection
		GetEnvironmentVariableW
		FindClose
		CreateFileW
		MultiByteToWideChar
		GetConsoleMode
		GetFileAttributesExW
		LoadLibraryA
		CloseHandle
		WriteConsoleW
		DeleteCriticalSection
		WideCharToMultiByte
		IsWow64Process
		OutputDebugStringW
		GetSystemTimeAsFileTime
		TlsSetValue
		TlsGetValue
		TlsAlloc
		InitializeCriticalSectionAndSpinCount
		SetLastError
		RaiseException
		RtlPcToFileHeader
		RtlUnwindEx
		InitializeSListHead
		GetCurrentProcessId
		IsDebuggerPresent
		IsProcessorFeaturePresent
		TerminateProcess
		SetUnhandledExceptionFilter
		UnhandledExceptionFilter
		RtlVirtualUnwind
		RtlLookupFunctionEntry
		RtlCaptureContext
		GetStringTypeW
		SwitchToThread
		GetCurrentThreadId
		InitializeCriticalSectionEx
		EncodePointer
		DecodePointer
		LCMapStringEx
		QueryPerformanceCounter
		[+] Found 60 imported functions.

	DLL NAME : USER32.dll
	Characteristics : 0x21308
	OriginalFirstThunk : 0x21308
	TimeDateStamp : 0x0
	ForwarderChain : 0x0
	FirstThunk : 0x18230

	Imported Functions : 

		MessageBoxW
		[+] Found 1 imported functions.

	DLL NAME : api-ms-win-crt-runtime-l1-1-0.dll
	Characteristics : 0x213C8
	OriginalFirstThunk : 0x213C8
	TimeDateStamp : 0x0
	ForwarderChain : 0x0
	FirstThunk : 0x182F0

	Imported Functions : 

		_get_initial_wide_environment
		_initialize_wide_environment
		_errno
		_configure_wide_argv
		_initterm
		_set_app_type
		_seh_filter_exe
		_cexit
		_initterm_e
		exit
		_register_onexit_function
		_initialize_onexit_table
		_invalid_parameter_noinfo_noreturn
		_exit
		abort
		__p___wargv
		_c_exit
		_register_thread_local_exe_atexit_callback
		_crt_atexit
		__p___argc
		terminate
		[+] Found 21 imported functions.

	DLL NAME : api-ms-win-crt-heap-l1-1-0.dll
	Characteristics : 0x21330
	OriginalFirstThunk : 0x21330
	TimeDateStamp : 0x0
	ForwarderChain : 0x0
	FirstThunk : 0x18258

	Imported Functions : 

		malloc
		_set_new_mode
		_callnewh
		calloc
		free
		[+] Found 5 imported functions.

	DLL NAME : api-ms-win-crt-time-l1-1-0.dll
	Characteristics : 0x21500
	OriginalFirstThunk : 0x21500
	TimeDateStamp : 0x0
	ForwarderChain : 0x0
	FirstThunk : 0x18428

	Imported Functions : 

		_time64
		wcsftime
		_gmtime64_s
		[+] Found 3 imported functions.

	DLL NAME : api-ms-win-crt-stdio-l1-1-0.dll
	Characteristics : 0x21478
	OriginalFirstThunk : 0x21478
	TimeDateStamp : 0x0
	ForwarderChain : 0x0
	FirstThunk : 0x183A0

	Imported Functions : 

		fputwc
		_set_fmode
		__stdio_common_vfwprintf
		__stdio_common_vsnwprintf_s
		__stdio_common_vswprintf
		__p__commode
		setvbuf
		_wfsopen
		fflush
		__acrt_iob_func
		[+] Found 10 imported functions.

	DLL NAME : api-ms-win-crt-locale-l1-1-0.dll
	Characteristics : 0x21360
	OriginalFirstThunk : 0x21360
	TimeDateStamp : 0x0
	ForwarderChain : 0x0
	FirstThunk : 0x18288

	Imported Functions : 

		___lc_locale_name_func
		__pctype_func
		setlocale
		___mb_cur_max_func
		_unlock_locales
		_lock_locales
		_create_locale
		_configthreadlocale
		_free_locale
		___lc_codepage_func
		[+] Found 10 imported functions.

	DLL NAME : api-ms-win-crt-string-l1-1-0.dll
	Characteristics : 0x214D0
	OriginalFirstThunk : 0x214D0
	TimeDateStamp : 0x0
	ForwarderChain : 0x0
	FirstThunk : 0x183F8

	Imported Functions : 

		_wcsdup
		toupper
		wcsncmp
		wcsnlen
		strcpy_s
		[+] Found 5 imported functions.

	DLL NAME : api-ms-win-crt-convert-l1-1-0.dll
	Characteristics : 0x21318
	OriginalFirstThunk : 0x21318
	TimeDateStamp : 0x0
	ForwarderChain : 0x0
	FirstThunk : 0x18240

	Imported Functions : 

		wcstoul
		_wtoi
		[+] Found 2 imported functions.

	DLL NAME : api-ms-win-crt-math-l1-1-0.dll
	Characteristics : 0x213B8
	OriginalFirstThunk : 0x213B8
	TimeDateStamp : 0x0
	ForwarderChain : 0x0
	FirstThunk : 0x182E0

	Imported Functions : 

		__setusermatherr
		[+] Found 1 imported functions.

[+] Total imported DLLs: 12

[-] No export table found!

[+] PE file parsing completed successfully!
No resources found.
[+] Resource parsing completed successfully!
[+] PE file analysis completed successfully!
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

- **Cross-Platform Compatibility**: The parser uses custom PE structure definitions for cross-platform compatibility
- **Memory-Based Parsing**: All parsing is done in-memory with no dependencies on Windows API
- **Built-in Output Capture**: 
  - Console output provides clean, user-friendly results
  - `Logs.txt` contains comprehensive debug information with timestamps
  - `ParseResults.txt` automatically captures complete analysis output for reference
  - Debug information includes memory addresses, parsing steps, and error diagnostics
- **Architecture Support**: Handles both 32-bit and 64-bit PE files with correct address calculations
- **Import Table Parsing**: Fixed critical memory address calculations for reliable import function enumeration
- **Cross-Platform Output**: Works identically on Windows and Linux with automatic file generation

## License

MIT License. See [LICENSE](LICENSE) for details.

## References

- [Microsoft PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
