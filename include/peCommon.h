#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdarg>

// Include output capture for global printf override
#include "outputCapture.h"

// Cross-platform PE parsing definitions
// These definitions are based on Windows PE format but made cross-platform

// Basic types
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint64_t QWORD;
typedef uintptr_t DWORD_PTR;
typedef int32_t LONG;
typedef uint32_t ULONG;
typedef int BOOL;
typedef void* HANDLE;

#define TRUE 1
#define FALSE 0
#define INVALID_HANDLE_VALUE ((HANDLE)-1)

// PE constants
#define IMAGE_DOS_SIGNATURE 0x5A4D     // MZ
#define IMAGE_NT_SIGNATURE 0x00004550  // PE00
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

// File characteristics
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_DLL 0x2000
#define IMAGE_FILE_SYSTEM 0x1000

// Section characteristics
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000

// Ordinal flags
#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL

// DOS Header
typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

// File Header
typedef struct _IMAGE_FILE_HEADER {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

// Data Directory
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

// Optional Header 32
typedef struct _IMAGE_OPTIONAL_HEADER32 {
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

// Optional Header 64
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    QWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    QWORD SizeOfStackReserve;
    QWORD SizeOfStackCommit;
    QWORD SizeOfHeapReserve;
    QWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

// NT Headers
typedef struct _IMAGE_NT_HEADERS32 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

// Generic NT Headers union
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    union {
        IMAGE_OPTIONAL_HEADER32 OptionalHeader32;
        IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
    } OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

// Section Header
typedef struct _IMAGE_SECTION_HEADER {
    BYTE Name[8];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

// Import structures
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD Characteristics;
        DWORD OriginalFirstThunk;
    };
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;
        DWORD Function;
        DWORD Ordinal;
        DWORD AddressOfData;
    } u1;
} IMAGE_THUNK_DATA32, *PIMAGE_THUNK_DATA32;

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        QWORD ForwarderString;
        QWORD Function;
        QWORD Ordinal;
        QWORD AddressOfData;
    } u1;
} IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;

typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD Hint;
    BYTE Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

// Export structures
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

// Common types and constants used across the PE parser
typedef struct _PE_FILE_INFO {
    HANDLE hFileContent;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    BOOL bIs64Bit;
    DWORD dwFileSize;
} PE_FILE_INFO, *PPE_FILE_INFO;

// Error codes
#define PE_SUCCESS 0
#define PE_ERROR_FILE_OPEN -1
#define PE_ERROR_INVALID_PE -2
#define PE_ERROR_MEMORY_ALLOCATION -3
#define PE_ERROR_PARSING -4

// WIN_CERTIFICATE structure for digital signature parsing
typedef struct _WIN_CERTIFICATE {
    DWORD dwLength;
    WORD wRevision;
    WORD wCertificateType;
    BYTE bCertificate[1]; // Variable length
} WIN_CERTIFICATE, *PWIN_CERTIFICATE;

// Helper function declarations
inline bool isValidString(const char* str, size_t maxLen) {
    if (!str) return false;
    for (size_t i = 0; i < maxLen; ++i) {
        if (str[i] == '\0') return true;
        if (str[i] < 32 || str[i] > 126) return false; // Printable ASCII only
    }
    return false; // No null terminator found within maxLen
}

// Logging functions
#include <ctime>
#include <fstream>

class Logger {
private:
    static std::ofstream logFile;
    static std::ofstream outputFile;
    static bool isInitialized;
    
public:
    static void init(const char* logFilename = "Logs.txt", const char* outputFilename = "ParseOutput.txt") {
        if (!isInitialized) {
            // Initialize log file
            logFile.open(logFilename, std::ios::app);
            if (logFile.is_open()) {
                auto now = std::time(nullptr);
                auto localTime = std::localtime(&now);
                logFile << "\n=== PE Parser Session Started at " 
                       << std::asctime(localTime) << "===\n";
                logFile.flush();
            }
            
            // Initialize output file
            outputFile.open(outputFilename, std::ios::trunc); // Overwrite for each session
            if (outputFile.is_open()) {
                auto now = std::time(nullptr);
                auto localTime = std::localtime(&now);
                outputFile << "=== PE Parser Results - " 
                          << std::asctime(localTime) << "===\n\n";
                outputFile.flush();
            }
            
            isInitialized = true;
        }
    }
    
    static void log(const char* message) {
        if (isInitialized && logFile.is_open()) {
            auto now = std::time(nullptr);
            auto localTime = std::localtime(&now);
            char timeStr[100];
            std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localTime);
            logFile << "[" << timeStr << "] " << message << std::endl;
            logFile.flush();
        }
    }
    
    static void output(const char* message) {
        if (isInitialized && outputFile.is_open()) {
            outputFile << message;
            outputFile.flush();
        }
    }
    
    static void printf_and_output(const char* format, ...) {
        char buffer[1024];
        va_list args;
        va_start(args, format);
        vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);
        
        // Print to console
        printf("%s", buffer);
        
        // Write to output file
        if (isInitialized && outputFile.is_open()) {
            outputFile << buffer;
            outputFile.flush();
        }
    }
    
    static void close() {
        if (isInitialized) {
            if (logFile.is_open()) {
                logFile << "=== PE Parser Session Ended ===\n\n";
                logFile.close();
            }
            if (outputFile.is_open()) {
                outputFile << "\n=== Analysis Complete ===\n";
                outputFile.close();
            }
            isInitialized = false;
        }
    }
};

// Logging macros
#define LOG(msg) do { \
    printf("%s", msg); \
    Logger::log(msg); \
    Logger::output(msg); \
} while(0)

#define LOGF(fmt, ...) do { \
    char buffer[1024]; \
    snprintf(buffer, sizeof(buffer), fmt, ##__VA_ARGS__); \
    printf("%s", buffer); \
    Logger::log(buffer); \
    Logger::output(buffer); \
} while(0)

// Debug logging macros (only write to log file, not console or output)
#define LOG_DEBUG(msg) do { \
    Logger::log(msg); \
} while(0)

#define LOGF_DEBUG(fmt, ...) do { \
    char buffer[1024]; \
    snprintf(buffer, sizeof(buffer), fmt, ##__VA_ARGS__); \
    Logger::log(buffer); \
} while(0)

// Output-only macros (write to console and output file, but not debug logs)
#define LOG_OUTPUT(msg) do { \
    printf("%s", msg); \
    Logger::output(msg); \
} while(0)

#define LOGF_OUTPUT(fmt, ...) do { \
    char buffer[1024]; \
    snprintf(buffer, sizeof(buffer), fmt, ##__VA_ARGS__); \
    printf("%s", buffer); \
    Logger::output(buffer); \
} while(0)

// Macro to replace printf with output logging
#define PRINTF_OUTPUT(...) Logger::printf_and_output(__VA_ARGS__)
