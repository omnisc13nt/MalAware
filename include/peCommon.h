#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdarg>
#include "outputCapture.h"
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
#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_DIRECTORY_ENTRY_EXPORT         0
#define IMAGE_DIRECTORY_ENTRY_IMPORT         1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE       2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION      3
#define IMAGE_DIRECTORY_ENTRY_SECURITY       4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC      5
#define IMAGE_DIRECTORY_ENTRY_DEBUG          6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR      8
#define IMAGE_DIRECTORY_ENTRY_TLS            9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11
#define IMAGE_DIRECTORY_ENTRY_IAT            12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_DLL 0x2000
#define IMAGE_FILE_SYSTEM 0x1000
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000
#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL
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
typedef struct _IMAGE_FILE_HEADER {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
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
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    union {
        IMAGE_OPTIONAL_HEADER32 OptionalHeader32;
        IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
    } OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;
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
typedef struct _IMAGE_DEBUG_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD Type;
    DWORD SizeOfData;
    DWORD AddressOfRawData;
    DWORD PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;
#define IMAGE_DEBUG_TYPE_UNKNOWN         0
#define IMAGE_DEBUG_TYPE_COFF            1
#define IMAGE_DEBUG_TYPE_CODEVIEW        2
#define IMAGE_DEBUG_TYPE_FPO             3
#define IMAGE_DEBUG_TYPE_MISC            4
#define IMAGE_DEBUG_TYPE_EXCEPTION       5
#define IMAGE_DEBUG_TYPE_FIXUP           6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC     7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC   8
#define IMAGE_DEBUG_TYPE_BORLAND         9
#define IMAGE_DEBUG_TYPE_RESERVED10      10
#define IMAGE_DEBUG_TYPE_CLSID           11
#define IMAGE_DEBUG_TYPE_VC_FEATURE      12
#define IMAGE_DEBUG_TYPE_POGO            13
#define IMAGE_DEBUG_TYPE_ILTCG           14
#define IMAGE_DEBUG_TYPE_MPX             15
#define IMAGE_DEBUG_TYPE_REPRO           16
typedef struct _IMAGE_SYMBOL {
    union {
        BYTE ShortName[8];
        struct {
            DWORD Short;
            DWORD Long;
        } Name;
        DWORD LongName[2];
    } N;
    DWORD Value;
    WORD SectionNumber;
    WORD Type;
    BYTE StorageClass;
    BYTE NumberOfAuxSymbols;
} IMAGE_SYMBOL, *PIMAGE_SYMBOL;
typedef struct _PE_FILE_INFO {
    HANDLE hFileContent;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    BOOL bIs64Bit;
    DWORD dwFileSize;
} PE_FILE_INFO, *PPE_FILE_INFO;
#define PE_SUCCESS 0
#define PE_ERROR_FILE_OPEN -1
#define PE_ERROR_INVALID_PE -2
#define PE_ERROR_MEMORY_ALLOCATION -3
#define PE_ERROR_PARSING -4
#define PE_ERROR_INVALID_SIGNATURE -5
#define PE_ERROR_UNSUPPORTED_ARCHITECTURE -6
#define PE_ERROR_CORRUPTED_STRUCTURE -7
#define PE_ERROR_SECURITY_ANALYSIS_FAILED -8
#define PE_ERROR_HASH_CALCULATION_FAILED -9
#define PE_ERROR_DEBUG_INFO_FAILED -10
#define PE_ERROR_RESOURCE_PARSING_FAILED -11
#define PE_ERROR_IMPORT_PARSING_FAILED -12
#define PE_ERROR_EXPORT_PARSING_FAILED -13
typedef struct _PE_ERROR_INFO {
    int errorCode;
    const char* errorMessage;
    const char* detailedMessage;
    const char* filename;
    int lineNumber;
} PE_ERROR_INFO, *PPE_ERROR_INFO;
#define PE_SET_ERROR(info, code, msg, detail) \
    do { \
        (info)->errorCode = (code); \
        (info)->errorMessage = (msg); \
        (info)->detailedMessage = (detail); \
        (info)->filename = __FILE__; \
        (info)->lineNumber = __LINE__; \
    } while(0)
#define PE_CHECK_ERROR(result, info, code, msg, detail) \
    do { \
        if ((result) != PE_SUCCESS) { \
            PE_SET_ERROR(info, code, msg, detail); \
            return (result); \
        } \
    } while(0)
typedef struct _WIN_CERTIFICATE {
    DWORD dwLength;
    WORD wRevision;
    WORD wCertificateType;
    BYTE bCertificate[1];
} WIN_CERTIFICATE, *PWIN_CERTIFICATE;
inline bool isValidString(const char* str, size_t maxLen) {
    if (!str) return false;
    size_t len = 0;
    for (size_t i = 0; i < maxLen; ++i) {
        if (str[i] == '\0') {
            return len >= 1 && len <= 255;
        }

        if (str[i] >= 32 && str[i] <= 126) {
            len++;
        } else if ((unsigned char)str[i] >= 128) {
            len++;
        } else if (str[i] == '\0') {
            break;
        } else {
            return false;
        }
    }
    return len >= 1 && len <= 255;
}
inline bool isLikelyObfuscated(const char* str, size_t len) {
    if (!str || len == 0) return true;
    size_t nonPrintable = 0;
    size_t uppercase = 0;
    size_t lowercase = 0;
    size_t digits = 0;
    size_t symbols = 0;
    for (size_t i = 0; i < len && str[i] != '\0'; ++i) {
        if (str[i] < 32 || str[i] > 126) nonPrintable++;
        else if (str[i] >= 'A' && str[i] <= 'Z') uppercase++;
        else if (str[i] >= 'a' && str[i] <= 'z') lowercase++;
        else if (str[i] >= '0' && str[i] <= '9') digits++;
        else symbols++;
    }
    if (nonPrintable > len / 4) return true;
    if (len > 3 && uppercase == 0 && lowercase == 0) return true;
    if (len > 10 && symbols > len / 2) return true;
    return false;
}
#include <ctime>
#include <fstream>


extern FILE* g_output_file;

class Logger {
private:
    static std::ofstream logFile;
    static std::ofstream outputFile;
    static bool isInitialized;
public:
    static void init(const char* logFilename = "", const char* outputFilename = "ParseOutput.txt") {
        if (!isInitialized) {

            if (logFilename && strlen(logFilename) > 0) {
                logFile.open(logFilename, std::ios::app);
                if (logFile.is_open()) {
                    auto now = std::time(nullptr);
                    auto localTime = std::localtime(&now);
                    logFile << "\n=== PE Parser Session Started at "
                           << std::asctime(localTime) << "===\n";
                    logFile.flush();
                }
            }


            if (outputFilename && strlen(outputFilename) > 0) {
                outputFile.open(outputFilename, std::ios::trunc);
                if (outputFile.is_open()) {
                    auto now = std::time(nullptr);
                    auto localTime = std::localtime(&now);
                    outputFile << "=== PE Parser Results - "
                              << std::asctime(localTime) << "===\n\n";
                    outputFile.flush();
                }
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
        printf("%s", buffer);
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
#define LOG(msg) do { \
    printf("%s", msg); \
    if (g_output_file) { \
        fprintf(g_output_file, "%s", msg); \
        fflush(g_output_file); \
    } \
} while(0)
#define LOGF(fmt, ...) do { \
    char buffer[8192]; \
    int result = snprintf(buffer, sizeof(buffer), fmt, ##__VA_ARGS__); \
    if (result > 0 && result < (int)sizeof(buffer)) { \
        printf("%s", buffer); \
        if (g_output_file) { \
            fprintf(g_output_file, "%s", buffer); \
            fflush(g_output_file); \
        } \
    } else { \
        const char* truncated_msg = "[ERROR: Message too long for buffer - Consider using shorter output format]\n"; \
        printf("%s", truncated_msg); \
        if (g_output_file) { \
            fprintf(g_output_file, "%s", truncated_msg); \
            fflush(g_output_file); \
        } \
    } \
} while(0)
#define LOG_DEBUG(msg) do { \
     \
     \
} while(0)
#define LOGF_DEBUG(fmt, ...) do { \
     \
     \
} while(0)
#define LOG_OUTPUT(msg) do { \
    printf("%s", msg); \
    if (g_output_file) { \
        fprintf(g_output_file, "%s", msg); \
        fflush(g_output_file); \
    } \
} while(0)
#define LOGF_OUTPUT(fmt, ...) do { \
    char buffer[4096]; \
    snprintf(buffer, sizeof(buffer), fmt, ##__VA_ARGS__); \
    printf("%s", buffer); \
    if (g_output_file) { \
        fprintf(g_output_file, "%s", buffer); \
        fflush(g_output_file); \
    } \
} while(0)
#define PRINTF_OUTPUT(...) do { \
    printf(__VA_ARGS__); \
    if (g_output_file) { \
        fprintf(g_output_file, __VA_ARGS__); \
        fflush(g_output_file); \
    } \
} while(0)
