#include "PEParser.h"
#include "peHeaderParser.h"
#include "peSectionParser.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <ios>
#include <string>
#include <cstddef>
#include <cstdlib>
void PEParser::printDebugInfo() const {
    if (!isValid()) {
        std::cerr << errorMessage_ << std::endl;
        return;
    }
    std::cout << "[+] Debug information parsing is planned for future releases." << std::endl;
}
void PEParser::printTLSCallbacks() const {
    if (!isValid()) {
        std::cerr << errorMessage_ << std::endl;
        return;
    }
    std::cout << "[+] TLS callbacks parsing is planned for future releases." << std::endl;
}
void PEParser::printDelayImports() const {
    if (!isValid()) {
        std::cerr << errorMessage_ << std::endl;
        return;
    }
    std::cout << "[+] Delay-loaded imports parsing is planned for future releases." << std::endl;
}
void PEParser::printBoundImports() const {
    if (!isValid()) {
        std::cerr << errorMessage_ << std::endl;
        return;
    }
    std::cout << "[+] Bound imports parsing is planned for future releases." << std::endl;
}
void PEParser::printDotNetMetadata() const {
    if (!isValid()) {
        std::cerr << errorMessage_ << std::endl;
        return;
    }
    std::cout << "[+] .NET metadata parsing is planned for future releases." << std::endl;
}
void PEParser::printIATReconstruction() const {
    if (!isValid()) {
        std::cerr << errorMessage_ << std::endl;
        return;
    }
    std::cout << "[+] IAT reconstruction is planned for future releases." << std::endl;
}
void PEParser::printDisassembly() const {
    if (!isValid()) {
        std::cerr << errorMessage_ << std::endl;
        return;
    }
    std::cout << "[+] Disassembly feature is planned for future releases." << std::endl;
}
void PEParser::printDependencies() const {
    if (!isValid()) {
        std::cerr << errorMessage_ << std::endl;
        return;
    }
    std::cout << "[+] Dependency scanner feature is planned for future releases." << std::endl;
}
void PEParser::printExceptionData() const {
    if (!isValid()) {
        std::cerr << errorMessage_ << std::endl;
        return;
    }
    const IMAGE_DATA_DIRECTORY* excDir = nullptr;
    if (is64Bit_) {
        excDir = &ntHeader_->OptionalHeader.OptionalHeader64.DataDirectory[3]; 
    } else {
        excDir = &ntHeader_->OptionalHeader.OptionalHeader32.DataDirectory[3];
    }
    if (!excDir || excDir->VirtualAddress == 0 || excDir->Size == 0) {
        std::cout << "[+] No exception handling data present." << std::endl;
        return;
    }
    std::cout << "[+] Exception Handling Data Directory found:" << std::endl;
    std::cout << "    RVA: 0x" << std::hex << excDir->VirtualAddress << std::dec << std::endl;
    std::cout << "    Size: " << excDir->Size << " bytes" << std::endl;
    std::cout << "    (Detailed parsing of unwind info is planned for future releases.)" << std::endl;
}
bool PEParser::is64Bit() const {
    return is64Bit_;
}
std::string PEParser::getErrorMessage() const {
    return errorMessage_;
}
void PEParser::printSummary() const {
    if (!isValid()) {
        std::cerr << errorMessage_ << std::endl;
        return;
    }
    std::cout << "[+] Successfully loaded PE file" << std::endl;
    std::cout << "[+] Architecture: " << (is64Bit_ ? "x64" : "x86") << std::endl;
}
void PEParser::printHeaders() const {
    if (!isValid()) return;
    DisplayDosHeader(dosHeader_);
    DisplayFileHeader(&ntHeader_->FileHeader);
    if (is64Bit_) {
        DisplayOptionalHeader64(&ntHeader_->OptionalHeader.OptionalHeader64);
    } else {
        DisplayOptionalHeader32(&ntHeader_->OptionalHeader.OptionalHeader32);
    }
}
void PEParser::printSections() const {
    if (!isValid()) return;
    auto* sectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>((DWORD_PTR)ntHeader_ + 4 + sizeof(IMAGE_FILE_HEADER) + ntHeader_->FileHeader.SizeOfOptionalHeader);
    DisplaySections(sectionHeader, ntHeader_->FileHeader.NumberOfSections);
}
void PEParser::printImports() const {
    if (!isValid()) return;
}
void PEParser::printExports() const {
    if (!isValid()) return;
}
void PEParser::printDigitalSignature() const {
    if (!isValid()) {
        std::cerr << errorMessage_ << std::endl;
        return;
    }
    const IMAGE_DATA_DIRECTORY* secDir = nullptr;
    if (is64Bit_) {
        secDir = &ntHeader_->OptionalHeader.OptionalHeader64.DataDirectory[4]; 
    } else {
        secDir = &ntHeader_->OptionalHeader.OptionalHeader32.DataDirectory[4];
    }
    if (!secDir || secDir->VirtualAddress == 0 || secDir->Size == 0) {
        std::cout << "[+] No digital signature present." << std::endl;
        return;
    }
    DWORD certOffset = secDir->VirtualAddress;
    DWORD certSize = secDir->Size;
    if (certOffset + certSize > fileSize_) {
        std::cout << "[!] Digital signature directory is out of file bounds." << std::endl;
        return;
    }
    const BYTE* certPtr = reinterpret_cast<const BYTE*>(fileContent_) + certOffset;
    const WIN_CERTIFICATE* winCert = reinterpret_cast<const WIN_CERTIFICATE*>(certPtr);
    std::cout << "[+] Digital Signature (Authenticode) found:" << std::endl;
    std::cout << "    Length: " << winCert->dwLength << std::endl;
    std::cout << "    Revision: " << winCert->wRevision << std::endl;
    std::cout << "    Certificate Type: " << winCert->wCertificateType << std::endl;
    std::cout << "    Raw certificate data size: " << certSize - sizeof(WIN_CERTIFICATE) + 1 << " bytes" << std::endl;
}
bool PEParser::loadFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        errorMessage_ = "Failed to open file.";
        return false;
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    if (size <= 0) {
        errorMessage_ = "Invalid file size.";
        file.close();
        return false;
    }
    fileContent_ = malloc(static_cast<size_t>(size));
    if (!fileContent_) {
        errorMessage_ = "Memory allocation failed.";
        file.close();
        return false;
    }
    if (!file.read(static_cast<char*>(fileContent_), size)) {
        errorMessage_ = "Failed to read file content.";
        file.close();
        free(fileContent_);
        fileContent_ = nullptr;
        return false;
    }
    fileSize_ = static_cast<DWORD>(size);
    file.close();
    return true;
}
bool PEParser::validatePE() {
    dosHeader_ = (PIMAGE_DOS_HEADER)fileContent_;
    if (!dosHeader_ || dosHeader_->e_magic != IMAGE_DOS_SIGNATURE) {
        errorMessage_ = "Invalid DOS header.";
        return false;
    }
    ntHeader_ = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileContent_ + dosHeader_->e_lfanew);
    if (!ntHeader_ || ntHeader_->Signature != IMAGE_NT_SIGNATURE) {
        errorMessage_ = "Invalid NT header.";
        return false;
    }
    if (ntHeader_->OptionalHeader.OptionalHeader64.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        is64Bit_ = true;
    } else if (ntHeader_->OptionalHeader.OptionalHeader32.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        is64Bit_ = false;
    } else {
        errorMessage_ = "Unknown PE architecture.";
        return false;
    }
    return true;
}
bool PEParser::isValid() const {
    return fileContent_ != nullptr && dosHeader_ != nullptr && ntHeader_ != nullptr && errorMessage_.empty();
}
void PEParser::cleanup() {
    if (fileContent_) {
        free(fileContent_);
        fileContent_ = nullptr;
    }
}
