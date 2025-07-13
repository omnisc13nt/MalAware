#include "../include/PETLSAnalyzer.h"
#include "../include/peSectionParser.h"
#include "../include/peImportExport.h"  
#include <vector>
#include <sstream>
int AnalyzeTLS(PPE_FILE_INFO pFileInfo) {
    LOGF("\n[+] TLS CALLBACK ANALYSIS\n");
    LOGF_DEBUG("[DEBUG] Starting TLS analysis\n");
    if (!pFileInfo || !pFileInfo->pNtHeader) {
        LOGF("[-] ERROR: Invalid PE file info\n");
        return PE_ERROR_INVALID_PE;
    }
    try {
        PETLSAnalyzer::TLSInfo tlsInfo = PETLSAnalyzer::analyzeTLS(pFileInfo);
        PETLSAnalyzer::logTLSAnalysis(tlsInfo);
        LOGF("[+] TLS analysis completed successfully!\n");
        return PE_SUCCESS;
    }
    catch (const std::exception& e) {
        LOGF("[-] ERROR: TLS analysis failed: %s\n", e.what());
        return PE_ERROR_PARSING;
    }
}
PETLSAnalyzer::TLSInfo PETLSAnalyzer::analyzeTLS(PPE_FILE_INFO pFileInfo) {
    TLSInfo tlsInfo = {};
    tlsInfo.hasTLS = false;
    tlsInfo.isSuspicious = false;
    if (!pFileInfo || !pFileInfo->pNtHeader) {
        tlsInfo.analysis = "Invalid PE file";
        return tlsInfo;
    }
    DWORD tlsRVA = 0;
    DWORD tlsSize = 0;
    if (pFileInfo->bIs64Bit) {
        auto optHeader64 = &pFileInfo->pNtHeader->OptionalHeader.OptionalHeader64;
        if (optHeader64->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS) {
            tlsRVA = optHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
            tlsSize = optHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
        }
    } else {
        auto optHeader32 = &pFileInfo->pNtHeader->OptionalHeader.OptionalHeader32;
        if (optHeader32->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS) {
            tlsRVA = optHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
            tlsSize = optHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
        }
    }
    if (tlsRVA == 0 || tlsSize == 0) {
        tlsInfo.analysis = "No TLS directory found";
        return tlsInfo;
    }
    tlsInfo.hasTLS = true;
    if (pFileInfo->bIs64Bit) {
        auto tlsDir64 = getTLSDirectory64(pFileInfo);
        if (tlsDir64) {
            tlsInfo.startAddressOfRawData = tlsDir64->StartAddressOfRawData;
            tlsInfo.endAddressOfRawData = tlsDir64->EndAddressOfRawData;
            tlsInfo.addressOfIndex = tlsDir64->AddressOfIndex;
            tlsInfo.addressOfCallBacks = tlsDir64->AddressOfCallBacks;
            tlsInfo.sizeOfZeroFill = tlsDir64->SizeOfZeroFill;
            tlsInfo.characteristics = tlsDir64->Characteristics;
        }
    } else {
        auto tlsDir32 = getTLSDirectory32(pFileInfo);
        if (tlsDir32) {
            tlsInfo.startAddressOfRawData = tlsDir32->StartAddressOfRawData;
            tlsInfo.endAddressOfRawData = tlsDir32->EndAddressOfRawData;
            tlsInfo.addressOfIndex = tlsDir32->AddressOfIndex;
            tlsInfo.addressOfCallBacks = tlsDir32->AddressOfCallBacks;
            tlsInfo.sizeOfZeroFill = tlsDir32->SizeOfZeroFill;
            tlsInfo.characteristics = tlsDir32->Characteristics;
        }
    }
    tlsInfo.callbacks = extractTLSCallbacks(pFileInfo);
    if (!tlsInfo.callbacks.empty()) {
        for (auto callback : tlsInfo.callbacks) {
            if (isCallbackSuspicious(callback, pFileInfo)) {
                tlsInfo.isSuspicious = true;
                break;
            }
        }
        tlsInfo.analysis = analyzeCallbackPattern(tlsInfo.callbacks);
    } else {
        tlsInfo.analysis = "TLS directory present but no callbacks found";
    }
    return tlsInfo;
}
bool PETLSAnalyzer::hasTLSDirectory(PPE_FILE_INFO pFileInfo) {
    if (!pFileInfo || !pFileInfo->pNtHeader) return false;
    DWORD tlsRVA = 0;
    if (pFileInfo->bIs64Bit) {
        auto optHeader64 = &pFileInfo->pNtHeader->OptionalHeader.OptionalHeader64;
        if (optHeader64->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS) {
            tlsRVA = optHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        }
    } else {
        auto optHeader32 = &pFileInfo->pNtHeader->OptionalHeader.OptionalHeader32;
        if (optHeader32->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_TLS) {
            tlsRVA = optHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        }
    }
    return tlsRVA != 0;
}
std::vector<DWORD_PTR> PETLSAnalyzer::extractTLSCallbacks(PPE_FILE_INFO pFileInfo) {
    std::vector<DWORD_PTR> callbacks;
    if (!pFileInfo || !hasTLSDirectory(pFileInfo)) {
        return callbacks;
    }
    try {
        if (pFileInfo->bIs64Bit) {
            auto tlsDir64 = getTLSDirectory64(pFileInfo);
            if (tlsDir64 && tlsDir64->AddressOfCallBacks) {
                extern int g_NumberOfSections;
                extern PIMAGE_SECTION_HEADER g_SectionHeader;
                if (g_SectionHeader) {
                    DWORD_PTR callbacksOffset = RvaToFileOffset(
                        (DWORD)(tlsDir64->AddressOfCallBacks - pFileInfo->pNtHeader->OptionalHeader.OptionalHeader64.ImageBase),
                        g_SectionHeader, g_NumberOfSections);
                    if (callbacksOffset > 0) {
                        auto callbackPtr = (QWORD*)((DWORD_PTR)pFileInfo->pDosHeader + callbacksOffset);
                        for (int i = 0; i < 16 && callbackPtr[i] != 0; i++) {
                            callbacks.push_back(callbackPtr[i]);
                        }
                    }
                }
            }
        } else {
            auto tlsDir32 = getTLSDirectory32(pFileInfo);
            if (tlsDir32 && tlsDir32->AddressOfCallBacks) {
                extern int g_NumberOfSections;
                extern PIMAGE_SECTION_HEADER g_SectionHeader;
                if (g_SectionHeader) {
                    DWORD_PTR callbacksOffset = RvaToFileOffset(
                        tlsDir32->AddressOfCallBacks - pFileInfo->pNtHeader->OptionalHeader.OptionalHeader32.ImageBase,
                        g_SectionHeader, g_NumberOfSections);
                    if (callbacksOffset > 0) {
                        auto callbackPtr = (DWORD*)((DWORD_PTR)pFileInfo->pDosHeader + callbacksOffset);
                        for (int i = 0; i < 16 && callbackPtr[i] != 0; i++) {
                            callbacks.push_back(callbackPtr[i]);
                        }
                    }
                }
            }
        }
    }
    catch (...) {
        LOGF_DEBUG("[DEBUG] Exception while extracting TLS callbacks\n");
    }
    return callbacks;
}
bool PETLSAnalyzer::isCallbackSuspicious(DWORD_PTR callbackAddress, PPE_FILE_INFO pFileInfo) {
    if (!pFileInfo) return false;
    extern int g_NumberOfSections;
    extern PIMAGE_SECTION_HEADER g_SectionHeader;
    if (!g_SectionHeader) return true; 
    DWORD imageBase = pFileInfo->bIs64Bit ? 
        (DWORD)pFileInfo->pNtHeader->OptionalHeader.OptionalHeader64.ImageBase :
        pFileInfo->pNtHeader->OptionalHeader.OptionalHeader32.ImageBase;
    DWORD rva = (DWORD)(callbackAddress - imageBase);
    for (int i = 0; i < g_NumberOfSections; i++) {
        auto section = &g_SectionHeader[i];
        if (rva >= section->VirtualAddress && 
            rva < section->VirtualAddress + section->Misc.VirtualSize) {
            if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
                return true; 
            }
            char sectionName[9] = {0};
            strncpy(sectionName, (char*)section->Name, 8);
            if (strcmp(sectionName, ".text") == 0) {
                return false; 
            }
            return true;
        }
    }
    return true; 
}
std::string PETLSAnalyzer::generateTLSReport(const TLSInfo& tlsInfo) {
    std::ostringstream report;
    if (!tlsInfo.hasTLS) {
        report << "No TLS directory found";
        return report.str();
    }
    report << "TLS Directory Analysis:\n";
    report << "  Callbacks Found: " << tlsInfo.callbacks.size() << "\n";
    report << "  Raw Data Range: 0x" << std::hex << tlsInfo.startAddressOfRawData 
           << " - 0x" << tlsInfo.endAddressOfRawData << "\n";
    report << "  Zero Fill Size: " << std::dec << tlsInfo.sizeOfZeroFill << " bytes\n";
    if (tlsInfo.isSuspicious) {
        report << "  [WARNING] Suspicious TLS callbacks detected!\n";
    }
    if (!tlsInfo.callbacks.empty()) {
        report << "  Callback Addresses:\n";
        for (auto callback : tlsInfo.callbacks) {
            report << "    0x" << std::hex << callback << "\n";
        }
    }
    return report.str();
}
void PETLSAnalyzer::logTLSAnalysis(const TLSInfo& tlsInfo) {
    if (!tlsInfo.hasTLS) {
        LOGF("\tNo TLS directory found\n");
        return;
    }
    LOGF("\tTLS Directory: Present\n");
    LOGF("\tRaw Data Range: 0x%llX - 0x%llX\n", 
         (unsigned long long)tlsInfo.startAddressOfRawData,
         (unsigned long long)tlsInfo.endAddressOfRawData);
    LOGF("\tZero Fill Size: %u bytes\n", tlsInfo.sizeOfZeroFill);
    LOGF("\tCharacteristics: 0x%X\n", tlsInfo.characteristics);
    if (tlsInfo.callbacks.empty()) {
        LOGF("\tTLS Callbacks: None\n");
    } else {
        LOGF("\tTLS Callbacks: %zu found\n", tlsInfo.callbacks.size());
        for (size_t i = 0; i < tlsInfo.callbacks.size(); i++) {
            LOGF("\t\tCallback %zu: 0x%llX\n", i + 1, 
                 (unsigned long long)tlsInfo.callbacks[i]);
        }
        if (tlsInfo.isSuspicious) {
            LOGF("\t[MALWARE ANALYSIS] Suspicious TLS callbacks detected!\n");
            LOGF("\t                   TLS callbacks can be used for anti-analysis\n");
            LOGF("\t                   or process injection techniques.\n");
        }
    }
    if (!tlsInfo.analysis.empty()) {
        LOGF("\tAnalysis: %s\n", tlsInfo.analysis.c_str());
    }
}
PIMAGE_TLS_DIRECTORY32 PETLSAnalyzer::getTLSDirectory32(PPE_FILE_INFO pFileInfo) {
    if (!pFileInfo || pFileInfo->bIs64Bit) return nullptr;
    auto optHeader32 = &pFileInfo->pNtHeader->OptionalHeader.OptionalHeader32;
    if (optHeader32->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_TLS) return nullptr;
    DWORD tlsRVA = optHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (tlsRVA == 0) return nullptr;
    extern int g_NumberOfSections;
    extern PIMAGE_SECTION_HEADER g_SectionHeader;
    if (!g_SectionHeader) return nullptr;
    DWORD_PTR tlsOffset = RvaToFileOffset(tlsRVA, g_SectionHeader, g_NumberOfSections);
    if (tlsOffset == 0) return nullptr;
    return (PIMAGE_TLS_DIRECTORY32)((DWORD_PTR)pFileInfo->pDosHeader + tlsOffset);
}
PIMAGE_TLS_DIRECTORY64 PETLSAnalyzer::getTLSDirectory64(PPE_FILE_INFO pFileInfo) {
    if (!pFileInfo || !pFileInfo->bIs64Bit) return nullptr;
    auto optHeader64 = &pFileInfo->pNtHeader->OptionalHeader.OptionalHeader64;
    if (optHeader64->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_TLS) return nullptr;
    DWORD tlsRVA = optHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (tlsRVA == 0) return nullptr;
    extern int g_NumberOfSections;
    extern PIMAGE_SECTION_HEADER g_SectionHeader;
    if (!g_SectionHeader) return nullptr;
    DWORD_PTR tlsOffset = RvaToFileOffset(tlsRVA, g_SectionHeader, g_NumberOfSections);
    if (tlsOffset == 0) return nullptr;
    return (PIMAGE_TLS_DIRECTORY64)((DWORD_PTR)pFileInfo->pDosHeader + tlsOffset);
}
std::string PETLSAnalyzer::analyzeCallbackPattern(const std::vector<DWORD_PTR>& callbacks) {
    if (callbacks.empty()) {
        return "No callbacks to analyze";
    }
    std::ostringstream analysis;
    analysis << "Found " << callbacks.size() << " TLS callback(s)";
    if (callbacks.size() > 3) {
        analysis << " [SUSPICIOUS: Many TLS callbacks unusual for legitimate software]";
    }
    if (callbacks.size() > 1) {
        bool sequential = true;
        for (size_t i = 1; i < callbacks.size(); i++) {
            if (callbacks[i] - callbacks[i-1] > 0x1000) {
                sequential = false;
                break;
            }
        }
        if (sequential) {
            analysis << " [SUSPICIOUS: Sequential callback addresses]";
        }
    }
    return analysis.str();
}
