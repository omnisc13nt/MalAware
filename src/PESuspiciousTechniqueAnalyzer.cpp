#include "PESuspiciousTechniqueAnalyzer.h"
#include "outputCapture.h"
#include <sstream>
#include <algorithm>
#include <iomanip>

PESuspiciousTechniqueAnalyzer::PESuspiciousTechniqueAnalyzer() {
    detectedTechniques.clear();
}

PESuspiciousTechniqueAnalyzer::~PESuspiciousTechniqueAnalyzer() {
    detectedTechniques.clear();
}

std::string PESuspiciousTechniqueAnalyzer::timestampToString(DWORD timestamp) {
    if (timestamp == 0) return "Invalid/Null (0x00000000)";
    
    time_t rawTime = static_cast<time_t>(timestamp);
    struct tm* timeInfo = gmtime(&rawTime);
    
    if (timeInfo == nullptr) {
        std::ostringstream oss;
        oss << "Invalid timestamp (0x" << std::hex << timestamp << ")";
        return oss.str();
    }
    
    std::ostringstream oss;
    oss << timeInfo->tm_mday << "/"
        << (timeInfo->tm_mon + 1) << "/"
        << (timeInfo->tm_year + 1900) << " "
        << timeInfo->tm_hour << ":"
        << std::setfill('0') << std::setw(2) << timeInfo->tm_min << " UTC";
    
    return oss.str();
}

std::string PESuspiciousTechniqueAnalyzer::getSeverityDescription(int severity) const {
    if (severity >= 9) return "CRITICAL";
    if (severity >= 7) return "HIGH";
    if (severity >= 5) return "MEDIUM";
    if (severity >= 3) return "LOW";
    return "INFO";
}

std::string PESuspiciousTechniqueAnalyzer::getThreatLevel() const {
    int score = getTotalSeverityScore();
    
    if (score >= 30) return "CRITICAL";
    if (score >= 20) return "HIGH";
    if (score >= 10) return "MEDIUM";
    if (score >= 5) return "LOW";
    return "MINIMAL";
}

bool PESuspiciousTechniqueAnalyzer::isKnownMalwareTimestamp(DWORD timestamp) {
    // Common malware families with known fake timestamps
    std::vector<DWORD> suspiciousTimestamps = {
        0x00000000, // Null timestamp
        0x2A425E19, // Aug 19, 1992 (common in old packers)
        0x4CE78F41, // Nov 20, 2010 (WannaCry fake timestamp)
        0x3B7D8410, // Aug 19, 2001 (common packer timestamp)
        0x5E5F1234, // Feb 29, 2020 (impossible date)
    };
    
    return std::find(suspiciousTimestamps.begin(), suspiciousTimestamps.end(), timestamp) != suspiciousTimestamps.end();
}

bool PESuspiciousTechniqueAnalyzer::analyzeTimestampManipulation(DWORD timestamp, const std::string& filename) {
    (void)filename; // Parameter intentionally unused in current implementation
    bool suspicious = false;
    
    // Check for null timestamp
    if (timestamp == 0) {
        SuspiciousTechnique technique;
        technique.name = "Null Timestamp Manipulation";
        technique.description = "PE file has a null compilation timestamp (0x00000000)";
        technique.severity = 6;
        technique.evidence = "Timestamp: " + timestampToString(timestamp);
        technique.mitigation = "Null timestamps are often used to evade timeline analysis";
        detectedTechniques.push_back(technique);
        suspicious = true;
    }
    
    // Check for known malware timestamps
    if (isKnownMalwareTimestamp(timestamp)) {
        SuspiciousTechnique technique;
        technique.name = "Known Malware Timestamp";
        technique.description = "Timestamp matches known malware families or impossible dates";
        technique.severity = 8;
        technique.evidence = "Timestamp: " + timestampToString(timestamp) + " (0x" + 
                           std::to_string(timestamp) + ")";
        technique.mitigation = "This timestamp is commonly used by malware to evade detection";
        detectedTechniques.push_back(technique);
        suspicious = true;
    }
    
    // Check for future dates (beyond current time + reasonable buffer)
    time_t currentTime = time(nullptr);
    time_t futureThreshold = currentTime + (365 * 24 * 60 * 60); // 1 year in future
    
    if (timestamp > futureThreshold) {
        SuspiciousTechnique technique;
        technique.name = "Future Timestamp Manipulation";
        technique.description = "PE file claims to be compiled in the future";
        technique.severity = 7;
        technique.evidence = "Timestamp: " + timestampToString(timestamp) + " (future date)";
        technique.mitigation = "Future timestamps indicate timestamp manipulation";
        detectedTechniques.push_back(technique);
        suspicious = true;
    }
    
    // Check for very old timestamps that don't match modern compilers
    time_t oldThreshold = 631152000; // Jan 1, 1990
    if (timestamp < oldThreshold && timestamp != 0) {
        SuspiciousTechnique technique;
        technique.name = "Anachronistic Timestamp";
        technique.description = "PE file claims to be compiled before modern PE format existed";
        technique.severity = 8;
        technique.evidence = "Timestamp: " + timestampToString(timestamp) + " (pre-1990)";
        technique.mitigation = "Timestamps before 1990 are highly suspicious for PE files";
        detectedTechniques.push_back(technique);
        suspicious = true;
    }
    
    // Special check for WannaCry-style timestamp manipulation
    if (timestamp == 0x4CE78F41) { // Nov 20, 2010
        SuspiciousTechnique technique;
        technique.name = "WannaCry-Style Timestamp Manipulation";
        technique.description = "This timestamp (Nov 20, 2010) was famously used by WannaCry ransomware from 2017";
        technique.severity = 9;
        technique.evidence = "Timestamp: " + timestampToString(timestamp) + " - Known WannaCry signature";
        technique.mitigation = "This specific timestamp indicates potential WannaCry variant or copycat malware";
        detectedTechniques.push_back(technique);
        suspicious = true;
    }
    
    return suspicious;
}

bool PESuspiciousTechniqueAnalyzer::analyzeEntryPointObfuscation(DWORD entryPoint, DWORD imageBase, DWORD sizeOfCode) {
    (void)imageBase; // Parameter intentionally unused in current implementation
    bool suspicious = false;
    
    // Check for entry point outside code section
    if (entryPoint > sizeOfCode) {
        SuspiciousTechnique technique;
        technique.name = "Entry Point Outside Code Section";
        technique.description = "Entry point is located outside the main code section";
        technique.severity = 8;
        technique.evidence = "Entry Point: 0x" + std::to_string(entryPoint) + 
                           ", Code Size: 0x" + std::to_string(sizeOfCode);
        technique.mitigation = "This indicates potential code injection or entry point obfuscation";
        detectedTechniques.push_back(technique);
        suspicious = true;
    }
    
    // Check for common packer entry points
    if (isCommonPackerEntryPoint(entryPoint)) {
        SuspiciousTechnique technique;
        technique.name = "Common Packer Entry Point";
        technique.description = "Entry point matches known packer signatures";
        technique.severity = 6;
        technique.evidence = "Entry Point: 0x" + std::to_string(entryPoint);
        technique.mitigation = "File may be packed with known packer software";
        detectedTechniques.push_back(technique);
        suspicious = true;
    }
    
    return suspicious;
}

bool PESuspiciousTechniqueAnalyzer::isCommonPackerEntryPoint(DWORD entryPoint) {
    // Common packer entry point patterns (relative to image base)
    std::vector<DWORD> packerEntryPoints = {
        0x1000, // UPX common
        0x77BA, // Observed in analysis
        0x1600, // ASPack common
        0x1200, // PECompact common
    };
    
    return std::find(packerEntryPoints.begin(), packerEntryPoints.end(), entryPoint) != packerEntryPoints.end();
}

bool PESuspiciousTechniqueAnalyzer::analyzeSectionCharacteristics(const std::vector<IMAGE_SECTION_HEADER>& sections) {
    bool suspicious = false;
    
    for (const auto& section : sections) {
        // Check for executable writable sections
        if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) && 
            (section.Characteristics & IMAGE_SCN_MEM_WRITE)) {
            SuspiciousTechnique technique;
            technique.name = "Executable Writable Section";
            technique.description = "Section is both executable and writable - potential code injection";
            technique.severity = 8;
            technique.evidence = "Section: " + std::string(reinterpret_cast<const char*>(section.Name), 8) + 
                               " (Characteristics: 0x" + std::to_string(section.Characteristics) + ")";
            technique.mitigation = "RWX sections enable runtime code modification and injection";
            detectedTechniques.push_back(technique);
            suspicious = true;
        }
        
        // Check for sections with unusual names
        std::string sectionName(reinterpret_cast<const char*>(section.Name), 8);
        if (sectionName.find("UPX") != std::string::npos ||
            sectionName.find("packed") != std::string::npos ||
            sectionName.find(".aspack") != std::string::npos ||
            sectionName.find(".neolite") != std::string::npos) {
            SuspiciousTechnique technique;
            technique.name = "Packer Section Name";
            technique.description = "Section name indicates known packer usage";
            technique.severity = 5;
            technique.evidence = "Section name: " + sectionName;
            technique.mitigation = "File is packed with known packer software";
            detectedTechniques.push_back(technique);
            suspicious = true;
        }
    }
    
    return suspicious;
}

bool PESuspiciousTechniqueAnalyzer::analyzeImportTableAnomalies(int totalImports, int corruptedImports) {
    bool suspicious = false;
    
    if (corruptedImports > 0) {
        SuspiciousTechnique technique;
        technique.name = "Import Table Corruption";
        technique.description = "Import table contains corrupted or invalid entries";
        technique.severity = 8;
        technique.evidence = std::to_string(corruptedImports) + " corrupted imports out of " + 
                           std::to_string(totalImports) + " total";
        technique.mitigation = "Corrupted imports often indicate anti-analysis or obfuscation techniques";
        detectedTechniques.push_back(technique);
        suspicious = true;
    }
    
    // Check for excessive imports (potential import flooding)
    if (totalImports > 500) {
        SuspiciousTechnique technique;
        technique.name = "Import Flooding";
        technique.description = "Unusually high number of imported functions";
        technique.severity = 6;
        technique.evidence = std::to_string(totalImports) + " imported functions detected";
        technique.mitigation = "Import flooding can be used to confuse analysis tools";
        detectedTechniques.push_back(technique);
        suspicious = true;
    }
    
    return suspicious;
}

bool PESuspiciousTechniqueAnalyzer::analyzeResourceAnomalies(DWORD resourceSize, DWORD totalFileSize) {
    bool suspicious = false;
    
    // Check if resources take up more than 80% of file
    double resourceRatio = static_cast<double>(resourceSize) / totalFileSize;
    if (resourceRatio > 0.8) {
        SuspiciousTechnique technique;
        technique.name = "Oversized Resource Section";
        technique.description = "Resource section is disproportionately large";
        technique.severity = 7;
        technique.evidence = "Resources: " + std::to_string(resourceSize) + " bytes (" + 
                           std::to_string(static_cast<int>(resourceRatio * 100)) + "% of file)";
        technique.mitigation = "Large resource sections often hide encrypted payloads";
        detectedTechniques.push_back(technique);
        suspicious = true;
    }
    
    return suspicious;
}

double PESuspiciousTechniqueAnalyzer::calculateAverageEntropy(const std::vector<double>& entropies) {
    if (entropies.empty()) return 0.0;
    
    double sum = 0.0;
    for (double entropy : entropies) {
        sum += entropy;
    }
    return sum / entropies.size();
}

bool PESuspiciousTechniqueAnalyzer::analyzePackingIndicators(const std::vector<double>& sectionEntropies) {
    bool suspicious = false;
    
    double avgEntropy = calculateAverageEntropy(sectionEntropies);
    
    // Check for high average entropy (packing indicator)
    if (avgEntropy > 7.5) {
        SuspiciousTechnique technique;
        technique.name = "High Entropy Packing";
        technique.description = "Average section entropy indicates likely packing/encryption";
        technique.severity = 7;
        technique.evidence = "Average entropy: " + std::to_string(avgEntropy) + " (threshold: 7.5)";
        technique.mitigation = "High entropy suggests compressed or encrypted code";
        detectedTechniques.push_back(technique);
        suspicious = true;
    }
    
    // Check for entropy variance (mixed packed/unpacked sections)
    if (sectionEntropies.size() >= 2) {
        double minEntropy = *std::min_element(sectionEntropies.begin(), sectionEntropies.end());
        double maxEntropy = *std::max_element(sectionEntropies.begin(), sectionEntropies.end());
        
        if ((maxEntropy - minEntropy) > 4.0) {
            SuspiciousTechnique technique;
            technique.name = "Entropy Variance Anomaly";
            technique.description = "Large entropy variance between sections";
            technique.severity = 6;
            technique.evidence = "Entropy range: " + std::to_string(minEntropy) + " - " + 
                               std::to_string(maxEntropy);
            technique.mitigation = "Mixed entropy suggests selective packing or embedded payloads";
            detectedTechniques.push_back(technique);
            suspicious = true;
        }
    }
    
    return suspicious;
}

bool PESuspiciousTechniqueAnalyzer::analyzeAntiAnalysisTechniques(const std::vector<std::string>& importedFunctions) {
    bool suspicious = false;
    
    // Anti-analysis API functions
    std::vector<std::string> antiAnalysisAPIs = {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "GetTickCount",
        "QueryPerformanceCounter",
        "SetUnhandledExceptionFilter",
        "UnhandledExceptionFilter",
        "NtQueryInformationProcess",
        "NtSetInformationThread",
        "ZwQueryInformationProcess",
        "ZwSetInformationThread"
    };
    
    int antiAnalysisCount = 0;
    for (const std::string& func : importedFunctions) {
        for (const std::string& antiAPI : antiAnalysisAPIs) {
            if (func.find(antiAPI) != std::string::npos) {
                antiAnalysisCount++;
                break;
            }
        }
    }
    
    if (antiAnalysisCount >= 3) {
        SuspiciousTechnique technique;
        technique.name = "Anti-Analysis API Usage";
        technique.description = "Multiple anti-analysis/anti-debugging APIs detected";
        technique.severity = 8;
        technique.evidence = std::to_string(antiAnalysisCount) + " anti-analysis APIs found";
        technique.mitigation = "File actively attempts to evade analysis and debugging";
        detectedTechniques.push_back(technique);
        suspicious = true;
    }
    
    return suspicious;
}

bool PESuspiciousTechniqueAnalyzer::analyzePEStructureAnomalies(const IMAGE_NT_HEADERS& ntHeaders) {
    bool suspicious = false;
    
    // Check for unusual section count
    if (ntHeaders.FileHeader.NumberOfSections > 20) {
        SuspiciousTechnique technique;
        technique.name = "Excessive Section Count";
        technique.description = "Unusually high number of sections";
        technique.severity = 6;
        technique.evidence = std::to_string(ntHeaders.FileHeader.NumberOfSections) + " sections (normal: 3-8)";
        technique.mitigation = "Excessive sections may indicate section injection or confusion techniques";
        detectedTechniques.push_back(technique);
        suspicious = true;
    }
    
    // Check for stripped symbols
    if (ntHeaders.FileHeader.PointerToSymbolTable == 0 && ntHeaders.FileHeader.NumberOfSymbols == 0) {
        SuspiciousTechnique technique;
        technique.name = "Stripped Debug Symbols";
        technique.description = "All debug symbols have been stripped";
        technique.severity = 4;
        technique.evidence = "Symbol table pointer: 0, Symbol count: 0";
        technique.mitigation = "Stripped symbols make reverse engineering more difficult";
        detectedTechniques.push_back(technique);
        suspicious = true;
    }
    
    return suspicious;
}

void PESuspiciousTechniqueAnalyzer::analyzeFile(
    const std::string& filename,
    DWORD timestamp,
    DWORD entryPoint,
    DWORD imageBase,
    DWORD sizeOfCode,
    const std::vector<IMAGE_SECTION_HEADER>& sections,
    const std::vector<double>& sectionEntropies,
    int totalImports,
    int corruptedImports,
    DWORD resourceSize,
    DWORD totalFileSize,
    const std::vector<std::string>& importedFunctions,
    bool is64Bit) {
    
    (void)is64Bit; // Parameter intentionally unused in current implementation
    
    // Clear previous results
    detectedTechniques.clear();
    
    // Perform all analyses
    analyzeTimestampManipulation(timestamp, filename);
    analyzeEntryPointObfuscation(entryPoint, imageBase, sizeOfCode);
    analyzeSectionCharacteristics(sections);
    analyzeImportTableAnomalies(totalImports, corruptedImports);
    analyzeResourceAnomalies(resourceSize, totalFileSize);
    analyzePackingIndicators(sectionEntropies);
    analyzeAntiAnalysisTechniques(importedFunctions);
    // Note: PE structure analysis simplified due to architecture differences
}

void PESuspiciousTechniqueAnalyzer::printAnalysis() const {
    LOGF("\n[+] SUSPICIOUS TECHNIQUE ANALYSIS\n");
    LOGF("=================================================\n");
    
    if (detectedTechniques.empty()) {
        LOGF("[INFO] No suspicious techniques detected\n");
        LOGF("Status: Clean\n");
        LOGF("=================================================\n");
        return;
    }
    
    // Basic summary information
    int totalScore = getTotalSeverityScore();
    std::string threatLevel = getThreatLevel();
    
    LOGF("Techniques Detected: %d\n", static_cast<int>(detectedTechniques.size()));
    LOGF("Total Threat Score: %d/100\n", totalScore);
    LOGF("Threat Level: %s\n", threatLevel.c_str());
    LOGF("Assessment: %s\n", isSuspicious() ? "HIGHLY SUSPICIOUS" : "MODERATE RISK");
    LOGF("\n");
    
    // List each technique in dropdown vertical format
    for (size_t i = 0; i < detectedTechniques.size(); i++) {
        const auto& technique = detectedTechniques[i];
        
        LOGF("Technique #%d: %s\n", static_cast<int>(i + 1), technique.name.c_str());
        LOGF("├─ Severity Level: %d/10 (%s)\n", technique.severity, getSeverityDescription(technique.severity).c_str());
        LOGF("├─ Description:\n");
        LOGF("│  %s\n", technique.description.c_str());
        LOGF("├─ Evidence Found:\n");
        LOGF("│  %s\n", technique.evidence.c_str());
        LOGF("└─ Analysis:\n");
        LOGF("   %s\n", technique.mitigation.c_str());
        
        if (i < detectedTechniques.size() - 1) {
            LOGF("\n");
        }
    }
    
    LOGF("\n");
    LOGF("RISK ASSESSMENT:\n");
    if (totalScore >= 25) {
        LOGF("  [CRITICAL] Immediate action required\n");
        LOGF("  - This file exhibits multiple high-severity malicious indicators\n");
        LOGF("  - Recommend quarantine and detailed forensic analysis\n");
        LOGF("  - Do not execute under any circumstances\n");
    } else if (totalScore >= 15) {
        LOGF("  [HIGH] Suspicious file - exercise extreme caution\n");
        LOGF("  - File shows concerning behavioral patterns\n");
        LOGF("  - Recommend sandboxed analysis before trust\n");
        LOGF("  - Monitor closely if execution is necessary\n");
    } else if (totalScore >= 8) {
        LOGF("  [MEDIUM] Potentially suspicious - investigate further\n");
        LOGF("  - Some suspicious indicators detected\n");
        LOGF("  - Additional analysis recommended\n");
        LOGF("  - Exercise normal security precautions\n");
    } else {
        LOGF("  [LOW] Minor concerns detected\n");
        LOGF("  - Low-level indicators present\n");
        LOGF("  - Standard security practices sufficient\n");
    }
    
    LOGF("=================================================\n");
}

const std::vector<SuspiciousTechnique>& PESuspiciousTechniqueAnalyzer::getDetectedTechniques() const {
    return detectedTechniques;
}

int PESuspiciousTechniqueAnalyzer::getTotalSeverityScore() const {
    int total = 0;
    for (const auto& technique : detectedTechniques) {
        total += technique.severity;
    }
    return total;
}

bool PESuspiciousTechniqueAnalyzer::isSuspicious() const {
    return getTotalSeverityScore() >= 15 || detectedTechniques.size() >= 3;
}
