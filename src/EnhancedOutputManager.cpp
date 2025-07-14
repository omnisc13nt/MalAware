#include "../include/EnhancedOutputManager.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
EnhancedOutputManager::EnhancedOutputManager() : currentFormat(OutputFormat::TEXT) {
}
EnhancedOutputManager::~EnhancedOutputManager() {
}
void EnhancedOutputManager::setOutputFormat(OutputFormat format) {
    currentFormat = format;
}
void EnhancedOutputManager::setOutputFile(const std::string& filePath) {
    outputFilePath = filePath;
}
bool EnhancedOutputManager::generateOutput(const AnalysisData& data) {
    std::string output;
    switch (currentFormat) {
        case OutputFormat::XML:
            output = generateXML(data);
            break;
        case OutputFormat::CSV:
            output = generateCSV(data);
            break;
        case OutputFormat::SUMMARY:
            output = generateSummary(data);
            break;
        case OutputFormat::TEXT:
        default:
            output = generateText(data);
            break;
    }
    if (outputFilePath.empty()) {
        std::cout << output << std::endl;
        return true;
    } else {
        std::ofstream file(outputFilePath);
        if (file.is_open()) {
            file << output;
            file.close();
            return true;
        }
        return false;
    }
}
std::string EnhancedOutputManager::generateXML(const AnalysisData& data) {
    std::stringstream xml;
    xml << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    xml << "<peAnalysis>\n";
    xml << "  <metadata>\n";
    xml << "    " << xmlElement("fileName", data.fileName) << "\n";
    xml << "    " << xmlElement("filePath", data.filePath) << "\n";
    xml << "    " << xmlElement("fileSize", static_cast<uint32_t>(data.fileSize)) << "\n";
    xml << "    " << xmlElement("architecture", data.architecture) << "\n";
    xml << "    " << xmlElement("analysisTimestamp", data.analysisTimestamp) << "\n";
    xml << "  </metadata>\n";
    xml << "  <hashes>\n";
    xml << "    " << xmlElement("md5", data.md5) << "\n";
    xml << "    " << xmlElement("sha1", data.sha1) << "\n";
    xml << "    " << xmlElement("sha256", data.sha256) << "\n";
    xml << "    " << xmlElement("imphash", data.imphash) << "\n";
    xml << "    <fuzzyHashes>\n";
    xml << "      " << xmlElement("ssdeep", data.ssdeep) << "\n";
    xml << "      " << xmlElement("tlsh", data.tlsh) << "\n";
    xml << "      " << xmlElement("vhash", data.vhash) << "\n";
    xml << "    </fuzzyHashes>\n";
    xml << "  </hashes>\n";
    xml << "  <peStructure>\n";
    xml << "    " << xmlElement("compilationTime", data.compilationTime) << "\n";
    xml << "    " << xmlElement("sectionCount", static_cast<uint32_t>(data.sectionCount)) << "\n";
    xml << "    " << xmlElement("entryPoint", data.entryPoint) << "\n";
    xml << "    " << xmlElement("subsystem", data.subsystem) << "\n";
    xml << "  </peStructure>\n";
    xml << "  <securityFeatures>\n";
    xml << "    " << xmlElement("aslr", data.aslrEnabled) << "\n";
    xml << "    " << xmlElement("dep", data.depEnabled) << "\n";
    xml << "    " << xmlElement("seh", data.sehEnabled) << "\n";
    xml << "    " << xmlElement("cfg", data.cfgEnabled) << "\n";
    xml << "    " << xmlElement("nxCompatible", data.nxCompatible) << "\n";
    xml << "  </securityFeatures>\n";
    xml << "  <imports>\n";
    xml << "    " << xmlElement("totalImports", data.importCount) << "\n";
    xml << "    " << xmlElement("dllCount", data.dllCount) << "\n";
    xml << "    " << xmlElement("corruptedImports", data.corruptedImports) << "\n";
    xml << "    <importedDlls>\n";
    for (const auto& dll : data.importedDlls) {
        xml << "      " << xmlElement("dll", dll) << "\n";
    }
    xml << "    </importedDlls>\n";
    xml << "  </imports>\n";
    xml << "  <entropyAnalysis>\n";
    xml << "    " << xmlElement("overallEntropy", data.overallEntropy) << "\n";
    xml << "    " << xmlElement("packingDetected", data.packingDetected) << "\n";
    xml << "    <sectionEntropies>\n";
    for (const auto& section : data.sectionEntropies) {
        xml << "      <section name=\"" << xmlEscape(section.first) << "\">" 
            << std::fixed << std::setprecision(2) << section.second << "</section>\n";
    }
    xml << "    </sectionEntropies>\n";
    xml << "  </entropyAnalysis>\n";
    xml << "  <riskAssessment>\n";
    xml << "    " << xmlElement("riskScore", data.riskScore) << "\n";
    xml << "    " << xmlElement("classification", data.classification) << "\n";
    xml << "    <threatIndicators>\n";
    for (const auto& indicator : data.threatIndicators) {
        xml << "      " << xmlElement("indicator", indicator) << "\n";
    }
    xml << "    </threatIndicators>\n";
    xml << "    " << xmlElement("recommendation", data.recommendation) << "\n";
    xml << "  </riskAssessment>\n";
    xml << "  <performance>\n";
    xml << "    " << xmlElement("analysisTime", data.analysisTime) << "\n";
    xml << "    " << xmlElement("memoryUsage", static_cast<uint32_t>(data.memoryUsage)) << "\n";
    xml << "  </performance>\n";
    xml << "</peAnalysis>\n";
    return xml.str();
}
std::string EnhancedOutputManager::generateCSV(const AnalysisData& data) {
    std::stringstream csv;
    csv << csvEscape(data.fileName) << ",";
    csv << data.fileSize << ",";
    csv << csvEscape(data.architecture) << ",";
    csv << csvEscape(data.md5) << ",";
    csv << csvEscape(data.sha1) << ",";
    csv << csvEscape(data.sha256) << ",";
    csv << data.riskScore << ",";
    csv << csvEscape(data.classification) << ",";
    csv << (data.aslrEnabled ? "Y" : "N") << ",";
    csv << (data.depEnabled ? "Y" : "N") << ",";
    csv << data.importCount << ",";
    csv << data.corruptedImports << ",";
    csv << std::fixed << std::setprecision(2) << data.overallEntropy << ",";
    csv << (data.packingDetected ? "Y" : "N") << ",";
    csv << std::fixed << std::setprecision(3) << data.analysisTime << ",";
    csv << csvEscape(data.analysisTimestamp);
    return csv.str();
}
std::string EnhancedOutputManager::generateSummary(const AnalysisData& data) {
    std::stringstream summary;
    summary << "=== PE Analysis Summary ===\n";
    summary << "File: " << data.fileName << "\n";
    summary << "Size: " << formatFileSize(data.fileSize) << "\n";
    summary << "Architecture: " << data.architecture << "\n";
    summary << "Risk Score: " << data.riskScore << "/100 (" << data.classification << ")\n";
    summary << "SHA-256: " << data.sha256 << "\n";
    summary << "\nSecurity Features:\n";
    summary << "  ASLR: " << (data.aslrEnabled ? "ENABLED" : "DISABLED") << "\n";
    summary << "  DEP:  " << (data.depEnabled ? "ENABLED" : "DISABLED") << "\n";
    summary << "  CFG:  " << (data.cfgEnabled ? "ENABLED" : "DISABLED") << "\n";
    summary << "\nImports: " << data.importCount << " functions from " << data.dllCount << " DLLs";
    if (data.corruptedImports > 0) {
        summary << " (" << data.corruptedImports << " corrupted)";
    }
    summary << "\n";
    summary << "Entropy: " << std::fixed << std::setprecision(2) << data.overallEntropy << "/8.0";
    if (data.packingDetected) {
        summary << " (PACKING DETECTED)";
    }
    summary << "\n";
    if (!data.threatIndicators.empty()) {
        summary << "\nThreat Indicators:\n";
        for (const auto& indicator : data.threatIndicators) {
            summary << "  - " << indicator << "\n";
        }
    }
    summary << "\nRecommendation: " << data.recommendation << "\n";
    summary << "Analysis Time: " << std::fixed << std::setprecision(3) << data.analysisTime << "s\n";
    return summary.str();
}
std::string EnhancedOutputManager::generateText(const AnalysisData& data) {
    std::stringstream text;
    text << "=== PE Parser Results - " << data.analysisTimestamp << " ===\n\n";
    text << "[INFO] Analysis completed for: " << data.filePath << "\n";
    text << "[+] File Size: " << formatFileSize(data.fileSize) << "\n";
    text << "[+] Architecture: " << data.architecture << "\n\n";
    text << "[+] FILE HASHES\n";
    text << "\tMD5: " << data.md5 << "\n";
    text << "\tSHA-1: " << data.sha1 << "\n";
    text << "\tSHA-256: " << data.sha256 << "\n";
    text << "\tImphash: " << data.imphash << "\n\n";
    text << "[+] FUZZY HASHES\n";
    text << "\tSSDeep: " << data.ssdeep << "\n";
    text << "\tTLSH: " << data.tlsh << "\n";
    text << "\tVHash: " << data.vhash << "\n\n";
    text << "[+] SECURITY FEATURES\n";
    text << "\tASLR: " << (data.aslrEnabled ? "ENABLED" : "DISABLED") << "\n";
    text << "\tDEP: " << (data.depEnabled ? "ENABLED" : "DISABLED") << "\n";
    text << "\tSEH: " << (data.sehEnabled ? "ENABLED" : "DISABLED") << "\n";
    text << "\tCFG: " << (data.cfgEnabled ? "ENABLED" : "DISABLED") << "\n";
    text << "\tNX Compatible: " << (data.nxCompatible ? "ENABLED" : "DISABLED") << "\n\n";
    text << "[+] IMPORT ANALYSIS\n";
    text << "\tTotal Imports: " << data.importCount << "\n";
    text << "\tDLL Count: " << data.dllCount << "\n";
    text << "\tCorrupted Imports: " << data.corruptedImports << "\n\n";
    text << "[+] ENTROPY ANALYSIS\n";
    text << "\tOverall Entropy: " << std::fixed << std::setprecision(2) << data.overallEntropy << "/8.0\n";
    text << "\tPacking Detected: " << (data.packingDetected ? "YES" : "NO") << "\n";
    for (const auto& section : data.sectionEntropies) {
        text << "\t" << section.first << " Entropy: " << std::fixed << std::setprecision(2) << section.second << "\n";
    }
    text << "\n";
    text << "[+] RISK ASSESSMENT\n";
    text << "\tRisk Score: " << data.riskScore << "/100\n";
    text << "\tClassification: " << data.classification << "\n";
    if (!data.threatIndicators.empty()) {
        text << "\tThreat Indicators:\n";
        for (const auto& indicator : data.threatIndicators) {
            text << "\t  - " << indicator << "\n";
        }
    }
    text << "\tRecommendation: " << data.recommendation << "\n\n";
    text << "[+] PERFORMANCE METRICS\n";
    text << "\tAnalysis Time: " << std::fixed << std::setprecision(3) << data.analysisTime << " seconds\n";
    text << "\tMemory Usage: " << formatFileSize(data.memoryUsage) << "\n\n";
    text << "[+] PE file parsing completed successfully!\n";
    return text.str();
}
std::string EnhancedOutputManager::getCSVHeader() {
    return "FileName,FileSize,Architecture,MD5,SHA1,SHA256,RiskScore,Classification,ASLR,DEP,ImportCount,CorruptedImports,Entropy,PackingDetected,AnalysisTime,Timestamp";
}
bool EnhancedOutputManager::isFormatSupported(OutputFormat format) {
    return format == OutputFormat::TEXT || 
           format == OutputFormat::XML || 
           format == OutputFormat::CSV || 
           format == OutputFormat::SUMMARY;
}
std::string EnhancedOutputManager::xmlEscape(const std::string& str) {
    std::string escaped;
    for (char c : str) {
        switch (c) {
            case '<': escaped += "&lt;"; break;
            case '>': escaped += "&gt;"; break;
            case '&': escaped += "&amp;"; break;
            case '"': escaped += "&quot;"; break;
            case '\'': escaped += "&apos;"; break;
            default: escaped += c; break;
        }
    }
    return escaped;
}
std::string EnhancedOutputManager::xmlElement(const std::string& name, const std::string& value) {
    return "<" + name + ">" + xmlEscape(value) + "</" + name + ">";
}
std::string EnhancedOutputManager::xmlElement(const std::string& name, bool value) {
    return "<" + name + ">" + (value ? "true" : "false") + "</" + name + ">";
}
std::string EnhancedOutputManager::xmlElement(const std::string& name, uint32_t value) {
    return "<" + name + ">" + std::to_string(value) + "</" + name + ">";
}
std::string EnhancedOutputManager::xmlElement(const std::string& name, double value) {
    std::stringstream ss;
    ss << "<" << name << ">" << std::fixed << std::setprecision(2) << value << "</" << name << ">";
    return ss.str();
}
std::string EnhancedOutputManager::csvEscape(const std::string& str) {
    if (str.find(',') != std::string::npos || str.find('"') != std::string::npos || str.find('\n') != std::string::npos) {
        std::string escaped = "\"";
        for (char c : str) {
            if (c == '"') escaped += "\"\"";
            else escaped += c;
        }
        escaped += "\"";
        return escaped;
    }
    return str;
}
std::string EnhancedOutputManager::formatTimestamp(uint32_t timestamp) {
    if (timestamp == 0) return "Unknown";
    std::time_t time = static_cast<std::time_t>(timestamp);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time), "%Y-%m-%d %H:%M:%S UTC");
    return ss.str();
}
std::string EnhancedOutputManager::formatFileSize(size_t size) {
    const char* units[] = {"B", "KB", "MB", "GB"};
    double dsize = static_cast<double>(size);
    int unit = 0;
    while (dsize >= 1024.0 && unit < 3) {
        dsize /= 1024.0;
        unit++;
    }
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << dsize << " " << units[unit];
    return ss.str();
}
std::string EnhancedOutputManager::getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}
