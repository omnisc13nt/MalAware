#include "../include/AdvancedEntropyAnalyzer.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cmath>
AdvancedEntropyAnalyzer::AdvancedEntropyAnalyzer() {
}
AdvancedEntropyAnalyzer::~AdvancedEntropyAnalyzer() {
}
double AdvancedEntropyAnalyzer::calculateEntropy(const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return 0.0;
    }
    auto frequencies = calculateFrequencies(data, size);
    return calculateShannonEntropy(frequencies, size);
}
std::string AdvancedEntropyAnalyzer::generateEntropyVisualization(double entropy, int maxChars) {
    std::string visualization;
    int filledChars = static_cast<int>((entropy / 8.0) * maxChars);
    for (int i = 0; i < maxChars; ++i) {
        if (i < filledChars) {
            if (entropy >= HIGH_ENTROPY_THRESHOLD) {
                visualization += ENTROPY_CHAR_FULL;
            } else if (entropy >= MEDIUM_ENTROPY_THRESHOLD) {
                visualization += ENTROPY_CHAR_HIGH;
            } else if (entropy >= LOW_ENTROPY_THRESHOLD) {
                visualization += ENTROPY_CHAR_MED;
            } else {
                visualization += ENTROPY_CHAR_LOW;
            }
        } else {
            visualization += ENTROPY_CHAR_EMPTY;
        }
    }
    return visualization;
}
std::string AdvancedEntropyAnalyzer::classifyEntropy(double entropy) {
    if (entropy >= PACKING_ENTROPY_THRESHOLD) {
        return "Very High (Likely Packed/Encrypted)";
    } else if (entropy >= HIGH_ENTROPY_THRESHOLD) {
        return "High (Compressed/Obfuscated)";
    } else if (entropy >= MEDIUM_ENTROPY_THRESHOLD) {
        return "Medium (Normal Code/Data)";
    } else if (entropy >= LOW_ENTROPY_THRESHOLD) {
        return "Low (Repetitive Data)";
    } else {
        return "Very Low (Padding/Zeros)";
    }
}
bool AdvancedEntropyAnalyzer::detectPacking(const uint8_t* data, size_t size) {
    if (!data || size < 1024) {
        return false;
    }
    PackingIndicators indicators = analyzePackingIndicators(data, size);
    int indicatorCount = 0;
    if (indicators.highEntropy) indicatorCount++;
    if (indicators.lowImportCount) indicatorCount++;
    if (indicators.suspiciousEntryPoint) indicatorCount++;
    if (indicators.packedSections) indicatorCount++;
    return indicatorCount >= 2 && indicators.confidence > 0.7;
}
AdvancedEntropyAnalyzer::OverallEntropyReport AdvancedEntropyAnalyzer::analyzeFile(const std::string& filePath) {
    OverallEntropyReport report;
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        report.riskScore = 0.0;
        return report;
    }
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    if (fileSize == 0) {
        report.riskScore = 0.0;
        return report;
    }
    std::vector<uint8_t> fileData(fileSize);
    file.read(reinterpret_cast<char*>(fileData.data()), fileSize);
    file.close();
    report.fileOverall.entropy = calculateEntropy(fileData.data(), fileSize);
    report.fileOverall.visualization = generateEntropyVisualization(report.fileOverall.entropy);
    report.fileOverall.classification = classifyEntropy(report.fileOverall.entropy);
    report.fileOverall.isPacked = detectPacking(fileData.data(), fileSize);
    report.fileOverall.isCompressed = report.fileOverall.entropy > 6.5;
    report.fileOverall.isEncrypted = report.fileOverall.entropy > 7.8;
    report.fileOverall.confidence = std::min(1.0, report.fileOverall.entropy / 8.0);
    if (fileSize > 1024 && fileData[0] == 'M' && fileData[1] == 'Z') {
        uint32_t peOffset = *reinterpret_cast<uint32_t*>(fileData.data() + 0x3C);
        if (peOffset < fileSize - 4 && 
            fileData[peOffset] == 'P' && fileData[peOffset + 1] == 'E') {
            std::vector<std::pair<std::string, std::pair<size_t, size_t>>> sections = {
                {".text", {0x1000, std::min(size_t(0x10000), fileSize)}},
                {".data", {0x20000, std::min(size_t(0x5000), fileSize)}},
                {".rdata", {0x30000, std::min(size_t(0x5000), fileSize)}}
            };
            for (const auto& section : sections) {
                if (section.second.first + section.second.second <= fileSize) {
                    SectionEntropyAnalysis sectionAnalysis;
                    sectionAnalysis.sectionName = section.first;
                    sectionAnalysis.sectionSize = section.second.second;
                    sectionAnalysis.virtualAddress = section.second.first;
                    const uint8_t* sectionData = fileData.data() + section.second.first;
                    sectionAnalysis.result.entropy = calculateEntropy(sectionData, section.second.second);
                    sectionAnalysis.result.visualization = generateEntropyVisualization(sectionAnalysis.result.entropy);
                    sectionAnalysis.result.classification = classifyEntropy(sectionAnalysis.result.entropy);
                    sectionAnalysis.result.isPacked = sectionAnalysis.result.entropy > PACKING_ENTROPY_THRESHOLD;
                    sectionAnalysis.result.isCompressed = sectionAnalysis.result.entropy > 6.5;
                    sectionAnalysis.result.isEncrypted = sectionAnalysis.result.entropy > 7.8;
                    sectionAnalysis.result.confidence = std::min(1.0, sectionAnalysis.result.entropy / 8.0);
                    report.sections.push_back(sectionAnalysis);
                }
            }
        }
    }
    std::vector<double> slidingEntropy = calculateSlidingEntropy(fileData.data(), fileSize);
    report.suspiciousRegions = detectSuspiciousPatterns(slidingEntropy);
    std::stringstream packingStream;
    if (report.fileOverall.isPacked) {
        packingStream << "PACKING DETECTED:\n";
        packingStream << "  - High entropy (" << std::fixed << std::setprecision(2) << report.fileOverall.entropy << "/8.0)\n";
        if (report.fileOverall.isEncrypted) {
            packingStream << "  - Possible encryption detected\n";
        }
        if (report.fileOverall.isCompressed) {
            packingStream << "  - Compression indicators present\n";
        }
    } else {
        packingStream << "No strong packing indicators detected.";
    }
    report.packingIndicators = packingStream.str();
    report.riskScore = 0.0;
    if (report.fileOverall.entropy > PACKING_ENTROPY_THRESHOLD) {
        report.riskScore += 30.0;
    } else if (report.fileOverall.entropy > HIGH_ENTROPY_THRESHOLD) {
        report.riskScore += 15.0;
    }
    if (report.fileOverall.isPacked) {
        report.riskScore += 25.0;
    }
    if (!report.suspiciousRegions.empty()) {
        report.riskScore += 10.0 * std::min(3.0, static_cast<double>(report.suspiciousRegions.size()));
    }
    return report;
}
std::vector<double> AdvancedEntropyAnalyzer::calculateSlidingEntropy(const uint8_t* data, size_t size, size_t windowSize) {
    std::vector<double> entropyValues;
    if (!data || size < windowSize) {
        return entropyValues;
    }
    for (size_t i = 0; i <= size - windowSize; i += windowSize / 2) {
        double entropy = calculateEntropy(data + i, windowSize);
        entropyValues.push_back(entropy);
    }
    return entropyValues;
}
std::vector<std::string> AdvancedEntropyAnalyzer::detectSuspiciousPatterns(const std::vector<double>& entropyValues) {
    std::vector<std::string> suspiciousRegions;
    for (size_t i = 0; i < entropyValues.size(); ++i) {
        if (entropyValues[i] > PACKING_ENTROPY_THRESHOLD) {
            std::stringstream ss;
            ss << "High entropy region at offset " << std::hex << (i * 512) 
               << " (entropy: " << std::fixed << std::setprecision(2) << entropyValues[i] << ")";
            suspiciousRegions.push_back(ss.str());
        }
    }
    for (size_t i = 1; i < entropyValues.size() - 1; ++i) {
        double current = entropyValues[i];
        double prev = entropyValues[i - 1];
        double next = entropyValues[i + 1];
        if (current > prev + 2.0 && current > next + 2.0 && current > 6.0) {
            std::stringstream ss;
            ss << "Entropy spike at offset " << std::hex << (i * 512) 
               << " (spike: " << std::fixed << std::setprecision(2) << current << ")";
            suspiciousRegions.push_back(ss.str());
        }
    }
    return suspiciousRegions;
}
double AdvancedEntropyAnalyzer::estimateCompressionRatio(const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return 0.0;
    }
    double entropy = calculateEntropy(data, size);
    double theoreticalRatio = entropy / 8.0;
    std::map<uint8_t, uint32_t> frequencies = calculateFrequencies(data, size);
    uint32_t uniqueBytes = frequencies.size();
    double uniquenessRatio = static_cast<double>(uniqueBytes) / 256.0;
    return theoreticalRatio * uniquenessRatio;
}
std::map<uint8_t, uint32_t> AdvancedEntropyAnalyzer::calculateFrequencies(const uint8_t* data, size_t size) {
    std::map<uint8_t, uint32_t> frequencies;
    for (size_t i = 0; i < size; ++i) {
        frequencies[data[i]]++;
    }
    return frequencies;
}
double AdvancedEntropyAnalyzer::calculateShannonEntropy(const std::map<uint8_t, uint32_t>& frequencies, size_t totalBytes) {
    double entropy = 0.0;
    for (const auto& freq : frequencies) {
        double probability = static_cast<double>(freq.second) / totalBytes;
        if (probability > 0.0) {
            entropy -= probability * std::log2(probability);
        }
    }
    return entropy;
}
AdvancedEntropyAnalyzer::PackingIndicators AdvancedEntropyAnalyzer::analyzePackingIndicators(const uint8_t* data, size_t size) {
    PackingIndicators indicators;
    indicators.highEntropy = false;
    indicators.lowImportCount = false;
    indicators.suspiciousEntryPoint = false;
    indicators.packedSections = false;
    indicators.confidence = 0.0;
    double overallEntropy = calculateEntropy(data, size);
    indicators.highEntropy = overallEntropy > PACKING_ENTROPY_THRESHOLD;
    std::vector<double> slidingEntropy = calculateSlidingEntropy(data, size, 1024);
    indicators.packedSections = checkHighEntropyRegions(slidingEntropy);
    if (indicators.highEntropy) indicators.confidence += 0.4;
    if (indicators.packedSections) indicators.confidence += 0.3;
    if (indicators.lowImportCount) indicators.confidence += 0.2;
    if (indicators.suspiciousEntryPoint) indicators.confidence += 0.1;
    return indicators;
}
bool AdvancedEntropyAnalyzer::checkHighEntropyRegions(const std::vector<double>& entropyValues) {
    int highEntropyCount = 0;
    for (double entropy : entropyValues) {
        if (entropy > PACKING_ENTROPY_THRESHOLD) {
            highEntropyCount++;
        }
    }
    double highEntropyRatio = static_cast<double>(highEntropyCount) / entropyValues.size();
    return highEntropyRatio > 0.3;
}
