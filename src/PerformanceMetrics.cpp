#include "../include/PerformanceMetrics.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <fstream>
#ifdef __linux__
#include <sys/resource.h>
#include <unistd.h>
#endif
PerformanceMetrics::PerformanceMetrics() : fileSize(0), baslineMemory(0), peakMemoryUsage(0) {
    baslineMemory = getProcessMemoryUsage();
}
PerformanceMetrics::~PerformanceMetrics() {
}
void PerformanceMetrics::startAnalysis() {
    analysisStartTime = std::chrono::high_resolution_clock::now();
    baslineMemory = getProcessMemoryUsage();
    peakMemoryUsage = baslineMemory;
}
void PerformanceMetrics::endAnalysis() {
    analysisEndTime = std::chrono::high_resolution_clock::now();
}
void PerformanceMetrics::startModule(const std::string& moduleName) {
    moduleStartTimes[moduleName] = std::chrono::high_resolution_clock::now();
    ModuleMetrics metrics;
    metrics.moduleName = moduleName;
    metrics.executionTime = 0.0;
    metrics.memoryUsed = 0;
    metrics.peakMemory = 0;
    metrics.success = false;
    moduleResults[moduleName] = metrics;
}
void PerformanceMetrics::endModule(const std::string& moduleName, bool success) {
    auto it = moduleStartTimes.find(moduleName);
    if (it != moduleStartTimes.end()) {
        auto endTime = std::chrono::high_resolution_clock::now();
        double elapsed = calculateElapsedTime(it->second, endTime);
        
        size_t currentMemory = getProcessMemoryUsage();
        peakMemoryUsage = std::max(peakMemoryUsage, currentMemory);
        
        moduleResults[moduleName].executionTime = elapsed;
        moduleResults[moduleName].success = success;
        moduleResults[moduleName].memoryUsed = currentMemory - baslineMemory;
        moduleResults[moduleName].peakMemory = peakMemoryUsage - baslineMemory;
        moduleStartTimes.erase(it);
    }
}
void PerformanceMetrics::recordMemoryUsage(const std::string& moduleName, size_t memoryUsed) {
    size_t currentMemory = getProcessMemoryUsage();
    peakMemoryUsage = std::max(peakMemoryUsage, currentMemory);
    if (!moduleName.empty()) {
        auto it = moduleResults.find(moduleName);
        if (it != moduleResults.end()) {
            it->second.memoryUsed = std::max(it->second.memoryUsed, memoryUsed);
            it->second.peakMemory = std::max(it->second.peakMemory, currentMemory - baslineMemory);
        }
    }
}
void PerformanceMetrics::setFileSize(size_t size) {
    fileSize = size;
}
PerformanceMetrics::OverallMetrics PerformanceMetrics::generateReport() {
    OverallMetrics report;
    report.totalTime = calculateElapsedTime(analysisStartTime, analysisEndTime);
    report.totalMemory = getProcessMemoryUsage() - baslineMemory;
    report.peakMemory = peakMemoryUsage - baslineMemory;
    report.fileSize = fileSize;
    for (const auto& pair : moduleResults) {
        report.moduleMetrics.push_back(pair.second);
    }
    report.performanceGrade = calculatePerformanceGrade(report);
    report.bottlenecks = identifyBottlenecks(report);
    report.recommendations = generateRecommendations(report);
    return report;
}
size_t PerformanceMetrics::getCurrentMemoryUsage() {
    return getProcessMemoryUsage() - baslineMemory;
}
double PerformanceMetrics::getAnalysisTime() {
    if (analysisStartTime.time_since_epoch().count() == 0) {
        return 0.0;
    }
    
    auto endTime = (analysisEndTime.time_since_epoch().count() != 0) ? 
                   analysisEndTime : std::chrono::high_resolution_clock::now();
    
    return calculateElapsedTime(analysisStartTime, endTime);
}
size_t PerformanceMetrics::getPeakMemoryUsage() {
    return peakMemoryUsage;
}
std::string PerformanceMetrics::calculatePerformanceGrade(const OverallMetrics& metrics) {
    double timeScore = 100.0;
    double memoryScore = 100.0;
    if (metrics.totalTime <= EXCELLENT_TIME_THRESHOLD) {
        timeScore = 95.0;
    } else if (metrics.totalTime <= GOOD_TIME_THRESHOLD) {
        timeScore = 85.0;
    } else if (metrics.totalTime <= FAIR_TIME_THRESHOLD) {
        timeScore = 75.0;
    } else if (metrics.totalTime <= POOR_TIME_THRESHOLD) {
        timeScore = 65.0;
    } else {
        timeScore = 50.0;
    }
    if (metrics.peakMemory <= EXCELLENT_MEMORY_THRESHOLD) {
        memoryScore = 95.0;
    } else if (metrics.peakMemory <= GOOD_MEMORY_THRESHOLD) {
        memoryScore = 85.0;
    } else if (metrics.peakMemory <= FAIR_MEMORY_THRESHOLD) {
        memoryScore = 75.0;
    } else if (metrics.peakMemory <= POOR_MEMORY_THRESHOLD) {
        memoryScore = 65.0;
    } else {
        memoryScore = 50.0;
    }
    double sizeMultiplier = 1.0;
    if (metrics.fileSize > 100 * 1024 * 1024) {  
        sizeMultiplier = 1.2;  
    } else if (metrics.fileSize < 1024 * 1024) {  
        sizeMultiplier = 0.8;  
    }
    double overallScore = (timeScore + memoryScore) / 2.0 * sizeMultiplier;
    if (overallScore >= 90) return "A (Excellent)";
    else if (overallScore >= 80) return "B (Good)";
    else if (overallScore >= 70) return "C (Fair)";
    else if (overallScore >= 60) return "D (Poor)";
    else return "F (Unacceptable)";
}
std::vector<std::string> PerformanceMetrics::identifyBottlenecks(const OverallMetrics& metrics) {
    std::vector<std::string> bottlenecks;
    if (metrics.totalTime > POOR_TIME_THRESHOLD) {
        bottlenecks.push_back("Overall analysis time exceeds acceptable threshold (" + 
                            formatTime(metrics.totalTime) + ")");
    }
    if (metrics.peakMemory > POOR_MEMORY_THRESHOLD) {
        bottlenecks.push_back("Peak memory usage exceeds threshold (" + 
                            formatMemory(metrics.peakMemory) + ")");
    }
    for (const auto& module : metrics.moduleMetrics) {
        double modulePercentage = (module.executionTime / metrics.totalTime) * 100.0;
        if (modulePercentage > 50.0) {
            std::stringstream ss;
            ss << "Module '" << module.moduleName << "' consumes " 
               << std::fixed << std::setprecision(1) << modulePercentage 
               << "% of total execution time";
            bottlenecks.push_back(ss.str());
        }
        if (module.peakMemory > metrics.peakMemory * 0.7) {
            std::stringstream ss;
            ss << "Module '" << module.moduleName << "' uses " 
               << formatMemory(module.peakMemory) << " of peak memory";
            bottlenecks.push_back(ss.str());
        }
    }
    return bottlenecks;
}
std::vector<std::string> PerformanceMetrics::generateRecommendations(const OverallMetrics& metrics) {
    std::vector<std::string> recommendations;
    if (metrics.totalTime > GOOD_TIME_THRESHOLD) {
        recommendations.push_back("Consider optimizing algorithm complexity for large files");
        recommendations.push_back("Implement parallel processing for independent analysis modules");
    }
    if (metrics.peakMemory > GOOD_MEMORY_THRESHOLD) {
        recommendations.push_back("Implement streaming analysis to reduce memory footprint");
        recommendations.push_back("Consider using memory-mapped files for large PE files");
    }
    if (metrics.fileSize > 100 * 1024 * 1024) {  
        recommendations.push_back("For files >100MB, consider implementing progressive analysis");
        recommendations.push_back("Add option to skip detailed analysis for very large files");
    }
    auto slowestModule = std::max_element(metrics.moduleMetrics.begin(), 
                                        metrics.moduleMetrics.end(),
                                        [](const ModuleMetrics& a, const ModuleMetrics& b) {
                                            return a.executionTime < b.executionTime;
                                        });
    if (slowestModule != metrics.moduleMetrics.end() && 
        slowestModule->executionTime > metrics.totalTime * 0.4) {
        recommendations.push_back("Optimize '" + slowestModule->moduleName + 
                                "' module - it's the primary performance bottleneck");
    }
    if (metrics.moduleMetrics.size() > 5) {
        recommendations.push_back("Consider implementing module dependency optimization");
    }
    return recommendations;
}
void PerformanceMetrics::reset() {
    moduleStartTimes.clear();
    moduleResults.clear();
    fileSize = 0;
    baslineMemory = getProcessMemoryUsage();
    peakMemoryUsage = baslineMemory;
}
double PerformanceMetrics::calculateElapsedTime(
    const std::chrono::high_resolution_clock::time_point& start,
    const std::chrono::high_resolution_clock::time_point& end) {
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    return static_cast<double>(duration.count()) / 1000000.0;  
}
size_t PerformanceMetrics::getProcessMemoryUsage() {
#ifdef __linux__
    std::ifstream statusFile("/proc/self/status");
    std::string line;
    size_t vmSize = 0;
    while (std::getline(statusFile, line)) {
        if (line.substr(0, 6) == "VmRSS:") {
            std::istringstream iss(line);
            std::string label, value, unit;
            iss >> label >> value >> unit;
            vmSize = std::stoull(value);
            if (unit == "kB") {
                vmSize *= 1024;  
            }
            break;
        }
    }
    return vmSize;
#else
    return 0;
#endif
}
std::string PerformanceMetrics::formatTime(double seconds) {
    std::stringstream ss;
    if (seconds < 1.0) {
        ss << std::fixed << std::setprecision(1) << (seconds * 1000.0) << "ms";
    } else if (seconds < 60.0) {
        ss << std::fixed << std::setprecision(2) << seconds << "s";
    } else {
        int minutes = static_cast<int>(seconds / 60);
        double remainingSeconds = seconds - (minutes * 60);
        ss << minutes << "m " << std::fixed << std::setprecision(1) << remainingSeconds << "s";
    }
    return ss.str();
}
std::string PerformanceMetrics::formatMemory(size_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB"};
    double dsize = static_cast<double>(bytes);
    int unit = 0;
    while (dsize >= 1024.0 && unit < 3) {
        dsize /= 1024.0;
        unit++;
    }
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << dsize << " " << units[unit];
    return ss.str();
}
