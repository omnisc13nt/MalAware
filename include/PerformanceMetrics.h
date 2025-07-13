#ifndef PERFORMANCE_METRICS_H
#define PERFORMANCE_METRICS_H
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <cstdint>
class PerformanceMetrics {
public:
    struct ModuleMetrics {
        std::string moduleName;
        double executionTime;
        size_t memoryUsed;
        size_t peakMemory;
        bool success;
    };
    struct OverallMetrics {
        double totalTime;
        size_t totalMemory;
        size_t peakMemory;
        size_t fileSize;
        std::vector<ModuleMetrics> moduleMetrics;
        std::string performanceGrade;
        std::vector<std::string> bottlenecks;
        std::vector<std::string> recommendations;
    };
    PerformanceMetrics();
    ~PerformanceMetrics();
    void startAnalysis();
    void endAnalysis();
    void startModule(const std::string& moduleName);
    void endModule(const std::string& moduleName, bool success = true);
    void recordMemoryUsage(const std::string& moduleName, size_t memoryUsed);
    void setFileSize(size_t size);
    OverallMetrics generateReport();
    size_t getCurrentMemoryUsage();
    double getAnalysisTime();
    size_t getPeakMemoryUsage();
    std::string calculatePerformanceGrade(const OverallMetrics& metrics);
    std::vector<std::string> identifyBottlenecks(const OverallMetrics& metrics);
    std::vector<std::string> generateRecommendations(const OverallMetrics& metrics);
    void reset();
private:
    std::chrono::high_resolution_clock::time_point analysisStartTime;
    std::chrono::high_resolution_clock::time_point analysisEndTime;
    std::map<std::string, std::chrono::high_resolution_clock::time_point> moduleStartTimes;
    std::map<std::string, ModuleMetrics> moduleResults;
    size_t fileSize;
    size_t baslineMemory;
    size_t peakMemoryUsage;
    static constexpr double EXCELLENT_TIME_THRESHOLD = 1.0;  
    static constexpr double GOOD_TIME_THRESHOLD = 5.0;
    static constexpr double FAIR_TIME_THRESHOLD = 15.0;
    static constexpr double POOR_TIME_THRESHOLD = 30.0;
    static constexpr size_t EXCELLENT_MEMORY_THRESHOLD = 50 * 1024 * 1024;  
    static constexpr size_t GOOD_MEMORY_THRESHOLD = 100 * 1024 * 1024;      
    static constexpr size_t FAIR_MEMORY_THRESHOLD = 200 * 1024 * 1024;      
    static constexpr size_t POOR_MEMORY_THRESHOLD = 500 * 1024 * 1024;      
    double calculateElapsedTime(
        const std::chrono::high_resolution_clock::time_point& start,
        const std::chrono::high_resolution_clock::time_point& end
    );
    size_t getProcessMemoryUsage();
    std::string formatTime(double seconds);
    std::string formatMemory(size_t bytes);
};
#endif 
