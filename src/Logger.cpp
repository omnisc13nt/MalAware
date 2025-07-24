#include "../include/peCommon.h"
#include <fstream>

// Define static members of Logger class
std::ofstream Logger::logFile;
std::ofstream Logger::outputFile;
bool Logger::isInitialized = false;
