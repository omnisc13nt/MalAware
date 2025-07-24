#include "../include/peCommon.h"
#include <fstream>

std::ofstream Logger::logFile;
std::ofstream Logger::outputFile;
bool Logger::isInitialized = false;
