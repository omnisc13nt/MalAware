#pragma once

#include <cstdio>
#include <cstdarg>

// Global output file pointer
extern FILE* g_output_file;

// Custom printf function that writes to both stdout and file
inline int printf_tee(const char* format, ...) {
    char buffer[2048];
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    // Write to stdout
    fputs(buffer, stdout);
    fflush(stdout);
    
    // Write to file if open
    if (g_output_file) {
        fputs(buffer, g_output_file);
        fflush(g_output_file);
    }
    
    return ret;
}

// Override printf with our custom function
#define printf printf_tee
