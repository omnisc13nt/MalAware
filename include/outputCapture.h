#pragma once
#include <cstdio>
#include <cstdarg>
extern FILE* g_output_file;
inline int printf_tee(const char* format, ...) {
    char buffer[2048];
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    fputs(buffer, stdout);
    fflush(stdout);
    if (g_output_file) {
        fputs(buffer, g_output_file);
        fflush(g_output_file);
    }
    return ret;
}
#define printf printf_tee
