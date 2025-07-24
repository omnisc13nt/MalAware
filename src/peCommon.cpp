#include "peCommon.h"

FILE* g_output_file = nullptr;

bool isValidString(const char* str, size_t maxLen) {
    if (!str) return false;
    size_t len = 0;
    for (size_t i = 0; i < maxLen; ++i) {
        if (str[i] == '\0') {
            return len >= 1 && len <= 255;
        }

        if (str[i] >= 32 && str[i] <= 126) {
            len++;
        } else if ((unsigned char)str[i] >= 128) {
            len++;
        } else if (str[i] == '\0') {
            break;
        } else {
            return false;
        }
    }
    return len >= 1 && len <= 255;
}

bool isLikelyObfuscated(const char* str, size_t len) {
    if (!str || len == 0) return true;
    size_t nonPrintable = 0;
    size_t uppercase = 0;
    size_t lowercase = 0;
    size_t digits = 0;
    size_t symbols = 0;
    for (size_t i = 0; i < len && str[i] != '\0'; ++i) {
        if (str[i] < 32 || str[i] > 126) nonPrintable++;
        else if (str[i] >= 'A' && str[i] <= 'Z') uppercase++;
        else if (str[i] >= 'a' && str[i] <= 'z') lowercase++;
        else if (str[i] >= '0' && str[i] <= '9') digits++;
        else symbols++;
    }
    if (nonPrintable > len / 4) return true;
    if (len > 3 && uppercase == 0 && lowercase == 0) return true;
    if (len > 10 && symbols > len / 2) return true;
    return false;
}
