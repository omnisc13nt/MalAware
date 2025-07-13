#ifndef ERROR_BOUNDS_CHECKER_H
#define ERROR_BOUNDS_CHECKER_H

#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>
#include <limits>

class ErrorBoundsChecker {
public:
    // Exception classes for different types of bounds errors
    class BoundsException : public std::runtime_error {
    public:
        explicit BoundsException(const std::string& message) : std::runtime_error(message) {}
    };

    class BufferOverflowException : public BoundsException {
    public:
        explicit BufferOverflowException(const std::string& message) : BoundsException("Buffer Overflow: " + message) {}
    };

    class IntegerOverflowException : public BoundsException {
    public:
        explicit IntegerOverflowException(const std::string& message) : BoundsException("Integer Overflow: " + message) {}
    };

    class InvalidParameterException : public BoundsException {
    public:
        explicit InvalidParameterException(const std::string& message) : BoundsException("Invalid Parameter: " + message) {}
    };

    class MemoryAccessException : public BoundsException {
    public:
        explicit MemoryAccessException(const std::string& message) : BoundsException("Memory Access Violation: " + message) {}
    };

    // Array and buffer bounds checking
    template<typename T>
    static void checkArrayBounds(const std::vector<T>& array, size_t index, const std::string& context = "") {
        if (index >= array.size()) {
            throw BufferOverflowException("Array index " + std::to_string(index) + 
                                        " out of bounds (size: " + std::to_string(array.size()) + ")" +
                                        (context.empty() ? "" : " in " + context));
        }
    }

    static void checkBufferBounds(const void* buffer, size_t bufferSize, size_t offset, size_t accessSize, const std::string& context = "") {
        if (buffer == nullptr) {
            throw MemoryAccessException("Null buffer pointer" + (context.empty() ? "" : " in " + context));
        }
        
        if (offset >= bufferSize) {
            throw BufferOverflowException("Offset " + std::to_string(offset) + 
                                        " exceeds buffer size " + std::to_string(bufferSize) +
                                        (context.empty() ? "" : " in " + context));
        }
        
        if (offset + accessSize > bufferSize) {
            throw BufferOverflowException("Access of " + std::to_string(accessSize) + 
                                        " bytes at offset " + std::to_string(offset) + 
                                        " exceeds buffer size " + std::to_string(bufferSize) +
                                        (context.empty() ? "" : " in " + context));
        }
    }

    static void checkStringBounds(const std::string& str, size_t index, const std::string& context = "") {
        if (index >= str.length()) {
            throw BufferOverflowException("String index " + std::to_string(index) + 
                                        " out of bounds (length: " + std::to_string(str.length()) + ")" +
                                        (context.empty() ? "" : " in " + context));
        }
    }

    // Integer overflow and underflow checking
    template<typename T>
    static void checkIntegerAddition(T a, T b, const std::string& context = "") {
        if (a > 0 && b > 0 && a > std::numeric_limits<T>::max() - b) {
            throw IntegerOverflowException("Addition overflow: " + std::to_string(a) + " + " + std::to_string(b) +
                                         (context.empty() ? "" : " in " + context));
        }
        if (a < 0 && b < 0 && a < std::numeric_limits<T>::min() - b) {
            throw IntegerOverflowException("Addition underflow: " + std::to_string(a) + " + " + std::to_string(b) +
                                         (context.empty() ? "" : " in " + context));
        }
    }

    template<typename T>
    static void checkIntegerMultiplication(T a, T b, const std::string& context = "") {
        if (a != 0 && b != 0) {
            if (a > 0 && b > 0 && a > std::numeric_limits<T>::max() / b) {
                throw IntegerOverflowException("Multiplication overflow: " + std::to_string(a) + " * " + std::to_string(b) +
                                             (context.empty() ? "" : " in " + context));
            }
            if (a < 0 && b < 0 && a < std::numeric_limits<T>::max() / b) {
                throw IntegerOverflowException("Multiplication overflow: " + std::to_string(a) + " * " + std::to_string(b) +
                                             (context.empty() ? "" : " in " + context));
            }
            if ((a > 0 && b < 0 && b < std::numeric_limits<T>::min() / a) ||
                (a < 0 && b > 0 && a < std::numeric_limits<T>::min() / b)) {
                throw IntegerOverflowException("Multiplication underflow: " + std::to_string(a) + " * " + std::to_string(b) +
                                             (context.empty() ? "" : " in " + context));
            }
        }
    }

    template<typename T>
    static void checkIntegerRange(T value, T minValue, T maxValue, const std::string& context = "") {
        if (value < minValue || value > maxValue) {
            throw InvalidParameterException("Value " + std::to_string(value) + 
                                          " out of range [" + std::to_string(minValue) + ", " + std::to_string(maxValue) + "]" +
                                          (context.empty() ? "" : " in " + context));
        }
    }

    // File and size validation
    static void checkFileSize(size_t fileSize, size_t minSize, size_t maxSize, const std::string& context = "") {
        if (fileSize < minSize) {
            throw InvalidParameterException("File size " + std::to_string(fileSize) + 
                                          " below minimum " + std::to_string(minSize) +
                                          (context.empty() ? "" : " in " + context));
        }
        if (fileSize > maxSize) {
            throw InvalidParameterException("File size " + std::to_string(fileSize) + 
                                          " exceeds maximum " + std::to_string(maxSize) +
                                          (context.empty() ? "" : " in " + context));
        }
    }

    static void checkAlignment(size_t value, size_t alignment, const std::string& context = "") {
        if (alignment == 0) {
            throw InvalidParameterException("Zero alignment value" + (context.empty() ? "" : " in " + context));
        }
        if (value % alignment != 0) {
            throw InvalidParameterException("Value " + std::to_string(value) + 
                                          " not aligned to " + std::to_string(alignment) +
                                          (context.empty() ? "" : " in " + context));
        }
    }

    // Pointer validation
    static void checkNullPointer(const void* ptr, const std::string& context = "") {
        if (ptr == nullptr) {
            throw MemoryAccessException("Null pointer access" + (context.empty() ? "" : " in " + context));
        }
    }

    // String validation
    static void checkStringLength(const std::string& str, size_t minLength, size_t maxLength, const std::string& context = "") {
        if (str.length() < minLength) {
            throw InvalidParameterException("String length " + std::to_string(str.length()) + 
                                          " below minimum " + std::to_string(minLength) +
                                          (context.empty() ? "" : " in " + context));
        }
        if (str.length() > maxLength) {
            throw InvalidParameterException("String length " + std::to_string(str.length()) + 
                                          " exceeds maximum " + std::to_string(maxLength) +
                                          (context.empty() ? "" : " in " + context));
        }
    }

    static void checkStringNotEmpty(const std::string& str, const std::string& context = "") {
        if (str.empty()) {
            throw InvalidParameterException("Empty string not allowed" + (context.empty() ? "" : " in " + context));
        }
    }

    // PE-specific validation
    static void checkPEOffset(uint32_t offset, uint32_t fileSize, uint32_t structSize, const std::string& context = "") {
        if (offset >= fileSize) {
            throw BufferOverflowException("PE offset " + std::to_string(offset) + 
                                        " exceeds file size " + std::to_string(fileSize) +
                                        (context.empty() ? "" : " in " + context));
        }
        if (offset + structSize > fileSize) {
            throw BufferOverflowException("PE structure of size " + std::to_string(structSize) + 
                                        " at offset " + std::to_string(offset) + 
                                        " exceeds file size " + std::to_string(fileSize) +
                                        (context.empty() ? "" : " in " + context));
        }
    }

    static void checkPESignature(uint32_t signature, uint32_t expectedSignature, const std::string& context = "") {
        if (signature != expectedSignature) {
            throw InvalidParameterException("Invalid PE signature 0x" + std::to_string(signature) + 
                                          " (expected 0x" + std::to_string(expectedSignature) + ")" +
                                          (context.empty() ? "" : " in " + context));
        }
    }

    // Network and API validation
    static void checkHttpStatusCode(int statusCode, const std::string& context = "") {
        if (statusCode < 100 || statusCode >= 600) {
            throw InvalidParameterException("Invalid HTTP status code " + std::to_string(statusCode) +
                                          (context.empty() ? "" : " in " + context));
        }
    }

    static void checkApiKeyFormat(const std::string& apiKey, const std::string& context = "") {
        checkStringNotEmpty(apiKey, context);
        checkStringLength(apiKey, 32, 128, context);
        
        // Check for valid characters (alphanumeric)
        for (char c : apiKey) {
            if (!std::isalnum(c)) {
                throw InvalidParameterException("API key contains invalid character '" + std::string(1, c) + "'" +
                                              (context.empty() ? "" : " in " + context));
            }
        }
    }

    // Utility functions for safe operations
    template<typename T>
    static T safeAdd(T a, T b, const std::string& context = "") {
        checkIntegerAddition(a, b, context);
        return a + b;
    }

    template<typename T>
    static T safeMultiply(T a, T b, const std::string& context = "") {
        checkIntegerMultiplication(a, b, context);
        return a * b;
    }

    static size_t safeArrayAccess(const std::vector<uint8_t>& array, size_t index, const std::string& context = "") {
        checkArrayBounds(array, index, context);
        return array[index];
    }
};

// Convenience macros for bounds checking
#define CHECK_BOUNDS(condition, message) \
    do { \
        if (!(condition)) { \
            throw ErrorBoundsChecker::BoundsException(message); \
        } \
    } while(0)

#define CHECK_BUFFER_BOUNDS(buffer, bufferSize, offset, accessSize, context) \
    ErrorBoundsChecker::checkBufferBounds(buffer, bufferSize, offset, accessSize, context)

#define CHECK_NULL_POINTER(ptr, context) \
    ErrorBoundsChecker::checkNullPointer(ptr, context)

#define CHECK_ARRAY_BOUNDS(array, index, context) \
    ErrorBoundsChecker::checkArrayBounds(array, index, context)

#define CHECK_INTEGER_RANGE(value, min, max, context) \
    ErrorBoundsChecker::checkIntegerRange(value, min, max, context)

#endif // ERROR_BOUNDS_CHECKER_H
