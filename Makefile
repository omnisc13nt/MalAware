
CXX = g++
CXX_WIN = x86_64-w64-mingw32-g++
CXXFLAGS = -std=c++17 -O2
INCLUDES = -Iinclude

SOURCES = main.cpp src/*.cpp

TARGET_LINUX = peFileParserLinux
TARGET_WIN = peFileParserWindows.exe

all: $(TARGET_LINUX)

linux: $(TARGET_LINUX)

$(TARGET_LINUX):
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SOURCES) -o $(TARGET_LINUX)

windows: $(TARGET_WIN)

$(TARGET_WIN):
	$(CXX_WIN) $(CXXFLAGS) $(INCLUDES) $(SOURCES) -o $(TARGET_WIN) -static-libgcc -static-libstdc++

cross: $(TARGET_LINUX) $(TARGET_WIN)

clean:
	rm -f $(TARGET_LINUX) $(TARGET_WIN)

help:
	@echo "Available targets:"
	@echo "  all      - Build Linux version (default)"
	@echo "  linux    - Build Linux version"
	@echo "  windows  - Build Windows version"
	@echo "  cross    - Build both versions"
	@echo "  clean    - Remove executables"
	@echo "  help     - Show this help"

.PHONY: all linux windows cross clean help
