
CXX = g++
CXX_WIN = x86_64-w64-mingw32-g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra
INCLUDES = -Iinclude
LIBS = 

SOURCES = main.cpp src/*.cpp

TARGET_LINUX = peFileParser
TARGET_WIN = peFileParserWindows.exe

all: $(TARGET_LINUX)

linux: $(TARGET_LINUX)

$(TARGET_LINUX):
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(SOURCES) -o $(TARGET_LINUX) $(LIBS)

windows: $(TARGET_WIN)

$(TARGET_WIN):
	$(CXX_WIN) $(CXXFLAGS) $(INCLUDES) $(SOURCES) -o $(TARGET_WIN) -static-libgcc -static-libstdc++ $(LIBS)

cross: $(TARGET_LINUX) $(TARGET_WIN)

clean:
	rm -f $(TARGET_LINUX) $(TARGET_WIN)

install-deps:
	@echo "Installing required dependencies..."
	sudo apt-get update
	sudo apt-get install -y libcurl4-openssl-dev libssl-dev libcrypto++-dev libjsoncpp-dev

help:
	@echo "Available targets:"
	@echo "  all          - Build Linux version (default)"  
	@echo "  linux        - Build Linux version"
	@echo "  windows      - Build Windows version"
	@echo "  cross        - Build both versions"
	@echo "  install-deps - Install required dependencies"
	@echo "  clean        - Remove executables"
	@echo "  help         - Show this help"

.PHONY: all linux windows cross clean install-deps help
