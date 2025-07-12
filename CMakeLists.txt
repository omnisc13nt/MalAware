cmake_minimum_required(VERSION 3.10)
project(PEFileParser)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Include directories
include_directories(include)

# Source files
file(GLOB_RECURSE SOURCES "src/*.cpp")

# Create modular executable
add_executable(peFileParser_modular main_new.cpp ${SOURCES})

# Create original executable
add_executable(peFileParser main.cpp)

# Set output directory
set_target_properties(peFileParser_modular PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

set_target_properties(peFileParser PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Install targets
install(TARGETS peFileParser_modular peFileParser
    DESTINATION bin
)
