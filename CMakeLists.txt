cmake_minimum_required(VERSION 3.10.2)

project(zygisk_telemetry_sniffer CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Directories
include_directories(include)

# Find necessary Android libraries
find_library(log-lib log)
find_library(android-lib android)

# Source files
set(SOURCE_FILES
    src/main.cpp
    src/hooks_native.cpp
    src/hooks_binder.cpp
    src/hooks_java.cpp
)

# Target
add_library(zygisk_telemetry_sniffer SHARED ${SOURCE_FILES})

# Link libraries
target_link_libraries(zygisk_telemetry_sniffer
    ${log-lib}
    ${android-lib}
)

# Optimization and hiding symbols
set_target_properties(zygisk_telemetry_sniffer PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN 1
)
