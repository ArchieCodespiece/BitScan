cmake_minimum_required(VERSION 3.16)
project(bitscan_sanitizer LANGUAGES CXX)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_library(bitscan_sanitizer SHARED sanitizer.cpp)
target_compile_features(bitscan_sanitizer PRIVATE cxx_std_17)
target_include_directories(bitscan_sanitizer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bitscan_sanitizer PRIVATE OpenSSL::Crypto)
set_target_properties(bitscan_sanitizer PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)
if(MSVC)
    target_compile_options(bitscan_sanitizer PRIVATE /W4 /permissive-)
else()
    target_compile_options(bitscan_sanitizer PRIVATE -Wall -Wextra -Wpedantic)
endif()
