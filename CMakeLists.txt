# SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
#
# SPDX-License-Identifier: 0BSD
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.14)

project(
  AntiCheat
  VERSION 0.1.0
  LANGUAGES C
)

# --- C Standard ---
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- Custom CMake Modules ---
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# --- Guards ---
if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
  message(
    FATAL_ERROR
      "In-source builds not allowed. Please make a new directory"
      " (called a build directory) and run CMake from there."
  )
endif()

# --- Tools ---
find_program(CLANG_EXECUTABLE
    NAMES clang
    REQUIRED
    DOC "Clang compiler used exclusively for BPF object compilation"
)
find_program(BPFTOOL_EXECUTABLE
    NAMES bpftool
    REQUIRED
    DOC "bpftool for BPF object linking and skeleton generation"
)

# --- Dependencies ---
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)
find_package(VmlinuxH REQUIRED) # For CO-RE

# --- CMake Modules ---
include(BpfCompile)

# --- Status ---
message(STATUS "clang         : ${CLANG_EXECUTABLE}")
message(STATUS "bpftool       : ${BPFTOOL_EXECUTABLE}")
message(STATUS "CO-RE support : ${VmlinuxH_FOUND}")

add_subdirectory(bpf)
add_subdirectory(loader)
