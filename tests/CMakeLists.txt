# SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
#
# SPDX-License-Identifier: MIT

find_package(Catch2 3 QUIET CONFIG)

if(NOT Catch2_FOUND)
  message(FATAL_ERROR
      "Catch2 not found. Install test dependencies with "
      "`conan install . -s build_type=<Debug|Release> --build=missing` "
      "and configure with the Conan-generated `conan-debug` or `conan-release` preset."
  )
endif()

include(Catch)

add_subdirectory(vendor/linux-inject)

get_target_property(_libbpf_includes libbpf::libbpf INTERFACE_INCLUDE_DIRECTORIES)

set(BPF_HELPER_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/helpers"
    "${PROJECT_SOURCE_DIR}/src/shared"
    ${_libbpf_includes}
)
execute_process(
    COMMAND ${CMAKE_C_COMPILER} -print-multiarch
    OUTPUT_VARIABLE _bpf_helper_multiarch
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(_bpf_helper_multiarch AND EXISTS "/usr/include/${_bpf_helper_multiarch}")
  list(APPEND BPF_HELPER_INCLUDE_DIRS "/usr/include/${_bpf_helper_multiarch}")
endif()

add_bpf_object(ebpf_exfil
    helpers/ebpf_exfil.bpf.c
    VMLINUX_H "${VmlinuxH_INCLUDE_DIR}"
    INCLUDES  ${BPF_HELPER_INCLUDE_DIRS}
)

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/skeleton")
set(EBPF_EXFIL_COMBINED_O "${CMAKE_CURRENT_BINARY_DIR}/skeleton/ebpf_exfil.bpf.o")
set(EBPF_EXFIL_SKELETON_H "${CMAKE_CURRENT_BINARY_DIR}/ebpf_exfil_bpf.skel.h")

add_bpf_skeleton(ebpf_exfil_skeleton
    OBJECTS    ebpf_exfil
    COMBINED_O "${EBPF_EXFIL_COMBINED_O}"
    SKELETON_H "${EBPF_EXFIL_SKELETON_H}"
)

add_library(real_cheat_payload SHARED real_cheat_payload.c)
set_target_properties(real_cheat_payload PROPERTIES
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)

set(REAL_CHEAT_PAYLOAD_PATH "${CMAKE_CURRENT_BINARY_DIR}/real_cheat_payload.so")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/real_cheat_payload_path.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/real_cheat_payload_path.h"
    @ONLY
)

file(GLOB AC_SUPPORT_SOURCES CONFIGURE_DEPENDS "support/*.cpp")
file(GLOB AC_TEST_SOURCES    CONFIGURE_DEPENDS "*.cpp")

add_executable(ac_tests
    ${AC_SUPPORT_SOURCES}
    ${AC_TEST_SOURCES}
)

add_dependencies(ac_tests real_cheat_payload ebpf_exfil_skeleton)

target_compile_features(ac_tests PRIVATE cxx_std_17)

target_include_directories(ac_tests
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/support"
        "${PROJECT_SOURCE_DIR}/src/shared"
        "${CMAKE_CURRENT_BINARY_DIR}"
)

target_link_libraries(ac_tests
    PRIVATE
        Catch2::Catch2WithMain
        ac_loader_runtime
        libbpf::libbpf
)

if(TARGET linux_inject_vendor)
  target_link_libraries(ac_tests PRIVATE linux_inject_vendor)
  target_compile_definitions(ac_tests PRIVATE HAVE_LINUX_INJECT=1)
endif()

catch_discover_tests(ac_tests
    DISCOVERY_MODE PRE_TEST
    PROPERTIES
        RUN_SERIAL TRUE
        TIMEOUT 20
        SKIP_REGULAR_EXPRESSION "skipping live BPF test:"
)
