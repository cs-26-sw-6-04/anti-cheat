# SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
#
# SPDX-License-Identifier: MIT

set(BPF_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${PROJECT_SOURCE_DIR}/src/shared"
    ${LIBBPF_INCLUDE_DIRS}
)

# Debian/Ubuntu ship asm/ under a multiarch path that clang -target bpf does
# not search by default; <linux/errno.h> then fails to find <asm/errno.h>.
execute_process(
    COMMAND ${CMAKE_C_COMPILER} -print-multiarch
    OUTPUT_VARIABLE _bpf_multiarch
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(_bpf_multiarch AND EXISTS "/usr/include/${_bpf_multiarch}")
  list(APPEND BPF_INCLUDE_DIRS "/usr/include/${_bpf_multiarch}")
endif()

set(BPF_DEFINES "")
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  list(APPEND BPF_DEFINES AC_DEBUG_BUILD)
endif()

# All enforcers live in one TU. Adding a new enforcer: drop a <name>.bpf.h
# that declares its SEC() programs and #include it from enforcers.bpf.c.
add_bpf_object(enforcers
    enforcers.bpf.c
    VMLINUX_H "${VmlinuxH_INCLUDE_DIR}"
    INCLUDES  ${BPF_INCLUDE_DIRS}
    DEFINES   ${BPF_DEFINES}
)

set(BPF_COMBINED_O "${CMAKE_CURRENT_BINARY_DIR}/skeleton/enforcers.bpf.o")
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/skeleton")
set(BPF_SKELETON_H "${CMAKE_CURRENT_BINARY_DIR}/enforcers_bpf.skel.h")

add_bpf_skeleton(enforcers_skeleton
    OBJECTS    enforcers
    COMBINED_O "${BPF_COMBINED_O}"
    SKELETON_H "${BPF_SKELETON_H}"
)

set(BPF_SKELETON_HEADER "${BPF_SKELETON_H}" PARENT_SCOPE)
