# SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
#
# SPDX-License-Identifier: MIT

# BpfCompile.cmake
#
# add_bpf_object(<target> <source>
#                [VMLINUX_H <dir>]
#                [INCLUDES <dir>...]
#                [DEFINES <DEF>...])
#
# add_bpf_skeleton(<target>
#                  OBJECTS <target>...
#                  COMBINED_O <path>
#                  SKELETON_H <path>)
#
# BPF objects must be compiled with clang -target bpf. We cannot set
# CMAKE_C_COMPILER or CMAKE_C_FLAGS for this because those are global and
# would break the host build. Instead clang is called directly via
# add_custom_command.
#
# Each BPF source also gets an EXCLUDE_FROM_ALL OBJECT library with the same
# flags so that CMake emits a correct entry in compile_commands.json for
# clangd and other tooling.

# 3.21 is required for DEPFILE on add_custom_command (header dep tracking
# below) to work with both Makefile and Ninja generators.
cmake_minimum_required(VERSION 3.21)

foreach(_tool CLANG_EXECUTABLE BPFTOOL_EXECUTABLE)
  if(NOT ${_tool})
    message(FATAL_ERROR "BpfCompile: ${_tool} is not set")
  endif()
endforeach()

function(add_bpf_object TARGET SOURCE)
  cmake_parse_arguments(BPF "" "VMLINUX_H" "INCLUDES;DEFINES" ${ARGN})

  if(NOT IS_ABSOLUTE "${SOURCE}")
    set(SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE}")
  endif()

  set(output_o "${CMAKE_CURRENT_BINARY_DIR}/${TARGET}.bpf.o")
  set(depfile "${CMAKE_CURRENT_BINARY_DIR}/${TARGET}.bpf.o.d")

  set(flags -target bpf -g -O2
        -Wno-missing-declarations
        -Werror=uninitialized
        -Werror=return-type
    )
  set(incdirs ${BPF_INCLUDES})
  set(defines ${BPF_DEFINES})

  if(BPF_VMLINUX_H)
    list(APPEND incdirs "${BPF_VMLINUX_H}")
    list(APPEND defines "HAVE_VMLINUX_H")
  endif()

  set(clang_cmd ${flags})
  foreach(d IN LISTS incdirs)
    list(APPEND clang_cmd "-I${d}")
  endforeach()
  foreach(d IN LISTS defines)
    list(APPEND clang_cmd "-D${d}")
  endforeach()

  # -MMD/-MF emits a make-style depfile listing every #include'd header.
  # CMake's DEPFILE wires it back so a header edit triggers a rebuild;
  # without this, changes to a .bpf.h would silently produce a stale .o.
  add_custom_command(
        OUTPUT  "${output_o}"
        COMMAND "${CLANG_EXECUTABLE}" ${clang_cmd}
                -MMD -MF "${depfile}"
                -c -o "${output_o}" "${SOURCE}"
        DEPENDS "${SOURCE}" ${BPF_VMLINUX_H}
        DEPFILE "${depfile}"
        VERBATIM
        COMMENT "Compiling BPF object: ${TARGET}.bpf.o"
    )

  add_custom_target("${TARGET}" DEPENDS "${output_o}")

  # Tooling stub: never built, exists only so compile_commands.json gets
  # the right include paths and defines for clangd.
  set(stub "${TARGET}__tooling")
  add_library("${stub}" OBJECT EXCLUDE_FROM_ALL "${SOURCE}")
  target_include_directories("${stub}" SYSTEM PRIVATE ${incdirs})
  target_compile_definitions("${stub}" PRIVATE ${defines})
  target_compile_options("${stub}" PRIVATE
        -Wno-unused-variable
        -Wno-unused-function
        -Wno-unknown-attributes
    )
  set_target_properties("${stub}" PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )

  set("${TARGET}_OBJECT" "${output_o}" PARENT_SCOPE)
endfunction()

function(add_bpf_skeleton TARGET)
  cmake_parse_arguments(SKEL "" "COMBINED_O;SKELETON_H" "OBJECTS" ${ARGN})

  if(NOT SKEL_OBJECTS)
    message(FATAL_ERROR "add_bpf_skeleton: OBJECTS is required")
  endif()
  if(NOT SKEL_COMBINED_O)
    message(FATAL_ERROR "add_bpf_skeleton: COMBINED_O is required")
  endif()
  if(NOT SKEL_SKELETON_H)
    message(FATAL_ERROR "add_bpf_skeleton: SKELETON_H is required")
  endif()

  set(obj_files "")
  set(obj_targets "")
  foreach(obj IN LISTS SKEL_OBJECTS)
    if(NOT DEFINED "${obj}_OBJECT")
      message(FATAL_ERROR
                "add_bpf_skeleton: ${obj}_OBJECT not defined; "
                "call add_bpf_object(${obj} ...) first")
    endif()
    list(APPEND obj_files   "${${obj}_OBJECT}")
    list(APPEND obj_targets "${obj}")
  endforeach()

  add_custom_command(
        OUTPUT  "${SKEL_COMBINED_O}"
        COMMAND "${BPFTOOL_EXECUTABLE}" gen object "${SKEL_COMBINED_O}" ${obj_files}
        DEPENDS ${obj_files} ${obj_targets}
        VERBATIM
        COMMENT "Linking BPF objects -> ${SKEL_COMBINED_O}"
    )

  # Redirect stdout rather than using bpftool's OUTPUT keyword to avoid
  # make seeing two rules for the same file and reporting a circular dep.
  add_custom_command(
        OUTPUT  "${SKEL_SKELETON_H}"
        COMMAND "${BPFTOOL_EXECUTABLE}" gen skeleton "${SKEL_COMBINED_O}"
                > "${SKEL_SKELETON_H}"
        DEPENDS "${SKEL_COMBINED_O}"
        COMMENT "Generating BPF skeleton -> ${SKEL_SKELETON_H}"
    )

  add_custom_target("${TARGET}" DEPENDS "${SKEL_SKELETON_H}")

  set("${TARGET}_HEADER" "${SKEL_SKELETON_H}" PARENT_SCOPE)
endfunction()
