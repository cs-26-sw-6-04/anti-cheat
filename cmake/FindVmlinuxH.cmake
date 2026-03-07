# SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
#
# SPDX-License-Identifier: MIT

# FindVmlinuxH.cmake
#
# Finds or generates the vmlinux.h BTF header for BPF CO-RE.
# CO-RE is not optional; this module is REQUIRED.
#
# Search order:
#   1. VMLINUX_H_DIR if set
#   2. /usr/include, /usr/local/include
#   3. Generate from /sys/kernel/btf/vmlinux via bpftool
#      (written to ${CMAKE_CURRENT_BINARY_DIR}/btf/vmlinux.h)
#
# Provides:
#   VmlinuxH_FOUND
#   VmlinuxH_INCLUDE_DIR
#   VmlinuxH_FILE
#   VmlinuxH::Headers  (INTERFACE target; adds include dir + HAVE_VMLINUX_H)
#
# Cache variables:
#   VMLINUX_H_DIR      hint directory for a pre-built vmlinux.h
#   VMLINUX_H_GENERATE set OFF to disable auto-generation (default ON)

cmake_minimum_required(VERSION 3.16)
include(FindPackageHandleStandardArgs)

set(VMLINUX_H_DIR "" CACHE PATH "Directory containing a pre-built vmlinux.h")
option(VMLINUX_H_GENERATE "Generate vmlinux.h from kernel BTF if not found" ON)

# Use file(EXISTS) instead of find_path() to avoid the NOTFOUND cache sentinel
# shadowing variables set by the generation step in the same configure pass.
foreach(dir IN ITEMS "${VMLINUX_H_DIR}" /usr/include /usr/local/include)
  if(dir AND EXISTS "${dir}/vmlinux.h")
    set(VmlinuxH_INCLUDE_DIR "${dir}")
    message(VERBOSE "FindVmlinuxH: found ${dir}/vmlinux.h")
    break()
  endif()
endforeach()

if(NOT VmlinuxH_INCLUDE_DIR AND VMLINUX_H_GENERATE)
  set(btf_src "/sys/kernel/btf/vmlinux")
  set(btf_dir "${CMAKE_CURRENT_BINARY_DIR}/btf")
  set(btf_out "${btf_dir}/vmlinux.h")

  if(NOT BPFTOOL_EXECUTABLE)
    message(STATUS "FindVmlinuxH: BPFTOOL_EXECUTABLE not set, cannot generate vmlinux.h")
  elseif(EXISTS "${btf_out}")
    message(VERBOSE "FindVmlinuxH: reusing ${btf_out}")
    set(VmlinuxH_INCLUDE_DIR "${btf_dir}")
  elseif(NOT EXISTS "${btf_src}")
    message(STATUS "FindVmlinuxH: ${btf_src} not present, kernel may lack BTF support")
  else()
    message(STATUS "FindVmlinuxH: generating vmlinux.h from ${btf_src}")
    file(MAKE_DIRECTORY "${btf_dir}")
    execute_process(
            COMMAND         "${BPFTOOL_EXECUTABLE}" btf dump file "${btf_src}" format c
            OUTPUT_FILE     "${btf_out}"
            ERROR_VARIABLE  btf_err
            RESULT_VARIABLE btf_ret
        )
    if(btf_ret EQUAL 0)
      set(VmlinuxH_INCLUDE_DIR "${btf_dir}")
      message(STATUS "FindVmlinuxH: generated ${btf_out}")
    else()
      file(REMOVE "${btf_out}")
      if(btf_err)
        message(STATUS "FindVmlinuxH: bpftool failed: ${btf_err}")
      else()
        message(STATUS "FindVmlinuxH: bpftool exited ${btf_ret} (check permissions on ${btf_src})")
      endif()
    endif()
  endif()
endif()

if(VmlinuxH_INCLUDE_DIR)
  set(VmlinuxH_FILE "${VmlinuxH_INCLUDE_DIR}/vmlinux.h")
endif()

set(_msg "vmlinux.h not found. Options:\n"
    "  -DVMLINUX_H_DIR=<dir>     use a pre-built vmlinux.h\n"
    "  ensure bpftool is on PATH and /sys/kernel/btf/vmlinux is readable")
string(CONCAT _msg ${_msg})

find_package_handle_standard_args(VmlinuxH
    REQUIRED_VARS VmlinuxH_INCLUDE_DIR VmlinuxH_FILE
    REASON_FAILURE_MESSAGE "${_msg}"
)

if(VmlinuxH_FOUND AND NOT TARGET VmlinuxH::Headers)
  add_library(VmlinuxH::Headers INTERFACE IMPORTED)
  set_target_properties(VmlinuxH::Headers PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${VmlinuxH_INCLUDE_DIR}"
    )
endif()
