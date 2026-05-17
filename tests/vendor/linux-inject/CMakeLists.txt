# SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  return()
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|i686|i386)$")
  # The adapter file #includes upstream .c sources directly; do not list
  # them here or they will be compiled twice.
  add_library(linux_inject_vendor STATIC linux_inject_lib.c)
  target_compile_options(linux_inject_vendor PRIVATE -w -std=gnu11)
  target_include_directories(linux_inject_vendor PUBLIC
      "${CMAKE_CURRENT_SOURCE_DIR}"
  )
  target_link_libraries(linux_inject_vendor PUBLIC dl)
  set_property(TARGET linux_inject_vendor PROPERTY POSITION_INDEPENDENT_CODE ON)
endif()
