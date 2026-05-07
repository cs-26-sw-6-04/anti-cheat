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

file(GLOB AC_SUPPORT_SOURCES CONFIGURE_DEPENDS "support/*.cpp")
file(GLOB AC_TEST_SOURCES    CONFIGURE_DEPENDS "*.cpp")

add_executable(ac_tests
    ${AC_SUPPORT_SOURCES}
    ${AC_TEST_SOURCES}
)

target_compile_features(ac_tests PRIVATE cxx_std_17)

target_include_directories(ac_tests
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/support"
        "${PROJECT_SOURCE_DIR}/src/shared"
)

target_link_libraries(ac_tests
    PRIVATE
        Catch2::Catch2WithMain
        ac_loader_runtime
)

catch_discover_tests(ac_tests
    DISCOVERY_MODE PRE_TEST
    PROPERTIES
        RUN_SERIAL TRUE
        TIMEOUT 20
        SKIP_REGULAR_EXPRESSION "skipping live BPF test:"
)
