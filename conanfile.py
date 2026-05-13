# SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
#
# SPDX-License-Identifier: MIT

from conan import ConanFile
from conan.tools.cmake import CMakeDeps, CMakeToolchain


class AntiCheatConan(ConanFile):
    settings = "os", "arch", "compiler", "build_type"

    # `ac` is linked fully static (see src/cli/CMakeLists.txt), so libbpf and
    # its transitive deps must produce static archives.
    default_options = {
        "libbpf/*:shared": False,
        "elfutils/*:shared": False,
        "zlib/*:shared": False,
    }

    def layout(self):
        build_type = str(self.settings.build_type).lower()
        self.folders.build = f"build/{build_type}-conan"
        self.folders.generators = f"{self.folders.build}/conan"

    def requirements(self):
        self.requires("libbpf/1.3.0")

    def build_requirements(self):
        self.test_requires("catch2/3.11.0")

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()

        toolchain = CMakeToolchain(self)
        toolchain.presets_prefix = "conan"
        toolchain.user_presets_path = "CMakeUserPresets.json"
        toolchain.generate()
