# SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
#
# SPDX-License-Identifier: MIT

from conan import ConanFile
from conan.tools.cmake import CMakeDeps, CMakeToolchain


class AntiCheatConan(ConanFile):
    settings = "os", "arch", "compiler", "build_type"

    def layout(self):
        build_type = str(self.settings.build_type).lower()
        self.folders.build = f"build/{build_type}-conan"
        self.folders.generators = f"{self.folders.build}/conan"

    def build_requirements(self):
        self.test_requires("catch2/3.11.0")

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()

        toolchain = CMakeToolchain(self)
        toolchain.presets_prefix = "conan"
        toolchain.user_presets_path = "CMakeUserPresets.json"
        toolchain.generate()
