#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 cs-26-sw-6-04 <cs-26-sw-6-04@student.aau.dk>
#
# SPDX-License-Identifier: MIT

import argparse
import subprocess
import sys
import glob as globmod
from collections import defaultdict
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        sys.exit("requires Python 3.11+ or: pip install tomli")

try:
    import pathspec
except ModuleNotFoundError:
    sys.exit("requires pathspec: pip install pathspec")


parser = argparse.ArgumentParser(
    description="Annotate all files declared in REUSE.toml"
)
parser.add_argument(
    "--dry-run",
    action="store_true",
    help="Print what would be annotated without touching files.",
)
args = parser.parse_args()

root = Path(__file__).parent.parent
toml_path = root / "REUSE.toml"

# Load .gitignore if present. pathspec uses the same pattern syntax as git.
gitignore_path = root / ".gitignore"
if gitignore_path.exists():
    spec = pathspec.PathSpec.from_lines(
        "gitwildmatch", gitignore_path.read_text().splitlines()
    )
else:
    spec = pathspec.PathSpec.from_lines("gitwildmatch", [])


def is_ignored(path: Path) -> bool:
    return spec.match_file(str(path.relative_to(root)))


with open(toml_path, "rb") as f:
    config = tomllib.load(f)

# Pass 1: iterate blocks in order, last match wins per file.
# This mirrors REUSE.toml's own priority semantics.
file_block: dict[Path, dict] = {}

for block in config.get("annotations", []):
    pattern = block.get("path", "")
    if not pattern:
        continue
    for p in globmod.glob(pattern, root_dir=root, recursive=True):
        resolved = (root / p).resolve()
        if resolved.is_file() and not is_ignored(resolved):
            file_block[resolved] = block


if not file_block:
    sys.exit("no files matched any annotation block")

# Pass 2: group files by their winning (copyright, license) pair so we make
# one reuse annotate call per unique combination, not one per file.
groups: dict[tuple[str, str], list[Path]] = defaultdict(list)

for path, block in file_block.items():
    copyright_ = block.get("SPDX-FileCopyrightText", "")
    license_ = block.get("SPDX-License-Identifier", "")
    if copyright_ and license_:
        groups[(copyright_, license_)].append(path)

for (copyright_, license_), files in groups.items():
    cmd = [
        "reuse",
        "annotate",
        "--copyright",
        copyright_,
        "--license",
        license_,
        "--merge-copyrights",
        "--fallback-dot-license",
    ] + [str(p) for p in sorted(files)]

    print(f"  {license_:<24} {copyright_}  ({len(files)} file(s))")

    if args.dry_run:
        for f in sorted(files):
            print(f"    {f.relative_to(root)}")
        print()
        continue

    result = subprocess.run(cmd, cwd=root)
    if result.returncode != 0:
        sys.exit(result.returncode)

print("\ndone — run `reuse lint` to verify")
