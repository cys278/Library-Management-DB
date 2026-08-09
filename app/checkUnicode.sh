#!/usr/bin/env bash

set -u

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
TARGET_DIR="${1:-$SCRIPT_DIR}"

if [[ ! -d "$TARGET_DIR" ]]; then
    echo "Directory does not exist: $TARGET_DIR"
    exit 2
fi

python3 - "$TARGET_DIR" <<'PYTHON'
import sys
import unicodedata
from pathlib import Path


target_directory = Path(sys.argv[1]).resolve()

excluded_directories = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    "coverage",
}

excluded_extensions = {
    ".db",
    ".sqlite",
    ".sqlite3",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".pdf",
    ".zip",
    ".pyc",
}

replacements = {
    0x00A0: "regular space",
    0x00AD: "remove",
    0x00B7: "&middot; or regular text separator",
    0x00D7: "* or x",
    0x00F7: "/",
    0x034F: "remove",
    0x061C: "remove",
    0x180E: "remove",
    0x2000: "regular space",
    0x2001: "regular space",
    0x2002: "regular space",
    0x2003: "regular space",
    0x2004: "regular space",
    0x2005: "regular space",
    0x2006: "regular space",
    0x2007: "regular space",
    0x2008: "regular space",
    0x2009: "regular space",
    0x200A: "regular space",
    0x200B: "remove",
    0x200C: "remove",
    0x200D: "remove",
    0x200E: "remove",
    0x200F: "remove",
    0x2010: "-",
    0x2011: "-",
    0x2012: "-",
    0x2013: "- or &ndash;",
    0x2014: "-- or &mdash;",
    0x2015: "--",
    0x2018: "'",
    0x2019: "'",
    0x201A: "'",
    0x201B: "'",
    0x201C: '"',
    0x201D: '"',
    0x201E: '"',
    0x201F: '"',
    0x2020: "remove",
    0x2021: "remove",
    0x2022: "* or -",
    0x2023: "-",
    0x2026: "...",
    0x202F: "regular space",
    0x2032: "'",
    0x2033: '"',
    0x2039: "<",
    0x203A: ">",
    0x2044: "/",
    0x205F: "regular space",
    0x2060: "remove",
    0x2061: "remove",
    0x2062: "remove",
    0x2063: "remove",
    0x2064: "remove",
    0x2066: "remove",
    0x2067: "remove",
    0x2068: "remove",
    0x2069: "remove",
    0x2212: "-",
    0x2215: "/",
    0x2216: "\\",
    0x2219: "*",
    0x22C5: "*",
    0x22EF: "...",
    0x25BA: ">",
    0x25B6: ">",
    0x25C6: "*",
    0x25E6: "-",
    0x3000: "regular space",
    0xFEFF: "remove",
}


def should_skip(path):
    if path.is_symlink():
        return True

    if any(part in excluded_directories for part in path.parts):
        return True

    if path.suffix.lower() in excluded_extensions:
        return True

    return False


def visible_character(character):
    category = unicodedata.category(character)

    if category in {"Cf", "Cc", "Zl", "Zp"} or character.isspace():
        return "<invisible>"

    return repr(character)


def location_in_text(text, index):
    line = text.count("\n", 0, index) + 1

    last_newline = text.rfind("\n", 0, index)

    if last_newline == -1:
        column = index + 1
    else:
        column = index - last_newline

    return line, column


findings = []
invalid_files = []
files_checked = 0
files_by_extension = {}

for path in sorted(target_directory.rglob("*")):
    if not path.is_file() or should_skip(path):
        continue

    try:
        raw_data = path.read_bytes()
    except OSError as error:
        print(f"Could not read {path}: {error}", file=sys.stderr)
        continue

    if b"\x00" in raw_data[:8192]:
        continue

    try:
        text = raw_data.decode("utf-8")
    except UnicodeDecodeError as error:
        invalid_files.append((path, error))
        continue

    files_checked += 1
    extension = path.suffix.lower() or "[no extension]"
    files_by_extension[extension] = (
    files_by_extension.get(extension, 0) + 1
    )

    for index, character in enumerate(text):
        code_point = ord(character)

        if code_point <= 127:
            continue

        line, column = location_in_text(text, index)

        findings.append(
            {
                "path": path,
                "line": line,
                "column": column,
                "character": character,
                "code_point": code_point,
                "name": unicodedata.name(
                    character,
                    "UNKNOWN UNICODE CHARACTER",
                ),
                "replacement": replacements.get(
                    code_point,
                    "review manually",
                ),
            }
        )


for path, error in invalid_files:
    try:
        display_path = path.relative_to(target_directory)
    except ValueError:
        display_path = path

    print(
        f"{display_path}: invalid UTF-8 data: {error}",
        file=sys.stderr,
    )


for finding in findings:
    try:
        display_path = finding["path"].relative_to(target_directory)
    except ValueError:
        display_path = finding["path"]

    code = f"U+{finding['code_point']:04X}"

    print(
        f"{display_path}:"
        f"{finding['line']}:"
        f"{finding['column']} "
        f"{code} "
        f"{finding['name']} "
        f"{visible_character(finding['character'])} "
        f"-> use {finding['replacement']}",
        file=sys.stderr,
    )


total_issues = len(findings) + len(invalid_files)

print()

if total_issues:
    print(
        f"Unicode check failed: {total_issues} issue(s) found "
        f"in {files_checked} text file(s).",
        file=sys.stderr,
    )

    print(
        "These findings do not prove AI authorship.",
        file=sys.stderr,
    )

    sys.exit(1)

print("Files checked by type:")

for extension, count in sorted(files_by_extension.items()):
    print(f"  {extension}: {count}")


print(
    f"Unicode check passed: "
    f"{files_checked} text file(s) contained only ASCII."
)

PYTHON