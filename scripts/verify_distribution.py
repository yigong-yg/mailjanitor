"""Fail closed when a built distribution contains unexpected local material."""

from __future__ import annotations

import argparse
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

ALLOWED_SDIST_FILES = frozenset(
    {
        (".editorconfig",),
        (".gitattributes",),
        (".github", "dependabot.yml"),
        (".github", "workflows", "ci.yml"),
        (".gitignore",),
        ("LICENSE",),
        ("PKG-INFO",),
        ("README.md",),
        ("SECURITY.md",),
        ("docs", "implementation-status.md"),
        ("docs", "operator-guide.md"),
        ("pyproject.toml",),
        ("scripts", "__init__.py"),
        ("scripts", "verify_distribution.py"),
        ("uv.lock",),
    }
)
ALLOWED_DOCUMENTATION_DIRECTORIES = frozenset(
    {"actions", "adr", "architecture", "security"}
)
FORBIDDEN_COMPONENTS = frozenset(
    {
        ".claude",
        ".codex",
        ".env",
        ".git",
        ".pypirc",
        "AGENTS.md",
    }
)
FORBIDDEN_SUFFIXES = (
    ".db",
    ".jsonl",
    ".sqlite",
    ".sqlite3",
    ".sqlite3-shm",
    ".sqlite3-wal",
)
MINIMUM_WHEEL_FILENAME_PARTS = 5


class DistributionError(RuntimeError):
    """Raised when an artifact violates the public manifest policy."""


def _safe_parts(raw_name: str) -> tuple[str, ...]:
    normalized = raw_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts:
        raise DistributionError("archive contains an unsafe path")
    parts = tuple(part for part in path.parts if part not in {"", "."})
    if not parts:
        raise DistributionError("archive contains an empty path")
    if any(part in FORBIDDEN_COMPONENTS for part in parts):
        raise DistributionError("archive contains a forbidden path component")
    if any(part.startswith("HANDOFF-") for part in parts):
        raise DistributionError("archive contains a workstation handoff")
    if parts[-1].casefold().endswith(FORBIDDEN_SUFFIXES):
        raise DistributionError("archive contains operational state")
    return parts


def _sdist_file_is_allowed(relative: tuple[str, ...]) -> bool:
    if relative in ALLOWED_SDIST_FILES:
        return True
    match relative:
        case ("src", *tail):
            return bool(tail) and (tail[-1] == "py.typed" or tail[-1].endswith(".py"))
        case ("tests", *tail):
            return bool(tail) and tail[-1].endswith(".py")
        case ("docs", directory, *tail):
            return (
                directory in ALLOWED_DOCUMENTATION_DIRECTORIES
                and bool(tail)
                and tail[-1].endswith(".md")
            )
        case _:
            return False


def _verify_sdist(path: Path) -> None:
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if not members:
            raise DistributionError("source distribution is empty")
        names = [member.name for member in members]
        if len(names) != len(set(names)):
            raise DistributionError("source distribution contains duplicate paths")
        parsed = [_safe_parts(member.name) for member in members]
        roots = {parts[0] for parts in parsed}
        expected_root = path.name.removesuffix(".tar.gz")
        if roots != {expected_root}:
            raise DistributionError("source distribution has an unexpected root")
        if any(not member.isfile() for member in members):
            raise DistributionError("source distribution contains a special entry")
        for parts in parsed:
            relative = parts[1:]
            if not relative or not _sdist_file_is_allowed(relative):
                raise DistributionError("source distribution exceeds its allowlist")


def _verify_wheel(path: Path) -> None:
    filename_parts = path.name.removesuffix(".whl").split("-")
    if len(filename_parts) < MINIMUM_WHEEL_FILENAME_PARTS:
        raise DistributionError("wheel filename is invalid")
    expected_dist_info = f"{filename_parts[0]}-{filename_parts[1]}.dist-info"
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if not members:
            raise DistributionError("wheel is empty")
        names = [member.filename for member in members]
        if len(names) != len(set(names)):
            raise DistributionError("wheel contains duplicate paths")
        for member in members:
            parts = _safe_parts(member.filename)
            if parts[0] not in {"mailjanitor", expected_dist_info}:
                raise DistributionError("wheel contains an unexpected root")
            if member.flag_bits & 0x1:
                raise DistributionError("wheel contains an encrypted member")
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise DistributionError("wheel contains a symbolic link")


def verify_directory(directory: Path) -> None:
    """Verify exactly one wheel and one source distribution in ``directory``."""
    if not directory.is_dir():
        raise DistributionError("artifact directory does not exist")
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise DistributionError(
            "expected exactly one wheel and one source distribution"
        )
    _verify_wheel(wheels[0])
    _verify_sdist(sdists[0])


def main() -> int:
    """Parse the artifact directory and verify its public manifest."""
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        verify_directory(args.directory)
    except (DistributionError, OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
