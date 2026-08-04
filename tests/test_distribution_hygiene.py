"""Tests for the public artifact-manifest boundary."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts.verify_distribution import DistributionError, verify_directory

ROOT = "mailjanitor-0.1.0"


def _write_wheel(directory: Path, *names: str) -> None:
    path = directory / "mailjanitor-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(path, mode="w") as archive:
        for name in names:
            archive.writestr(name, b"synthetic")


def _write_sdist(directory: Path, *names: str) -> None:
    path = directory / "mailjanitor-0.1.0.tar.gz"
    with tarfile.open(path, mode="w:gz") as archive:
        for name in names:
            payload = b"synthetic"
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))


def _write_valid_pair(directory: Path) -> None:
    _write_wheel(
        directory,
        "mailjanitor/__init__.py",
        "mailjanitor-0.1.0.dist-info/METADATA",
    )
    _write_sdist(
        directory,
        f"{ROOT}/README.md",
        f"{ROOT}/src/mailjanitor/__init__.py",
    )


def test_minimal_public_distribution_pair_is_accepted(tmp_path: Path) -> None:
    _write_valid_pair(tmp_path)

    verify_directory(tmp_path)


@pytest.mark.parametrize(
    "name",
    [
        f"{ROOT}/.claude/settings.local.json",
        f"{ROOT}/AGENTS.md",
        f"{ROOT}/docs/HANDOFF-private.md",
        f"{ROOT}/docs/personal-notes.md",
        f"{ROOT}/state.sqlite3",
        f"{ROOT}/private/notes.txt",
        f"{ROOT}/../escape.txt",
    ],
)
def test_sdist_rejects_private_or_unexpected_paths(tmp_path: Path, name: str) -> None:
    _write_wheel(
        tmp_path,
        "mailjanitor/__init__.py",
        "mailjanitor-0.1.0.dist-info/METADATA",
    )
    _write_sdist(tmp_path, name)

    with pytest.raises(DistributionError):
        verify_directory(tmp_path)


def test_wheel_rejects_unexpected_root(tmp_path: Path) -> None:
    _write_wheel(tmp_path, "workstation/private.txt")
    _write_sdist(tmp_path, f"{ROOT}/README.md")

    with pytest.raises(DistributionError, match="wheel contains"):
        verify_directory(tmp_path)


def test_requires_exactly_one_artifact_pair(tmp_path: Path) -> None:
    with pytest.raises(DistributionError, match="exactly one"):
        verify_directory(tmp_path)
