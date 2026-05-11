"""Subprocess helpers — timeouts, sudo detection, missing-binary handling."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass


class MissingBinaryError(RuntimeError):
    """A required external CLI is not installed."""


class NeedsRootError(RuntimeError):
    """Command requires root privileges and the current EUID is not 0."""


@dataclass(frozen=True)
class RunResult:
    rc: int
    stdout: str
    stderr: str


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def run(
    cmd: list[str],
    *,
    timeout: float = 30.0,
    needs_root: bool = False,
) -> RunResult:
    """Run a command and return its result.

    Raises MissingBinaryError if cmd[0] is not on PATH, or NeedsRootError if
    `needs_root` is True and the process is not running as root.
    """
    if not have(cmd[0]):
        raise MissingBinaryError(cmd[0])
    if needs_root and not is_root():
        raise NeedsRootError(cmd[0])
    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return RunResult(rc=completed.returncode, stdout=completed.stdout, stderr=completed.stderr)
