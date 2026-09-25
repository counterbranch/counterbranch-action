"""Bounded I/O shared by trusted publication helpers (POSIX hosts only)."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import time

MAX_FILE = 256 * 1024 * 1024
# `candidate` kits may be released; earlier rehearsal kits remain readable.
KIT_STATUSES = ("candidate", "unsigned_local_rehearsal")


def read(path: Path, limit: int = MAX_FILE) -> bytes:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError("input must be a bounded regular file")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("input identity changed")
        data = stream.read(limit + 1)
    if len(data) > limit or len(data) != before.st_size:
        raise ValueError("input changed or exceeded limit")
    return data


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encoded(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def write(path: Path, data: bytes, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o755 if executable else 0o644)


def environment() -> dict[str, str]:
    allowed = ("PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "TMPDIR", "LANG", "LC_ALL")
    env = {key: os.environ[key] for key in allowed if key in os.environ}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT="0", GIT_CONFIG_COUNT="0")
    return env


def run(args: list[str], root: Path, env: dict[str, str] | None = None,
        timeout: int = 900, limit: int = 8 * 1024 * 1024, combined: bool = False) -> str:
    """Never return raw subprocess diagnostics in a release record."""
    process = subprocess.Popen(args, cwd=root, env=environment() if env is None else env,
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    captured = bytearray()
    total = 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            selector.register(process.stderr, selectors.EVENT_READ)
            while selector.get_map():
                if time.monotonic() > deadline:
                    raise ValueError("process exceeded timeout")
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > limit:
                        raise ValueError("process exceeded output limit")
                    if combined or key.fileobj is process.stdout:
                        captured.extend(chunk)
            status = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            if status:
                raise ValueError(f"process failed with exit status {status}")
        return captured.decode("utf-8").strip()
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            if process.poll() is None:
                process.kill()
        process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def inventory(root: Path) -> dict:
    files = {}
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("stage contains a symbolic link")
        if path.is_dir():
            continue
        data = read(path)
        total += len(data)
        if total > 512 * 1024 * 1024 or len(files) >= 4096:
            raise ValueError("inventory exceeds file or byte limit")
        files[path.relative_to(root).as_posix()] = {
            "sha256": digest(data), "size": len(data),
            "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}",
        }
    return files
