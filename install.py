#!/usr/bin/env python3
"""Verify and atomically install a local Counterbranch release archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import tarfile
import tempfile

TARGET = "aarch64-apple-darwin"
LINUX_TARGET = "x86_64-unknown-linux-gnu"
SUPPORTED_HOSTS = {
    ("Darwin", "arm64"): TARGET,
    ("Linux", "x86_64"): LINUX_TARGET,
    ("Linux", "amd64"): LINUX_TARGET,
}
MAX_ARCHIVE_SIZE = 256 * 1024 * 1024
MAX_MEMBERS = 512
MAX_EXPANDED_SIZE = 512 * 1024 * 1024
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?\Z")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def host_target() -> str:
    try:
        return SUPPORTED_HOSTS[(platform.system(), platform.machine())]
    except KeyError:
        raise ValueError(
            f"unsupported installer host: {platform.system()} {platform.machine()}"
        ) from None


def validate_relative(name: str) -> None:
    path = PurePosixPath(name)
    if (not name or str(path) != name or path.is_absolute() or "\\" in name
            or any(part in ("", ".", "..") for part in path.parts)):
        raise ValueError(f"unsafe archive member: {name!r}")


def read_archive_bytes(archive_path: Path) -> bytes:
    try:
        before = archive_path.lstat()
    except OSError as error:
        raise ValueError("archive is missing or exceeds the size limit") from error
    if (not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARCHIVE_SIZE):
        raise ValueError("archive is missing or exceeds the size limit")
    with archive_path.open("rb") as source:
        opened = os.fstat(source.fileno())
        if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino or opened.st_size != before.st_size):
            raise ValueError("archive identity changed before it could be read")
        chunks = []
        total = 0
        while chunk := source.read(min(1024 * 1024, MAX_ARCHIVE_SIZE + 1 - total)):
            total += len(chunk)
            if total > MAX_ARCHIVE_SIZE:
                raise ValueError("archive is missing or exceeds the size limit")
            chunks.append(chunk)
        after = os.fstat(source.fileno())
        if (total != opened.st_size or after.st_size != opened.st_size
                or after.st_dev != opened.st_dev or after.st_ino != opened.st_ino
                or after.st_mtime_ns != opened.st_mtime_ns):
            raise ValueError("archive identity changed while it was read")
        archive_bytes = b"".join(chunks)
    return archive_bytes


def validate_archive_bytes(archive_bytes: bytes, expected_sha256: str, version: str,
                           target: str) -> tuple[dict, dict[str, bytes]]:
    if len(expected_sha256) != 64 or any(c not in "0123456789abcdef" for c in expected_sha256):
        raise ValueError("archive SHA-256 must be 64 lowercase hexadecimal characters")
    if sha256(archive_bytes) != expected_sha256:
        raise ValueError("archive SHA-256 mismatch")
    if not VERSION_RE.fullmatch(version):
        raise ValueError("expected version is not a supported semantic version")
    with tarfile.open(fileobj=__import__("io").BytesIO(archive_bytes), mode="r|gz") as archive:
        names: set[str] = set()
        extracted: dict[str, bytes] = {}
        root: str | None = None
        total_size = 0
        for count, member in enumerate(archive, 1):
            if count > MAX_MEMBERS:
                raise ValueError("archive has too many members")
            validate_relative(member.name)
            if member.name in names or not member.isfile() or member.size > MAX_ARCHIVE_SIZE:
                raise ValueError(f"invalid archive member: {member.name!r}")
            total_size += member.size
            if total_size > MAX_EXPANDED_SIZE:
                raise ValueError("archive expands beyond the size limit")
            names.add(member.name)
            parts = PurePosixPath(member.name).parts
            if len(parts) < 2:
                raise ValueError("every member must be under one release directory")
            root = root or parts[0]
            if parts[0] != root:
                raise ValueError("archive contains multiple release directories")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"cannot read archive member: {member.name!r}")
            data = stream.read(member.size + 1)
            if len(data) != member.size:
                raise ValueError(f"archive member size mismatch: {member.name!r}")
            extracted["/".join(parts[1:])] = data
    if "MANIFEST.json" not in extracted:
        raise ValueError("archive manifest is missing")
    manifest_bytes = extracted.pop("MANIFEST.json")
    try:
        manifest = json.loads(manifest_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("archive manifest is invalid") from error
    if not isinstance(manifest, dict):
        raise ValueError("archive manifest must be an object")
    if manifest.get("format") != 1 or manifest.get("name") != "counterbranch":
        raise ValueError("unsupported archive manifest")
    if manifest.get("version") != version or manifest.get("target") != target:
        raise ValueError("archive version or target mismatch")
    if root != f"counterbranch-{version}-{target}":
        raise ValueError("archive release directory does not match version and target")
    declared = manifest.get("files")
    if not isinstance(declared, dict) or set(declared) != set(extracted):
        raise ValueError("archive members do not exactly match the manifest")
    if "bin/counterbranch" not in declared or "LICENSE" not in declared:
        raise ValueError("archive lacks required Counterbranch files")
    for name, data in extracted.items():
        validate_relative(name)
        record = declared[name]
        if not isinstance(record, dict) or record.get("sha256") != sha256(data) or record.get("size") != len(data):
            raise ValueError(f"file checksum or size mismatch: {name}")
        expected_mode = "0755" if name == "bin/counterbranch" else "0644"
        if record.get("mode") != expected_mode:
            raise ValueError(f"invalid installed mode: {name}")
    extracted["MANIFEST.json"] = manifest_bytes
    return manifest, extracted


def validate_archive(archive_path: Path, expected_sha256: str, version: str,
                     target: str) -> tuple[dict, dict[str, bytes]]:
    return validate_archive_bytes(read_archive_bytes(archive_path), expected_sha256, version, target)


def read_verified(archive_path: Path, expected_sha256: str, version: str,
                  target: str | None = None) -> tuple[dict, dict[str, bytes]]:
    target = target or host_target()
    if target != host_target():
        raise ValueError(f"installer platform does not match {target}")
    return validate_archive(archive_path, expected_sha256, version, target)


def install(archive: Path, expected_sha256: str, version: str, prefix: Path,
            target: str | None = None) -> Path:
    target = target or host_target()
    if not VERSION_RE.fullmatch(version):
        raise ValueError("expected version is not a supported semantic version")
    _, files = read_verified(archive, expected_sha256, version, target)
    destination = prefix / "lib" / "counterbranch" / f"{version}-{target}"
    if destination.exists():
        raise FileExistsError(f"release already installed: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    bin_dir = prefix / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    executable = bin_dir / "counterbranch"
    temporary_name: str | None = None
    published = False
    # Removed with shutil.rmtree: Ubuntu 3.12 TemporaryDirectory.cleanup() binds rmtree at import.
    staging = Path(tempfile.mkdtemp(prefix=".counterbranch-install-", dir=destination.parent))
    try:
        stage = staging / destination.name
        for name, data in files.items():
            output = stage / Path(*PurePosixPath(name).parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
            output.chmod(0o755 if name == "bin/counterbranch" else 0o644)
        fd, temporary_name = tempfile.mkstemp(prefix=".counterbranch-", dir=bin_dir)
        primary_error: BaseException | None = None
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(files["bin/counterbranch"])
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary_name, 0o755)
            os.replace(stage, destination)
            published = True
            os.replace(temporary_name, executable)
            temporary_name = None
        except BaseException as error:
            primary_error = error
            if published:
                try:
                    shutil.rmtree(destination)
                except OSError as cleanup_error:
                    error.add_note(f"release rollback failed; inspect {destination}: {cleanup_error}")
            raise
        finally:
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass
                except OSError as cleanup_error:
                    if primary_error is not None:
                        primary_error.add_note(
                            f"temporary executable cleanup failed; inspect {temporary_name}: {cleanup_error}"
                        )
                    else:
                        raise
    except BaseException as error:
        try:
            shutil.rmtree(staging)
        except OSError as cleanup_error:
            error.add_note(f"staging cleanup failed; inspect {staging}: {cleanup_error}")
        raise
    else:
        try:
            shutil.rmtree(staging)
        except OSError as error:
            raise RuntimeError(
                f"installation completed at {executable}, but staging cleanup failed; inspect {staging}"
            ) from error
    return executable


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--sha256", required=True, help="independently obtained archive SHA-256")
    parser.add_argument("--version", required=True)
    parser.add_argument("--prefix", type=Path, default=Path.home() / ".local")
    args = parser.parse_args()
    print(install(args.archive.resolve(), args.sha256, args.version, args.prefix.resolve(),
                  host_target()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
