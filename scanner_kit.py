#!/usr/bin/env python3
"""Validate and extract one strict Counterbranch scanner-only kit.

Public callers must derive every expected value from a reviewed, approved release
manifest. ``--local-unsigned`` is a separate operator-controlled inspection path;
it authenticates no publisher and never executes either bundled binary.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile


KIT_SCHEMA = "counterbranch-scanner-kit/1"
KIT_STATUS = "unsigned-local-candidate"
EDITION = "scanner-only"
CORE_BUILD_SCHEMA = "counterbranch-build/1"
CORE_REPOSITORY = "https://github.com/counterbranch/counterbranch"
DISCOVERY_ARTIFACT_SCHEMA = "counterbranch-discovery-artifact/2"
DISCOVERY_BUILD_SCHEMA = "counterbranch-discovery-build/2"
DISCOVERY_REPOSITORY = "https://github.com/counterbranch/discovery"
DISCOVERY_VERSION = "0.24.0"
DISCOVERY_COMMIT = "d0d5dfe44b58ebcc1db21585e18be6edccb2d6ac"
DISCOVERY_TREE = "78338e69c84dd3d8265682cd4b3bbdfbf69a9cc4"
SCANNER_RELEASE_REPOSITORY = "counterbranch/alpha-releases"
TARGETS = frozenset({"aarch64-apple-darwin", "x86_64-unknown-linux-gnu"})
PUBLIC_RELEASE_TARGETS = frozenset({"x86_64-unknown-linux-gnu"})

MAX_ARCHIVE_SIZE = 512 * 1024 * 1024
MAX_EXPANDED_SIZE = 512 * 1024 * 1024
MAX_MEMBER_SIZE = 256 * 1024 * 1024
MAX_MEMBERS = 1024
MAX_KIT_SIZE = 1024 * 1024
MAX_RELEASE_MANIFEST_SIZE = 64 * 1024
MAX_BUNDLE_SIZE = 16 * 1024 * 1024
MAX_MEMBER_NAME_BYTES = 255
# A regular tar member uses one 512-byte header and at most 511 bytes of
# padding. tarfile also pads the complete archive to a record boundary.
MAX_TAR_STREAM_SIZE = MAX_EXPANDED_SIZE + MAX_MEMBERS * 1024 + tarfile.RECORDSIZE
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
OID_RE = re.compile(r"[0-9a-f]{40}\Z")
VERSION_RE = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?"
    r"(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?\Z"
)
SAFE_NOTICE_COMPONENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}\Z")
NOTICE_FILE_RE = re.compile(r"(?:license|copying|notice|copyright)[A-Za-z0-9_.+-]*\Z", re.I)

KIT_FIELDS = frozenset({
    "schema_version", "status", "edition", "target", "counterbranch",
    "discovery", "files", "inventory_sha256",
})
CORE_FIELDS = frozenset({"build", "source", "artifact"})
CORE_BUILD_FIELDS = frozenset({"schema_version", "product", "binary", "version", "edition"})
SOURCE_FIELDS = frozenset({"repository", "commit", "tree", "dirty"})
CORE_ARTIFACT_FIELDS = frozenset({"binary", "path", "target", "size_bytes", "sha256"})
DISCOVERY_FIELDS = frozenset({"schema_version", "edition", "build", "artifact"})
DISCOVERY_BUILD_FIELDS = frozenset({
    "schema_version", "product", "binary", "version", "edition", "source",
})
DISCOVERY_ARTIFACT_FIELDS = frozenset({"binary", "target", "size_bytes", "sha256"})
FILE_FIELDS = frozenset({"sha256", "size", "mode"})
RELEASE_FIELDS = frozenset({
    "format", "edition", "status", "repository", "tag", "version", "kits",
    "core_source", "discovery_source",
})
RELEASE_SOURCE_FIELDS = SOURCE_FIELDS
RELEASE_KIT_FIELDS = frozenset({"edition", "name", "sha256", "size", "bundle"})
RELEASE_BUNDLE_FIELDS = frozenset({"name", "sha256", "size"})

DISCOVERY_MANIFEST_PATH = "share/counterbranch/discovery-artifact.json"
REQUIRED_PAYLOADS = frozenset({
    "bin/counterbranch",
    "bin/discovery",
    DISCOVERY_MANIFEST_PATH,
    "share/counterbranch/scanner_qualify.py",
    "share/counterbranch/examples/base/Orders.cs",
    "share/counterbranch/examples/base/orders.ts",
    "share/counterbranch/examples/candidate/Orders.cs",
    "share/counterbranch/examples/candidate/orders.ts",
    "share/counterbranch/licenses/counterbranch/LICENSE",
    "share/counterbranch/licenses/counterbranch/DEPENDENCIES.json",
    "share/counterbranch/licenses/discovery/LICENSE",
    "share/counterbranch/licenses/discovery/NOTICE",
    "share/counterbranch/licenses/discovery/DEPENDENCIES.json",
})
EXECUTABLES = frozenset({"bin/counterbranch", "bin/discovery"})


class DuplicateKeyError(ValueError):
    """Raised when strict JSON contains the same member name twice."""


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def strict_json(data: bytes, label: str) -> object:
    """Decode one UTF-8 JSON value while rejecting duplicate keys and NaN values."""
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_object,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (UnicodeError, json.JSONDecodeError, DuplicateKeyError, ValueError) as error:
        raise ValueError(f"{label} is not valid strict JSON") from error


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _bounded_regular_file(path: Path, limit: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise ValueError(f"{label} is missing or invalid") from error
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError(f"{label} is missing or invalid")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if ((before.st_dev, before.st_ino, before.st_size)
                != (opened.st_dev, opened.st_ino, opened.st_size)):
            raise ValueError(f"{label} identity changed")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if (len(data) != opened.st_size or len(data) > limit
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise ValueError(f"{label} changed or exceeded its size limit")
    return data


def load_archive_bytes(path: Path, expected_sha256: str, expected_size: int | None = None) -> bytes:
    """Read a bounded regular archive and bind it to its trusted digest and optional size."""
    if not isinstance(expected_sha256, str) or not SHA256_RE.fullmatch(expected_sha256):
        raise ValueError("kit SHA-256 must be 64 lowercase hexadecimal characters")
    if expected_size is not None and (
        not isinstance(expected_size, int) or isinstance(expected_size, bool)
        or not 0 < expected_size <= MAX_ARCHIVE_SIZE
    ):
        raise ValueError("expected kit size is invalid")
    data = _bounded_regular_file(path, MAX_ARCHIVE_SIZE, "kit archive")
    if expected_size is not None and len(data) != expected_size:
        raise ValueError("kit archive size differs from the trusted release manifest")
    if sha256(data) != expected_sha256:
        raise ValueError("kit archive digest differs from the trusted expectation")
    return data


def _exact_object(value: object, fields: frozenset[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} fields do not match the scanner-only schema")
    return value


def _oid(value: object, label: str) -> str:
    if not isinstance(value, str) or not OID_RE.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase 40-character Git object id")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _positive_int(value: object, maximum: int, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= maximum:
        raise ValueError(f"{label} is invalid")
    return value


def _source(value: object, repository: str, commit: str, tree: str, label: str) -> dict:
    source = _exact_object(value, SOURCE_FIELDS, label)
    if (source.get("repository") != repository or source.get("dirty") is not False
            or source.get("commit") != commit or source.get("tree") != tree):
        raise ValueError(f"{label} does not match the exact clean source identity")
    return source


def _safe_path(name: str) -> None:
    path = PurePosixPath(name)
    try:
        name_size = len(name.encode("utf-8"))
    except UnicodeError as error:
        raise ValueError("kit contains an unsafe member path") from error
    if (not name or name_size > MAX_MEMBER_NAME_BYTES or "\x00" in name or "\\" in name
            or path.is_absolute()
            or str(path) != name or any(part in ("", ".", "..") for part in path.parts)):
        raise ValueError("kit contains an unsafe member path")


def _allowed_payload(name: str) -> bool:
    if name in REQUIRED_PAYLOADS:
        return True
    parts = PurePosixPath(name).parts
    prefix = ("share", "counterbranch", "licenses")
    if len(parts) < 5 or parts[:3] != prefix or parts[3] not in ("counterbranch", "discovery"):
        return False
    relative = parts[4:]
    if len(relative) == 1:
        return relative[0] in {"LICENSE", "NOTICE", "DEPENDENCIES.json", "NOTICE-SOURCES.json"}
    return (len(relative) == 3 and relative[0] == "third-party"
            and SAFE_NOTICE_COMPONENT_RE.fullmatch(relative[1]) is not None
            and NOTICE_FILE_RE.fullmatch(relative[2]) is not None)


def _read_archive(data: bytes) -> tuple[dict[str, tuple[bytes, int]], bytes]:
    files: dict[str, tuple[bytes, int]] = {}
    total = 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as compressed:
            tar_bytes = compressed.read(MAX_TAR_STREAM_SIZE + 1)
        if len(tar_bytes) > MAX_TAR_STREAM_SIZE:
            raise ValueError("kit uncompressed tar stream exceeds its size limit")
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
            for count, member in enumerate(archive, 1):
                if count > MAX_MEMBERS:
                    raise ValueError("kit contains too many members")
                name = member.name
                _safe_path(name)
                if (name in files or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                        or member.sparse is not None or member.pax_headers):
                    raise ValueError("kit contains a duplicate or non-regular member")
                if (member.mode not in (0o644, 0o755) or member.uid != 0 or member.gid != 0
                        or member.uname not in ("", None) or member.gname not in ("", None)
                        or member.mtime != 0):
                    raise ValueError("kit member metadata is not normalized")
                member_limit = MAX_KIT_SIZE if name == "KIT.json" else MAX_MEMBER_SIZE
                if member.size < 0 or member.size > member_limit:
                    raise ValueError("kit member exceeds its size limit")
                total += member.size
                if total > MAX_EXPANDED_SIZE:
                    raise ValueError("kit expands beyond its size limit")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("kit member cannot be read")
                content = stream.read(member.size + 1)
                if len(content) != member.size:
                    raise ValueError("kit member size differs")
                files[name] = (content, member.mode)
    except (tarfile.TarError, OSError, EOFError) as error:
        raise ValueError("kit archive is not a valid gzip tar archive") from error
    record, mode = files.pop("KIT.json", (b"", 0))
    if not record or mode != 0o644 or len(record) > MAX_KIT_SIZE:
        raise ValueError("kit completion record is missing or invalid")
    return files, record


def validate_archive_bytes(
    archive_bytes: bytes,
    expected_sha256: str,
    expected_target: str,
    expected_core_version: str,
    expected_core_source_commit: str,
    expected_core_source_tree: str,
    expected_size: int | None = None,
) -> tuple[dict, dict[str, bytes]]:
    """Validate bytes against trusted identity without executing bundled content."""
    if len(archive_bytes) > MAX_ARCHIVE_SIZE:
        raise ValueError("kit archive exceeds its size limit")
    _digest(expected_sha256, "expected kit digest")
    if sha256(archive_bytes) != expected_sha256:
        raise ValueError("kit archive digest differs from the trusted expectation")
    if expected_size is not None and len(archive_bytes) != _positive_int(
        expected_size, MAX_ARCHIVE_SIZE, "expected kit size"
    ):
        raise ValueError("kit archive size differs from the trusted release manifest")
    if expected_target not in TARGETS:
        raise ValueError("kit target is unsupported")
    if not isinstance(expected_core_version, str) or not VERSION_RE.fullmatch(expected_core_version):
        raise ValueError("expected Counterbranch version is invalid")
    _oid(expected_core_source_commit, "expected Counterbranch source commit")
    _oid(expected_core_source_tree, "expected Counterbranch source tree")

    members, record_bytes = _read_archive(archive_bytes)
    record = _exact_object(strict_json(record_bytes, "kit completion record"), KIT_FIELDS,
                           "kit completion record")
    if record_bytes != canonical(record):
        raise ValueError("kit completion record is not canonical JSON")
    if (record.get("schema_version") != KIT_SCHEMA or record.get("status") != KIT_STATUS
            or record.get("edition") != EDITION or record.get("target") != expected_target):
        raise ValueError("kit completion record identity differs")

    core = _exact_object(record["counterbranch"], CORE_FIELDS, "Counterbranch record")
    core_build = _exact_object(core["build"], CORE_BUILD_FIELDS, "Counterbranch build")
    expected_build = {
        "schema_version": CORE_BUILD_SCHEMA,
        "product": "counterbranch",
        "binary": "counterbranch",
        "version": expected_core_version,
        "edition": EDITION,
    }
    if core_build != expected_build:
        raise ValueError("Counterbranch build identity differs")
    _source(core["source"], CORE_REPOSITORY, expected_core_source_commit,
            expected_core_source_tree, "Counterbranch source")
    core_artifact = _exact_object(core["artifact"], CORE_ARTIFACT_FIELDS,
                                  "Counterbranch artifact")
    if (core_artifact.get("binary") != "counterbranch"
            or core_artifact.get("path") != "bin/counterbranch"
            or core_artifact.get("target") != expected_target):
        raise ValueError("Counterbranch artifact identity differs")
    core_size = _positive_int(core_artifact.get("size_bytes"), MAX_MEMBER_SIZE,
                              "Counterbranch artifact size")
    core_digest = _digest(core_artifact.get("sha256"), "Counterbranch artifact digest")

    discovery = _exact_object(record["discovery"], DISCOVERY_FIELDS, "Discovery artifact")
    if (discovery.get("schema_version") != DISCOVERY_ARTIFACT_SCHEMA
            or discovery.get("edition") != EDITION):
        raise ValueError("Discovery artifact schema or edition differs")
    discovery_build = _exact_object(discovery["build"], DISCOVERY_BUILD_FIELDS,
                                    "Discovery build")
    if ({key: discovery_build.get(key) for key in (
        "schema_version", "product", "binary", "version", "edition"
    )} != {
        "schema_version": DISCOVERY_BUILD_SCHEMA,
        "product": "counterbranch-discovery",
        "binary": "discovery",
        "version": DISCOVERY_VERSION,
        "edition": EDITION,
    }):
        raise ValueError("Discovery build identity differs")
    _source(discovery_build["source"], DISCOVERY_REPOSITORY, DISCOVERY_COMMIT,
            DISCOVERY_TREE, "Discovery source")
    discovery_artifact = _exact_object(discovery["artifact"], DISCOVERY_ARTIFACT_FIELDS,
                                       "Discovery binary artifact")
    if (discovery_artifact.get("binary") != "discovery"
            or discovery_artifact.get("target") != expected_target):
        raise ValueError("Discovery binary artifact identity differs")
    discovery_size = _positive_int(discovery_artifact.get("size_bytes"), MAX_MEMBER_SIZE,
                                   "Discovery artifact size")
    discovery_digest = _digest(discovery_artifact.get("sha256"), "Discovery artifact digest")

    declared = _exact_object(record["files"], frozenset(members), "kit inventory")
    observed: dict[str, dict[str, object]] = {}
    executable_names = set()
    for name, (content, mode) in members.items():
        if not _allowed_payload(name):
            raise ValueError(f"kit contains an unsupported payload: {name}")
        if mode == 0o755:
            executable_names.add(name)
        item = _exact_object(declared[name], FILE_FIELDS, f"kit inventory entry {name}")
        _digest(item.get("sha256"), f"kit inventory entry {name} digest")
        if (type(item.get("size")) is not int or item["size"] < 0
                or item["size"] > MAX_MEMBER_SIZE):
            raise ValueError(f"kit inventory entry size is invalid: {name}")
        if type(item.get("mode")) is not str or item["mode"] not in {"0644", "0755"}:
            raise ValueError(f"kit inventory entry mode is invalid: {name}")
        expected_item = {"sha256": sha256(content), "size": len(content), "mode": f"{mode:04o}"}
        if item != expected_item:
            raise ValueError(f"kit inventory entry differs: {name}")
        observed[name] = expected_item
    if not REQUIRED_PAYLOADS.issubset(members):
        raise ValueError("kit required payload inventory differs")
    if executable_names != EXECUTABLES:
        raise ValueError("kit executable inventory differs")
    if _digest(record["inventory_sha256"], "kit inventory digest") != sha256(canonical(observed)):
        raise ValueError("kit inventory digest differs")

    core_bytes = members["bin/counterbranch"][0]
    if len(core_bytes) != core_size or sha256(core_bytes) != core_digest:
        raise ValueError("Counterbranch binary differs from its artifact record")
    discovery_bytes = members["bin/discovery"][0]
    if len(discovery_bytes) != discovery_size or sha256(discovery_bytes) != discovery_digest:
        raise ValueError("Discovery binary differs from its artifact record")
    if members[DISCOVERY_MANIFEST_PATH][0] != canonical(discovery):
        raise ValueError("packaged Discovery artifact manifest differs from KIT.json")
    return record, {name: content for name, (content, _) in members.items()}


def _release_source(value: object, repository: str, label: str) -> tuple[str, str]:
    source = _exact_object(value, RELEASE_SOURCE_FIELDS, label)
    commit = _oid(source.get("commit"), f"{label} commit")
    tree = _oid(source.get("tree"), f"{label} tree")
    if source.get("repository") != repository or source.get("dirty") is not False:
        raise ValueError(f"{label} is not the exact clean canonical source")
    return commit, tree


def load_release(path: Path, target: str, supplied_sha256: str) -> dict[str, object]:
    """Load one expected kit from the exact approved scanner release-manifest schema."""
    if target not in PUBLIC_RELEASE_TARGETS:
        raise ValueError("release target is unsupported")
    supplied_sha256 = _digest(supplied_sha256, "supplied kit digest")
    value = strict_json(_bounded_regular_file(path, MAX_RELEASE_MANIFEST_SIZE, "release manifest"),
                        "release manifest")
    release = _exact_object(value, RELEASE_FIELDS, "release manifest")
    if (type(release.get("format")) is not int or release.get("format") != 2
            or release.get("edition") != EDITION or release.get("status") != "approved"
            or release.get("repository") != SCANNER_RELEASE_REPOSITORY):
        raise ValueError("release manifest is not an approved scanner-only format 2 release")
    version = release.get("version")
    if (not isinstance(version, str) or not VERSION_RE.fullmatch(version)
            or release.get("tag") != f"v{version}"):
        raise ValueError("release version and immutable tag differ")
    core_commit, core_tree = _release_source(release["core_source"], CORE_REPOSITORY,
                                             "release Counterbranch source")
    discovery_commit, discovery_tree = _release_source(
        release["discovery_source"], DISCOVERY_REPOSITORY, "release Discovery source"
    )
    if (discovery_commit, discovery_tree) != (DISCOVERY_COMMIT, DISCOVERY_TREE):
        raise ValueError("release Discovery source differs from the supported scanner pin")
    kits = release.get("kits")
    if not isinstance(kits, dict) or set(kits) != PUBLIC_RELEASE_TARGETS:
        raise ValueError("release manifest must contain exactly the public Linux scanner kit")
    selected = None
    for kit_target, item_value in kits.items():
        item = _exact_object(item_value, RELEASE_KIT_FIELDS, f"release kit {kit_target}")
        name = f"counterbranch-scanner-only-alpha-{kit_target}.tar.gz"
        bundle = _exact_object(item.get("bundle"), RELEASE_BUNDLE_FIELDS,
                               f"release bundle {kit_target}")
        if item.get("edition") != EDITION or item.get("name") != name \
                or bundle.get("name") != f"{name}.sigstore.json":
            raise ValueError("release kit name or edition differs")
        item_digest = _digest(item.get("sha256"), f"release kit {kit_target} digest")
        item_size = _positive_int(item.get("size"), MAX_ARCHIVE_SIZE,
                                  f"release kit {kit_target} size")
        _digest(bundle.get("sha256"), f"release bundle {kit_target} digest")
        _positive_int(bundle.get("size"), MAX_BUNDLE_SIZE, f"release bundle {kit_target} size")
        if kit_target == target:
            selected = (item_digest, item_size)
    assert selected is not None
    if supplied_sha256 != selected[0]:
        raise ValueError("supplied kit digest differs from the trusted release manifest")
    return {
        "sha256": selected[0], "size": selected[1], "target": target,
        "core_version": version, "core_source_commit": core_commit,
        "core_source_tree": core_tree,
    }


def extract(
    archive_path: Path,
    prefix: Path,
    expected_sha256: str,
    expected_target: str,
    expected_core_version: str,
    expected_core_source_commit: str,
    expected_core_source_tree: str,
    expected_size: int | None = None,
) -> dict:
    """Validate then extract a kit; trusted public expectations come from ``load_release``."""
    archive_bytes = load_archive_bytes(archive_path, expected_sha256, expected_size)
    record, files = validate_archive_bytes(
        archive_bytes, expected_sha256, expected_target, expected_core_version,
        expected_core_source_commit, expected_core_source_tree, expected_size,
    )
    prefix = prefix.resolve()
    prefix.parent.mkdir(parents=True, exist_ok=True)
    try:
        prefix.mkdir(mode=0o755)
    except FileExistsError:
        raise FileExistsError(f"refusing to overwrite extraction prefix: {prefix}") from None
    try:
        modes = record["files"]
        for name, content in sorted(files.items()):
            destination = prefix.joinpath(*PurePosixPath(name).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            destination.chmod(int(modes[name]["mode"], 8))
        with (prefix / "KIT.json").open("xb") as stream:
            stream.write(canonical(record))
            stream.flush()
            os.fsync(stream.fileno())
        (prefix / "KIT.json").chmod(0o644)
    except BaseException:
        shutil.rmtree(prefix, ignore_errors=True)
        raise
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    parser.add_argument("--prefix", required=True, type=Path)
    parser.add_argument("--release-manifest", type=Path)
    parser.add_argument("--local-unsigned", action="store_true")
    parser.add_argument("--core-version")
    parser.add_argument("--core-source-commit")
    parser.add_argument("--core-source-tree")
    args = parser.parse_args()

    local_values = (args.core_version, args.core_source_commit, args.core_source_tree)
    if args.local_unsigned:
        if args.release_manifest is not None or not all(local_values):
            parser.error("--local-unsigned requires all core identity options and rejects --release-manifest")
        expected = {
            "sha256": args.sha256, "size": None, "target": args.target,
            "core_version": args.core_version,
            "core_source_commit": args.core_source_commit,
            "core_source_tree": args.core_source_tree,
        }
    else:
        if args.release_manifest is None or any(local_values):
            parser.error("public extraction requires --release-manifest and rejects manual core identity options")
        expected = load_release(args.release_manifest, args.target, args.sha256)
    extract(
        args.archive, args.prefix, expected["sha256"], expected["target"],
        expected["core_version"], expected["core_source_commit"],
        expected["core_source_tree"], expected["size"],
    )
    print(json.dumps({
        "status": "extracted", "edition": EDITION, "target": args.target,
        "authentication": "none" if args.local_unsigned else "release-manifest-bound",
        "prefix": str(args.prefix.resolve()),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
