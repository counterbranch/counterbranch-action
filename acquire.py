#!/usr/bin/env python3
"""Acquire the scanner-only paired kit pinned by this Action's reviewed release manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import tempfile
import threading
import time

SUPPORTED_TARGETS = {
    ("Linux", "x86_64"): "x86_64-unknown-linux-gnu",
    ("Linux", "amd64"): "x86_64-unknown-linux-gnu",
}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
MAX_VERIFIER_OUTPUT = 8 * 1024 * 1024
DOWNLOAD_TIMEOUT = 300
MAX_MANIFEST_BYTES = 64 * 1024
MAX_BUNDLE_BYTES = 16 * 1024 * 1024
DISCOVERY_COMMIT = "d0d5dfe44b58ebcc1db21585e18be6edccb2d6ac"
DISCOVERY_TREE = "78338e69c84dd3d8265682cd4b3bbdfbf69a9cc4"
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?\Z")
SIGNER_IDENTITY = "https://github.com/counterbranch/counterbranch/.github/workflows/publish-scanner.yml@refs/heads/main"
SIGNER_ISSUER = "https://token.actions.githubusercontent.com"
# GitHub issued release/v0.1 predicates before moving to v0.2; both bind subjects the same way.
RELEASE_PREDICATES = ("https://in-toto.io/attestation/release/v0.1",
                      "https://in-toto.io/attestation/release/v0.2")
RELEASE_FORMAT = 2
RELEASE_EDITION = "scanner-only"
SCANNER_RELEASE_REPOSITORY = "counterbranch/alpha-releases"
RELEASE_TARGETS = frozenset(SUPPORTED_TARGETS.values())
RELEASE_FIELDS = frozenset({
    "format", "edition", "status", "repository", "tag", "version", "kits",
    "core_source", "discovery_source",
})
KIT_FIELDS = frozenset({"edition", "name", "sha256", "size", "bundle"})
BUNDLE_FIELDS = frozenset({"name", "sha256", "size"})
SOURCE_FIELDS = frozenset({"repository", "commit", "tree", "dirty"})


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"release manifest contains duplicate field: {key}")
        value[key] = item
    return value


def load_json_object(text: str) -> dict:
    value = json.loads(
        text,
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=lambda constant: (_ for _ in ()).throw(
            ValueError(f"release manifest contains invalid number: {constant}")
        ),
    )
    if not isinstance(value, dict):
        raise ValueError("release manifest is missing or invalid")
    return value


def host_target() -> str:
    try:
        return SUPPORTED_TARGETS[(platform.system(), platform.machine().lower())]
    except KeyError as error:
        raise RuntimeError("The public Counterbranch scanner Action supports only Linux x86_64 GNU") from error


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_manifest(path: Path) -> str:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_MANIFEST_BYTES:
        raise ValueError("release manifest must be a bounded regular file")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(MAX_MANIFEST_BYTES + 1)
        after = os.fstat(stream.fileno())
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
    if identity(before) != identity(opened) or identity(opened) != identity(after) or len(data) != opened.st_size:
        raise ValueError("release manifest changed while reading")
    if len(data) > MAX_MANIFEST_BYTES:
        raise ValueError("release manifest exceeds its size limit")
    return data.decode("utf-8")


def load_release(path: Path, target: str, kit: bool = False) -> tuple[str, str, str, str, str, int, tuple | None]:
    try:
        value = load_json_object(read_manifest(path))
        if type(value.get("format")) is not int or value["format"] != RELEASE_FORMAT \
                or value.get("edition") != RELEASE_EDITION:
            raise ValueError("release manifest is not a scanner-only format 2 release")
        if value.get("status") != "approved":
            raise ValueError("release publisher trust is not approved")
        if set(value) != RELEASE_FIELDS:
            raise ValueError("release manifest fields do not match the scanner-only schema")
        if not kit:
            raise ValueError(
                'scanner-only releases require paired-kit acquisition'
            )
        kits = value.get("kits", {})
        if "assets" in value or not isinstance(kits, dict) or set(kits) != RELEASE_TARGETS:
            raise ValueError("release manifest must contain exactly the supported scanner-only kits")
        repository, tag, version = value["repository"], value["tag"], value["version"]
        if (repository != SCANNER_RELEASE_REPOSITORY or not isinstance(version, str)
                or not VERSION_RE.fullmatch(version) or tag != f"v{version}"):
            raise ValueError("release repository, tag, or version is invalid")
        for field, expected_repository in (
                ("core_source", "https://github.com/counterbranch/counterbranch"),
                ("discovery_source", "https://github.com/counterbranch/discovery")):
            source = value[field]
            if (not isinstance(source, dict) or set(source) != SOURCE_FIELDS
                    or source.get("repository") != expected_repository or source.get("dirty") is not False
                    or not all(isinstance(source.get(item), str)
                               and re.fullmatch(r"[0-9a-f]{40}", source[item])
                               for item in ("commit", "tree"))):
                raise ValueError(f"release manifest {field} is invalid")
        if (value["discovery_source"]["commit"], value["discovery_source"]["tree"]) != (DISCOVERY_COMMIT, DISCOVERY_TREE):
            raise ValueError("release Discovery source differs from the supported pin")
        selected_identities = None
        for release_target, release_kit in kits.items():
            expected_name = f"counterbranch-scanner-only-alpha-{release_target}.tar.gz"
            if (not isinstance(release_kit, dict) or set(release_kit) != KIT_FIELDS
                    or release_kit.get("edition") != RELEASE_EDITION):
                raise ValueError("release kit is not scanner-only")
            bundle_value = release_kit.get("bundle")
            if (release_kit.get("name") != expected_name or not isinstance(bundle_value, dict)
                    or set(bundle_value) != BUNDLE_FIELDS
                    or bundle_value.get("name") != f"{expected_name}.sigstore.json"):
                raise ValueError("release manifest contains an invalid scanner-only kit identity")
            if type(bundle_value.get("size")) is not int or not 0 < bundle_value["size"] <= MAX_BUNDLE_BYTES:
                raise ValueError("release bundle exceeds its size limit")
            release_identities = [release_kit, bundle_value]
            for entry in release_identities:
                if (not isinstance(entry.get("sha256"), str)
                        or not SHA256_RE.fullmatch(entry["sha256"])
                        or not isinstance(entry.get("size"), int)
                        or isinstance(entry["size"], bool)
                        or not 0 < entry["size"] <= 512 * 1024 * 1024):
                    raise ValueError("release manifest contains an invalid asset identity")
            if release_target == target:
                selected_identities = release_identities
        asset = kits[target]
        entries = selected_identities
        identities = [(entry["name"], entry["sha256"], entry["size"]) for entry in entries]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ValueError("release manifest is missing or invalid") from error
    if not all(isinstance(field, str) and field for field in (repository, tag, version)):
        raise ValueError("release manifest fields must be nonempty strings")
    for name, digest, size in identities:
        if not all(isinstance(field, str) and field for field in (name, digest)):
            raise ValueError("release manifest fields must be nonempty strings")
        if (not REPOSITORY_RE.fullmatch(repository) or any(c in tag + version + name for c in "\r\n\x00")
                or "/" in name or "\\" in name or not SHA256_RE.fullmatch(digest)):
            raise ValueError("release manifest contains an invalid identity")
        if not isinstance(size, int) or isinstance(size, bool) or size < 1 or size > 512 * 1024 * 1024:
            raise ValueError("release manifest contains an invalid asset size")
    if identities[0][0] == identities[1][0]:
        raise ValueError("release manifest contains an invalid identity")
    return repository, tag, version, *identities[0], identities[1]


def preflight(manifest: Path) -> dict[str, str]:
    """Validate the public host and complete paired-kit manifest without network access."""
    target = host_target()
    repository, tag, version, name, digest, _size, bundle = load_release(
        manifest, target, kit=True
    )
    return {
        "repository": repository,
        "tag": tag,
        "version": version,
        "target": target,
        "asset": name,
        "sha256": digest,
        "bundle": bundle[0],
    }


def run_gh(argv: list[str], env: dict[str, str], label: str = "GitHub release") -> bytes:
    try:
        process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as error:
        raise RuntimeError(f"{label} verification could not complete") from error
    captures = [bytearray(), bytearray()]
    overflow = [False, False]
    def drain(stream, index):
        while chunk := stream.read(64 * 1024):
            remaining = MAX_VERIFIER_OUTPUT - len(captures[index])
            if remaining > 0:
                captures[index].extend(chunk[:remaining])
            if len(chunk) > remaining:
                overflow[index] = True
    threads = [threading.Thread(target=drain, args=(process.stdout, 0), daemon=True),
               threading.Thread(target=drain, args=(process.stderr, 1), daemon=True)]
    for thread in threads: thread.start()
    try:
        status = process.wait(timeout=300)
    except subprocess.TimeoutExpired as error:
        process.kill(); process.wait()
        raise RuntimeError(f"{label} verification could not complete") from error
    for thread in threads: thread.join(timeout=5)
    process.stdout.close(); process.stderr.close()
    if any(thread.is_alive() for thread in threads) or any(overflow):
        raise RuntimeError(f"{label} verification output exceeds 8 MiB")
    if status != 0:
        raise RuntimeError(f"{label} authentication failed")
    return bytes(captures[0])


def download_gh(gh: str, repository: str, tag: str, name: str, destination: Path,
                size: int, env: dict[str, str]) -> None:
    try:
        process = subprocess.Popen(
            [gh, "release", "download", tag, "--repo", repository, "--pattern", name,
             "--output", "-"], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise RuntimeError("GitHub release download could not start") from error
    stderr = bytearray(); overflow = False
    deadline = time.monotonic() + DOWNLOAD_TIMEOUT
    timer = threading.Timer(DOWNLOAD_TIMEOUT, process.kill)
    timer.daemon = True
    timer.start()
    def drain_stderr():
        nonlocal overflow
        while chunk := process.stderr.read(64 * 1024):
            remaining = MAX_VERIFIER_OUTPUT - len(stderr)
            if remaining > 0: stderr.extend(chunk[:remaining])
            if len(chunk) > remaining: overflow = True
    reader = threading.Thread(target=drain_stderr, daemon=True); reader.start()
    total = 0
    try:
        with destination.open("xb") as output:
            while chunk := process.stdout.read(min(1024 * 1024, size + 1 - total)):
                if time.monotonic() > deadline:
                    raise RuntimeError("GitHub release download timed out")
                total += len(chunk)
                if total > size:
                    raise RuntimeError("downloaded asset exceeds the reviewed release size")
                output.write(chunk)
            output.flush(); os.fsync(output.fileno())
        status = process.wait()
        if time.monotonic() > deadline:
            raise RuntimeError("GitHub release download timed out")
        if overflow or status != 0 or total != size:
            raise RuntimeError("GitHub release download failed or returned an unexpected size")
    finally:
        timer.cancel()
        if process.poll() is None:
            process.kill()
        process.wait()
        if process.stdout is not None:
            process.stdout.close()
        reader.join(timeout=5)
        if process.stderr is not None:
            process.stderr.close()
        if reader.is_alive():
            raise RuntimeError("GitHub release download output could not be drained")


def acquire(manifest: Path, output: Path, gh: str = "gh", target: str | None = None,
            archive: Path | None = None, kit: bool = False, cosign: str = "cosign") -> dict[str, str]:
    selected = target or host_target()
    if selected not in set(SUPPORTED_TARGETS.values()):
        raise RuntimeError("unsupported Counterbranch release target")
    if kit and archive is not None:
        raise RuntimeError("kit acquisition requires a GitHub release download")
    repository, tag, version, name, expected, size, bundle = load_release(manifest, selected, kit)
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"refusing to overwrite acquisition output: {output}")
    proxies = {key: value for key, value in os.environ.items()
               if key.lower() in ("https_proxy", "http_proxy", "no_proxy")}
    env = {**proxies, **{key: value for key, value in os.environ.items() if key in ("PATH", "GH_TOKEN")}}
    with tempfile.TemporaryDirectory(prefix="counterbranch-acquire-", dir=output.parent) as temp:
        env["GH_CONFIG_DIR"] = str(Path(temp) / "gh-config")
        # Without HOME, gh writes its state under ./.local, i.e. into the caller's workspace.
        env["XDG_STATE_HOME"] = str(Path(temp) / "gh-state")
        env["GH_HOST"] = "github.com"
        downloaded = Path(temp) / name
        if archive is None:
            download_gh(gh, repository, tag, name, downloaded, size, env)
            if bundle is not None:
                signature = Path(temp) / bundle[0]
                download_gh(gh, repository, tag, bundle[0], signature, bundle[2], env)
                if sha256(signature) != bundle[1]:
                    raise RuntimeError("downloaded Sigstore bundle digest does not match the reviewed release manifest")
        else:
            if not archive.is_file() or archive.stat().st_size != size:
                raise RuntimeError("local CLI archive does not match the reviewed release size")
            with archive.open("rb") as source, downloaded.open("xb") as destination:
                remaining = size
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise RuntimeError("local CLI archive changed during acquisition")
                    destination.write(chunk); remaining -= len(chunk)
                if source.read(1):
                    raise RuntimeError("local CLI archive changed during acquisition")
                destination.flush(); os.fsync(destination.fileno())
        actual = sha256(downloaded)
        if actual != expected:
            raise RuntimeError("downloaded asset digest does not match the reviewed release manifest")
        evidence = run_gh([gh, "release", "verify-asset", tag, str(downloaded),
                           "--repo", repository, "--format", "json"], env)
        try:
            parsed = json.loads(evidence)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise RuntimeError("GitHub release verification returned invalid evidence") from error
        try:
            statement = parsed["verificationResult"]["statement"]
            subjects = statement["subject"]
        except (KeyError, TypeError) as error:
            raise RuntimeError("GitHub release verification returned invalid evidence") from error
        if (statement.get("predicateType") not in RELEASE_PREDICATES
                or not isinstance(subjects, list)
                or not any(isinstance(item, dict) and item.get("name") == name
                           and item.get("digest", {}).get("sha256") == expected for item in subjects)):
            raise RuntimeError("GitHub release attestation does not bind the reviewed asset")
        if bundle is not None:
            home = Path(temp) / "cosign-home"; home.mkdir()
            run_gh([cosign, "verify-blob", "--bundle", str(signature),
                    "--certificate-identity", SIGNER_IDENTITY,
                    "--certificate-oidc-issuer", SIGNER_ISSUER, str(downloaded)],
                   # cosign fetches Sigstore's trust root, so self-hosted runners may need their proxy.
                   {**proxies, "PATH": env.get("PATH", ""), "HOME": str(home)}, "Sigstore bundle")
        os.replace(downloaded, output)
    return {"repository": repository, "tag": tag, "version": version, "target": selected,
            "asset": name, "sha256": expected, "archive": str(output),
            **({"bundle": bundle[0]} if bundle else {})}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("release-manifest.json"))
    parser.add_argument("--preflight", action="store_true",
                        help="Validate the public host and approved paired-kit manifest without network access")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--archive", type=Path, help="Verify an already available archive through the same release path")
    parser.add_argument("--kit", action="store_true", help="Acquire the paired kit and verify its Sigstore bundle")
    parser.add_argument("--cosign", default="cosign")
    args = parser.parse_args()
    if args.preflight:
        if args.output is not None or args.archive is not None or args.kit:
            parser.error("--preflight cannot be combined with acquisition options")
        print(json.dumps(preflight(args.manifest), sort_keys=True))
        return 0
    if args.output is None:
        parser.error("--output is required unless --preflight is used")
    print(json.dumps(acquire(args.manifest, args.output, args.gh, archive=args.archive,
                             kit=args.kit, cosign=args.cosign), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
