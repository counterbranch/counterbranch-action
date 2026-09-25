#!/usr/bin/env python3
"""Acquire the pinned, publisher-attested OPA runtime into a verified cache."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.request

VERSION = "1.11.0"
REPOSITORY = "open-policy-agent/opa"
TARGET = "darwin-arm64"
ASSET = "opa_darwin_arm64"
SHA256 = "ac5e6e61a97efc0e776712212c86416a3db7361587f6acd95d5b76f53571061c"
SIZE = 69_411_586
PLATFORMS = {
    ("Darwin", "arm64"): (TARGET, ASSET, SHA256, SIZE),
    ("Linux", "x86_64"): (
        "linux-amd64", "opa_linux_amd64",
        "5450bf543dcad75a272dab92a13ad61967e1a7cba41fac4fcafd54bcf1dd13b2",
        74_898_152,
    ),
    ("Linux", "amd64"): (
        "linux-amd64", "opa_linux_amd64",
        "5450bf543dcad75a272dab92a13ad61967e1a7cba41fac4fcafd54bcf1dd13b2",
        74_898_152,
    ),
}
MAX_BYTES = 80 * 1024 * 1024
MAX_VERIFIER_OUTPUT = 2 * 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _platform() -> tuple[str, str, str, int]:
    try:
        return PLATFORMS[(platform.system(), platform.machine())]
    except KeyError:
        raise RuntimeError(
            f"automatic OPA preparation does not support {platform.system()} {platform.machine()}"
        ) from None


def _download(destination: Path, asset: str = ASSET) -> None:
    url = f"https://github.com/{REPOSITORY}/releases/download/v{VERSION}/{asset}"
    request = urllib.request.Request(url, headers={"User-Agent": "counterbranch-opa-preparer/1"})
    with urllib.request.urlopen(request, timeout=30) as response, destination.open("xb") as output:
        if not response.geturl().startswith("https://"):
            raise RuntimeError("OPA download redirected outside HTTPS")
        length = response.headers.get("Content-Length")
        if length is not None and int(length) > MAX_BYTES:
            raise RuntimeError("OPA download exceeds the size limit")
        total = 0
        deadline = time.monotonic() + 120
        while chunk := response.read(min(1024 * 1024, MAX_BYTES + 1 - total)):
            if time.monotonic() > deadline:
                raise RuntimeError("OPA download exceeded its time limit")
            total += len(chunk)
            if total > MAX_BYTES:
                raise RuntimeError("OPA download exceeds the size limit")
            output.write(chunk)
        output.flush()
        os.fsync(output.fileno())


def _run_verifier(argv: list[str]) -> bytes:
    process = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    captured = bytearray()
    overflow = False

    def drain() -> None:
        nonlocal overflow
        assert process.stdout is not None
        while chunk := process.stdout.read(64 * 1024):
            remaining = MAX_VERIFIER_OUTPUT - len(captured)
            if remaining > 0:
                captured.extend(chunk[:remaining])
            if len(chunk) > remaining:
                overflow = True

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        result = process.wait(timeout=60)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        reader.join(timeout=5)
        raise RuntimeError("OPA publisher release attestation verification timed out") from None
    reader.join(timeout=5)
    if process.stdout is not None:
        process.stdout.close()
    if reader.is_alive() or overflow:
        raise RuntimeError("OPA release verifier output exceeds the size limit")
    if result != 0:
        raise RuntimeError("OPA publisher release attestation verification failed")
    return bytes(captured)


def _verify(binary: Path, gh: str, asset: str = ASSET, digest: str = SHA256,
            size: int = SIZE) -> None:
    if binary.stat().st_size != size or _sha256(binary) != digest:
        raise RuntimeError("OPA artifact does not match the built-in release identity")
    output = _run_verifier(
        [gh, "release", "verify-asset", f"v{VERSION}", str(binary),
         "--repo", REPOSITORY, "--format", "json"]
    )
    try:
        verified = json.loads(output)
        statement = verified["verificationResult"]["statement"]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("OPA release verifier returned invalid evidence") from error
    subjects = statement.get("subject")
    if statement.get("predicateType") != "https://in-toto.io/attestation/release/v0.1" or not isinstance(subjects, list):
        raise RuntimeError("OPA release verifier returned an unsupported attestation")
    if not any(item.get("name") == asset and item.get("digest", {}).get("sha256") == digest
               for item in subjects if isinstance(item, dict)):
        raise RuntimeError("OPA release attestation does not bind the selected artifact")


def prepare(cache_root: Path, gh: str | None = None) -> dict[str, object]:
    target, asset, digest, size = _platform()
    verifier = gh or shutil.which("gh")
    if not verifier or not Path(verifier).is_absolute():
        raise RuntimeError("GitHub CLI is required to verify the OPA publisher attestation")
    directory = cache_root.resolve() / "counterbranch" / "opa" / VERSION / target
    binary = directory / "opa"
    directory.mkdir(parents=True, exist_ok=True)
    if binary.exists():
        if not binary.is_file() or binary.is_symlink():
            raise RuntimeError("cached OPA path is not a regular file")
        _verify(binary, verifier, asset, digest, size)
    else:
        with tempfile.TemporaryDirectory(prefix=".opa-download-", dir=directory) as temporary:
            staged = Path(temporary) / "opa"
            _download(staged, asset)
            _verify(staged, verifier, asset, digest, size)
            staged.chmod(0o755)
            os.replace(staged, binary)
    binary.chmod(0o755)
    evidence = {
        "schema_version": 1, "engine": "opa", "version": VERSION,
        "platform": target, "executable": str(binary), "artifact_sha256": digest,
        "verification": {"method": "github-release-attestation", "repository": REPOSITORY,
                         "tag": f"v{VERSION}", "asset": asset},
    }
    evidence_path = directory / "verified.json"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=directory,
                                     prefix=".verified-", delete=False) as output:
        json.dump(evidence, output, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
        temporary_name = output.name
    os.replace(temporary_name, evidence_path)
    return evidence


def default_cache_root() -> Path:
    configured = os.environ.get("XDG_CACHE_HOME")
    if configured:
        return Path(configured)
    home = os.environ.get("HOME")
    if not home:
        raise RuntimeError("cannot determine the automatic OPA cache directory")
    return Path(home) / ".cache"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-root", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.cache_root or default_cache_root()), sort_keys=True))
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"prepare_opa.py: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
