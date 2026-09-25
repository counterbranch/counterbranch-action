#!/usr/bin/env python3
"""Acquire the CLI asset or paired kit pinned by this Action's reviewed release manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import threading
import time

SUPPORTED_TARGETS = {
    ("Darwin", "arm64"): "aarch64-apple-darwin",
    ("Darwin", "aarch64"): "aarch64-apple-darwin",
    ("Linux", "x86_64"): "x86_64-unknown-linux-gnu",
    ("Linux", "amd64"): "x86_64-unknown-linux-gnu",
}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
MAX_VERIFIER_OUTPUT = 8 * 1024 * 1024
DOWNLOAD_TIMEOUT = 300
SIGNER_IDENTITY = "https://github.com/counterbranch/counterbranch/.github/workflows/publish.yml@refs/heads/main"
SIGNER_ISSUER = "https://token.actions.githubusercontent.com"
# GitHub issued release/v0.1 predicates before moving to v0.2; both bind subjects the same way.
RELEASE_PREDICATES = ("https://in-toto.io/attestation/release/v0.1",
                      "https://in-toto.io/attestation/release/v0.2")


def host_target() -> str:
    try:
        return SUPPORTED_TARGETS[(platform.system(), platform.machine().lower())]
    except KeyError as error:
        raise RuntimeError("Counterbranch releases support only macOS arm64 and Linux x86_64 GNU") from error


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_release(path: Path, target: str, kit: bool = False) -> tuple[str, str, str, str, str, int, tuple | None]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("format") != 1 or value.get("status") != "approved":
            raise ValueError("release publisher trust is not approved")
        repository, tag, version = value["repository"], value["tag"], value["version"]
        if not kit and "assets" not in value:
            raise ValueError("release carries only Discovery kits; policy modes need CLI archives, use discovery: \"true\"")
        asset = value["kits" if kit else "assets"][target]
        entries = [asset, asset["bundle"]] if kit else [asset]
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
    if kit and identities[0][0] == identities[1][0]:
        raise ValueError("release manifest contains an invalid identity")
    return repository, tag, version, *identities[0], identities[1] if kit else None


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
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gh", default="gh")
    parser.add_argument("--archive", type=Path, help="Verify an already available archive through the same release path")
    parser.add_argument("--kit", action="store_true", help="Acquire the paired kit and verify its Sigstore bundle")
    parser.add_argument("--cosign", default="cosign")
    args = parser.parse_args()
    print(json.dumps(acquire(args.manifest, args.output, args.gh, archive=args.archive,
                             kit=args.kit, cosign=args.cosign), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
