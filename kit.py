#!/usr/bin/env python3
"""Extract a hash-verified paired kit into a new prefix."""
import argparse
import gzip
import io
import json
from pathlib import Path, PurePosixPath
import tarfile

from common import KIT_STATUSES, digest, encoded, inventory, read, write

MAX_TOTAL = 512 * 1024 * 1024
MAX_MEMBERS = 4096


def archive(root: Path) -> bytes:
    result = io.BytesIO()
    with gzip.GzipFile(fileobj=result, mode="wb", mtime=0, filename="") as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as tar:
            for name, item in inventory(root).items():
                data = read(root / name)
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = int(item["mode"], 8)
                tar.addfile(member, io.BytesIO(data))
    return result.getvalue()


def extract(archive_path: Path, expected_sha256: str, prefix: Path) -> dict:
    data = read(archive_path)
    if digest(data) != expected_sha256:
        raise ValueError("kit archive digest differs")
    files, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar:
            name = member.name
            path = PurePosixPath(name)
            if (not name or path.is_absolute() or ".." in path.parts or str(path) != name
                    or "\\" in name or not member.isfile() or name in files
                    or member.mode not in (0o644, 0o755) or member.size < 0):
                raise ValueError("unsafe kit archive member")
            total += member.size
            if total > MAX_TOTAL or len(files) >= MAX_MEMBERS:
                raise ValueError("kit exceeds extraction limits")
            content = tar.extractfile(member).read(member.size + 1)
            if len(content) != member.size:
                raise ValueError("incomplete kit member")
            files[name] = (content, member.mode)
    record_data, mode = files.pop("KIT.json", (b"", 0))
    if not record_data or mode != 0o644:
        raise ValueError("kit completion record missing")
    record = json.loads(record_data)
    expected = record["files"]
    observed = {name: {"sha256": digest(content), "size": len(content), "mode": f"{mode:04o}"}
                for name, (content, mode) in files.items()}
    if (record.get("status") not in KIT_STATUSES or observed != expected
            or digest(encoded(expected)) != record["inventory_sha256"]):
        raise ValueError("kit inventory differs")
    if {name for name, (_, mode) in files.items() if mode == 0o755} != {"bin/counterbranch", "bin/discovery"}:
        raise ValueError("kit executable inventory differs")
    prefix.mkdir(parents=True, exist_ok=False)
    for name, (content, mode) in files.items():
        write(prefix / name, content, mode == 0o755)
    write(prefix / "KIT.json", record_data)
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--prefix", required=True, type=Path)
    args = parser.parse_args()
    extract(args.archive, args.sha256, args.prefix)
