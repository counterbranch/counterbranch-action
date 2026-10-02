#!/usr/bin/env python3
"""Package a bounded scanner report directory for GitHub artifact upload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urlsplit


BUNDLE_SCHEMA = "counterbranch-scanner-report-bundle/1"
COMPARISON_SCHEMA = "counterbranch-discovery-comparison/3"
COMPARISON_KIND = "discovery_coverage_comparison"
OUTCOMES = {"CLEAN", "INCOMPLETE", "NEEDS_OWNER_REVIEW"}
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
RUN_ID_RE = re.compile(r"[1-9][0-9]{0,29}")
MAX_REPORT = 72 * 1024 * 1024
MAX_MARKDOWN = 8 * 1024 * 1024
MAX_GUIDE = 256 * 1024
MAX_PROVENANCE = 256 * 1024


class BundleError(Exception):
    pass


def parse_incomplete(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("incomplete must be true or false")


def reject_constant(value: str) -> None:
    raise BundleError(f"comparison contains unsupported JSON constant {value}")


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise BundleError("comparison contains duplicate JSON fields")
        value[key] = item
    return value


def read_regular(path: Path, maximum: int, description: str) -> bytes:
    if not path.is_absolute():
        raise BundleError(f"{description} path must be absolute")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BundleError(f"{description} must be a readable regular file") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum:
            raise BundleError(f"{description} is empty, oversized, or not a regular file")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != metadata.st_size or len(data) > maximum:
            raise BundleError(f"{description} changed while it was being read")
        return data
    finally:
        os.close(descriptor)


def regular_directory(path: Path, description: str) -> Path:
    if not path.is_absolute():
        raise BundleError(f"{description} path must be absolute")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise BundleError(f"{description} must be an existing directory") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise BundleError(f"{description} must be a directory and not a symlink")
    return path.resolve(strict=True)


def validate_context(repository: str, base: str, head: str, merge_base: str | None,
                     run_id: str, run_attempt: int, run_url: str) -> None:
    if (type(repository) is not str or type(base) is not str or type(head) is not str
            or (merge_base is not None and type(merge_base) is not str)
            or type(run_id) is not str or type(run_attempt) is not int
            or type(run_url) is not str):
        raise BundleError("repository, revision, and run context types are invalid")
    if not REPOSITORY_RE.fullmatch(repository) or repository.startswith(('.', '-')):
        raise BundleError("repository must be a bounded owner/name identifier")
    if any(not COMMIT_RE.fullmatch(value) for value in (base, head)):
        raise BundleError("base and head must be exact lowercase commit IDs")
    if merge_base is not None and not COMMIT_RE.fullmatch(merge_base):
        raise BundleError("merge base must be an exact lowercase commit ID")
    if not RUN_ID_RE.fullmatch(run_id) or not 1 <= run_attempt <= 1_000_000:
        raise BundleError("run ID or attempt is invalid")
    parsed = urlsplit(run_url)
    expected_path = f"/{repository}/actions/runs/{run_id}"
    if (parsed.scheme != "https" or not parsed.netloc or parsed.username is not None
            or parsed.password is not None or parsed.path.rstrip("/") != expected_path
            or parsed.query or parsed.fragment or len(run_url) > 2048):
        raise BundleError("run URL does not identify the supplied repository and run")


def validate_comparison(data: bytes, outcome: str, incomplete: bool,
                        merge_base: str, head: str) -> str:
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                           parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise BundleError("comparison is not valid bounded UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise BundleError("comparison must be a JSON object")
    schema = value.get("schema_version")
    report_outcome = value.get("outcome")
    report_incomplete = value.get("has_incomplete")
    base = value.get("base")
    candidate = value.get("candidate")
    if (schema != COMPARISON_SCHEMA or value.get("report_kind") != COMPARISON_KIND
            or report_outcome not in OUTCOMES or type(report_incomplete) is not bool
            or not isinstance(base, dict) or not isinstance(candidate, dict)
            or not isinstance(base.get("revision"), str)
            or not isinstance(candidate.get("revision"), str)):
        raise BundleError("comparison schema or required field types are unsupported")
    if (report_outcome != outcome or report_incomplete is not incomplete
            or base["revision"] != merge_base or candidate["revision"] != head):
        raise BundleError("comparison assessment or revisions do not match Action outputs")
    if ((outcome == "CLEAN" and incomplete)
            or (outcome == "INCOMPLETE" and not incomplete)):
        raise BundleError("comparison outcome and incompleteness are inconsistent")
    return schema


def file_record(data: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def encode_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True,
                       allow_nan=False) + "\n").encode("utf-8")


def write_new_file(directory: Path, name: str, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    path = directory / name
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BundleError(f"could not write {name}")
            view = view[written:]
    except BaseException:
        try:
            os.close(descriptor)
        except BaseException:
            pass
        try:
            path.unlink()
        except OSError:
            pass
        raise
    try:
        os.close(descriptor)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def create_bundle(*, report: Path | None, markdown: Path, run_directory: Path,
                  output_directory: Path, outcome: str, incomplete: bool,
                  merge_base: str | None, repository: str, base: str, head: str,
                  run_id: str, run_attempt: int, run_url: str,
                  guide: Path | None = None) -> Path:
    validate_context(repository, base, head, merge_base, run_id, run_attempt, run_url)
    if type(outcome) is not str or type(incomplete) is not bool:
        raise BundleError("outcome and incomplete types are invalid")
    if outcome == "UNKNOWN":
        if not incomplete or report is not None:
            raise BundleError("reportless UNKNOWN bundles require incomplete=true and no comparison")
    elif outcome not in OUTCOMES or merge_base is None or report is None:
        raise BundleError("successful bundles require a supported outcome, merge base, and comparison")

    run_root = regular_directory(run_directory, "run directory")
    markdown_data = read_regular(markdown, MAX_MARKDOWN, "Markdown report")
    try:
        markdown_data.decode("utf-8")
    except UnicodeError as error:
        raise BundleError("Markdown report must be UTF-8") from error
    markdown_parent = markdown.resolve(strict=True).parent

    if report is not None:
        report_data = read_regular(report, MAX_REPORT, "comparison")
        report_parent = report.resolve(strict=True).parent
        if report.name != "comparison.json" or markdown.name != "report.md":
            raise BundleError("successful source files must be named comparison.json and report.md")
        if report_parent != markdown_parent or report_parent.parent != run_root:
            raise BundleError("comparison and Markdown must be sibling outputs directly under the run directory")
        comparison_schema: str | None = validate_comparison(
            report_data, outcome, incomplete, merge_base, head,
        )
        payloads = {"comparison.json": report_data, "report.md": markdown_data}
    else:
        if markdown.name != "report.md" or markdown_parent != run_root:
            raise BundleError("UNKNOWN status Markdown must be report.md directly under the run directory")
        status_markdown = markdown_data.decode("utf-8")
        if (not re.search(r"(?mi)^Outcome:\s*(?:\*\*)?UNKNOWN(?:\*\*)?\s*$", status_markdown)
                or re.search(r"(?mi)^Outcome:\s*(?:\*\*)?CLEAN(?:\*\*)?\s*$", status_markdown)):
            raise BundleError("UNKNOWN status Markdown must explicitly report UNKNOWN without a CLEAN claim")
        comparison_schema = None
        payloads = {"report.md": markdown_data}

    output_parent = output_directory.parent.resolve(strict=True)
    if not output_directory.is_absolute() or output_parent != markdown_parent:
        raise BundleError("output directory must be a fresh sibling of the source outputs")
    if output_directory.exists() or output_directory.is_symlink():
        raise BundleError("output directory already exists")

    guide_path = guide
    if guide_path is None:
        guide_path = Path(__file__).with_name("REPORT-GUIDE.md")
        if not guide_path.is_file():
            guide_path = Path(__file__).with_name("scanner_REPORT_GUIDE.md")
    guide_data = read_regular(guide_path.absolute(), MAX_GUIDE, "report guide")
    try:
        guide_data.decode("utf-8")
    except UnicodeError as error:
        raise BundleError("report guide must be UTF-8") from error
    payloads["REPORT-GUIDE.md"] = guide_data

    provenance = {
        "assessment": {"has_incomplete": incomplete, "outcome": outcome},
        "authentication": "unsigned_action_record",
        "comparison_schema_version": comparison_schema,
        "files": {name: file_record(data) for name, data in sorted(payloads.items())},
        "repository": repository,
        "revisions": {"base": base, "head": head, "merge_base": merge_base},
        "run": {"attempt": run_attempt, "id": run_id, "url": run_url},
        "schema_version": BUNDLE_SCHEMA,
    }
    provenance_data = encode_json(provenance)
    if len(provenance_data) > MAX_PROVENANCE:
        raise BundleError("provenance exceeds its bounded size")
    payloads["provenance.json"] = provenance_data

    created = False
    written: list[Path] = []
    try:
        os.mkdir(output_directory, 0o700)
        created = True
        for name, data in payloads.items():
            write_new_file(output_directory, name, data)
            written.append(output_directory / name)
    except Exception as error:
        for path in reversed(written):
            try:
                path.unlink()
            except OSError:
                pass
        if created:
            try:
                output_directory.rmdir()
            except OSError:
                pass
        if isinstance(error, OSError):
            raise BundleError("could not create fresh report bundle") from error
        raise
    return output_directory


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--report", type=Path)
    value.add_argument("--markdown", required=True, type=Path)
    value.add_argument("--run-directory", required=True, type=Path)
    value.add_argument("--output-directory", required=True, type=Path)
    value.add_argument("--outcome", required=True)
    value.add_argument("--incomplete", required=True, type=parse_incomplete)
    value.add_argument("--merge-base")
    value.add_argument("--repository", required=True)
    value.add_argument("--base", required=True)
    value.add_argument("--head", required=True)
    value.add_argument("--run-id", required=True)
    value.add_argument("--run-attempt", required=True, type=int)
    value.add_argument("--run-url", required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        output = create_bundle(
            report=options.report, markdown=options.markdown,
            run_directory=options.run_directory, output_directory=options.output_directory,
            outcome=options.outcome, incomplete=options.incomplete,
            merge_base=options.merge_base, repository=options.repository,
            base=options.base, head=options.head, run_id=options.run_id,
            run_attempt=options.run_attempt, run_url=options.run_url,
        )
    except (BundleError, OSError, ValueError) as error:
        print(f"counterbranch report bundle: {error}", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
