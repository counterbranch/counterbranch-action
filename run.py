#!/usr/bin/env python3
"""Run one bounded scanner-only static comparison in a checked-out Git repository."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading


COMMIT_RE = re.compile(r"[0-9a-f]{40}")
PROFILES = {"", "default", "large", "xl"}
OUTCOMES = {"CLEAN", "INCOMPLETE", "NEEDS_OWNER_REVIEW"}
MAX_CAPTURE = 8 * 1024 * 1024
MAX_REPORT = 72 * 1024 * 1024
MAX_REPORT_CAPTURE = MAX_REPORT + 1024 * 1024
MAX_MARKDOWN = 8 * 1024 * 1024
MAX_TOKEN = 4096


class ActionError(Exception):
    pass


def child_environment() -> dict[str, str]:
    allowed = {"PATH", "HOME", "TMPDIR", "TEMP", "TMP", "XDG_CACHE_HOME", "LANG", "LC_ALL"}
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    environment.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                        "GIT_CONFIG_COUNT": "0", "GIT_TERMINAL_PROMPT": "0"})
    return environment


def run(command: list[str], timeout: int, cwd: str | None = None,
        stdout_limit: int = MAX_CAPTURE, stderr_limit: int = MAX_CAPTURE) -> tuple[int, bytes, bytes]:
    try:
        process = subprocess.Popen(
            command, cwd=cwd, env=child_environment(), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
    except OSError as error:
        raise ActionError(f"{Path(command[0]).name} execution could not start") from error
    captures = [bytearray(), bytearray()]
    overflow = [False, False]

    def drain(stream, destination: bytearray, limit: int, index: int) -> None:
        while chunk := stream.read(64 * 1024):
            remaining = limit - len(destination)
            if remaining > 0:
                destination.extend(chunk[:remaining])
            if len(chunk) > remaining:
                overflow[index] = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    try:
                        process.kill()
                    except OSError:
                        pass

    readers = [threading.Thread(target=drain, args=(process.stdout, captures[0], stdout_limit, 0), daemon=True),
               threading.Thread(target=drain, args=(process.stderr, captures[1], stderr_limit, 1), daemon=True)]
    for reader in readers:
        reader.start()
    try:
        status = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            process.kill()
        process.wait()
        raise ActionError(f"{Path(command[0]).name} execution timed out") from error
    finally:
        for reader in readers:
            reader.join(timeout=2)
        if any(reader.is_alive() for reader in readers):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            for reader in readers:
                reader.join(timeout=2)
        process.stdout.close(); process.stderr.close()
    if any(reader.is_alive() for reader in readers):
        raise ActionError(f"{Path(command[0]).name} output could not be drained")
    if any(overflow):
        raise ActionError(f"{Path(command[0]).name} output exceeds its bounded capture limit")
    return status, bytes(captures[0]), bytes(captures[1])


def merge_base(repository: str, base: str, head: str, timeout: int) -> str:
    status, shallow, _ = run(["git", "rev-parse", "--is-shallow-repository"], timeout, repository)
    if status != 0 or shallow != b"false\n":
        raise ActionError("repository must be a non-shallow checkout with full base and head history")
    status, output, _ = run(["git", "merge-base", "--all", base, head], timeout, repository)
    try:
        values = output.decode("ascii").splitlines()
    except UnicodeError as error:
        raise ActionError("git merge-base returned invalid output") from error
    if status != 0 or len(values) != 1 or not COMMIT_RE.fullmatch(values[0]):
        raise ActionError("base and head must have exactly one available merge base")
    return values[0]


def write_lines(variable: str, lines: list[str]) -> None:
    destination = os.environ.get(variable)
    if not destination:
        raise ActionError(f"{variable} is unavailable")
    with open(destination, "a", encoding="utf-8") as stream:
        for line in lines:
            if "\n" in line or "\r" in line:
                raise ActionError("output contains a line break")
            stream.write(line + "\n")


def emit_unknown(message: str) -> None:
    write_lines("GITHUB_OUTPUT", ["outcome=UNKNOWN", "has_incomplete=true"])
    write_lines("GITHUB_STEP_SUMMARY", ["## Counterbranch static comparison", "", "Outcome: **UNKNOWN**", "", message])


def validate_gate() -> None:
    mode = os.environ.get("COUNTERBRANCH_ACTION_ACCESS_MODE", "gated")
    token = os.environ.get("COUNTERBRANCH_ACTION_SIGNUP_TOKEN", "")
    if len(token.encode("utf-8")) > MAX_TOKEN or any(character in token for character in "\r\n\x00"):
        raise ActionError("signup token is invalid")
    if mode == "gated":
        raise ActionError("signup validation is unavailable; this gated Action cannot run")
    if mode != "open":
        raise ActionError("Action access mode is invalid")
    if token:
        raise ActionError("signup token is not accepted while the Action is configured open")


def validate_release_manifest(path: Path) -> None:
    try:
        if not path.is_file() or not 0 < path.stat().st_size <= 1024 * 1024:
            raise ActionError("release manifest is missing, empty, or oversized")
        def object_pairs(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ActionError("release manifest contains duplicate fields")
                value[key] = item
            return value
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=object_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ActionError("release manifest is invalid") from error
    if not isinstance(value, dict) or type(value.get("format")) is not int \
            or value.get("format") != 2 or value.get("edition") != "scanner-only":
        raise ActionError("release manifest is not a scanner-only format 2 manifest")
    if value.get("status") != "approved":
        raise ActionError("release publisher trust is not approved")
    if set(value) != {"format", "edition", "status", "repository", "tag", "version", "kits",
                      "core_source", "discovery_source"}:
        raise ActionError("approved release manifest fields are invalid")


def validate_report(binary: Path, report: Path, base: str, head: str, timeout: int) -> tuple[str, bool]:
    if not report.is_file() or not 0 < report.stat().st_size <= MAX_REPORT:
        raise ActionError("Discovery comparison is missing, empty, or oversized")
    status, output, _ = run([str(binary), "report", "--input", str(report), "--format", "json"],
                            timeout, stdout_limit=MAX_REPORT_CAPTURE)
    if status != 0:
        raise ActionError("saved comparison failed Counterbranch validation")
    try:
        envelope = json.loads(output)
        value = envelope["report"]
        outcome = value["outcome"]
        incomplete = value["has_incomplete"]
        revisions = (value["base"]["revision"], value["candidate"]["revision"])
        kind = value["report_kind"]
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ActionError("validated comparison has an invalid envelope") from error
    if (outcome not in OUTCOMES or not isinstance(incomplete, bool)
            or kind != "discovery_coverage_comparison" or revisions != (base, head)
            or (outcome == "INCOMPLETE" and not incomplete)
            or (outcome == "CLEAN" and incomplete)):
        raise ActionError("validated comparison has an unsupported assessment")
    return outcome, incomplete


def main() -> int:
    try:
        validate_gate()
        binary = Path(os.environ.get("COUNTERBRANCH_ACTION_BINARY", ""))
        repository = os.environ.get("COUNTERBRANCH_ACTION_REPOSITORY", "")
        base = os.environ.get("COUNTERBRANCH_ACTION_BASE", "")
        head = os.environ.get("COUNTERBRANCH_ACTION_HEAD", "")
        profile = os.environ.get("COUNTERBRANCH_ACTION_PROFILE", "")
        try:
            timeout = int(os.environ.get("COUNTERBRANCH_ACTION_TIMEOUT_SECONDS", "1800"))
        except ValueError as error:
            raise ActionError("timeout-seconds must be an integer") from error
        if not binary.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
            raise ActionError("scanner binary must be an absolute executable file")
        discovery = binary.with_name("discovery")
        discovery_manifest = binary.parent.parent / "share/counterbranch/discovery-artifact.json"
        if (not discovery.is_file() or not os.access(discovery, os.X_OK)
                or not discovery_manifest.is_file()):
            raise ActionError("authenticated kit is missing its scanner or scanner manifest")
        if (not os.path.isabs(repository) or any(not COMMIT_RE.fullmatch(item) for item in (base, head))
                or profile not in PROFILES or not 1 <= timeout <= 3600):
            raise ActionError("repository, revisions, profile, or timeout is invalid")
        tested_base = merge_base(repository, base, head, min(timeout, 120))
        workspace = Path(tempfile.mkdtemp(prefix="counterbranch-static-", dir=os.environ.get("RUNNER_TEMP")))
        directory = workspace / "discovery"
        command = [str(binary), "discovery", "--repository", repository, "--base", tested_base,
                   "--head", head, "--scanner", str(discovery), "--scanner-manifest",
                   str(discovery_manifest), "--output-dir", str(directory)]
        if profile:
            command += ["--profile", profile]
        status, _, _ = run(command, timeout)
        if status != 0:
            raise ActionError(f"static Discovery comparison failed with exit status {status}")
        comparisons = list(directory.glob("*/comparison.json"))
        if len(comparisons) != 1 or not (directory / "index.md").is_file():
            raise ActionError("Discovery did not deliver exactly one indexed comparison")
        report = comparisons[0]
        markdown = report.with_name("report.md")
        if not markdown.is_file() or not 0 < markdown.stat().st_size <= MAX_MARKDOWN:
            raise ActionError("Discovery Markdown report is missing, empty, or oversized")
        outcome, incomplete = validate_report(binary, report, tested_base, head, min(timeout, 120))
        write_lines("GITHUB_OUTPUT", [f"outcome={outcome}", f"has_incomplete={str(incomplete).lower()}",
                    f"report={report}", f"markdown_report={markdown}", f"run_directory={directory}",
                    f"merge_base={tested_base}"])
        write_lines("GITHUB_STEP_SUMMARY", ["## Counterbranch static comparison", "",
                    f"Outcome: **{outcome}**", "",
                    "This is unauthenticated static evidence; it does not establish application behavior.", "",
                    *markdown.read_text(encoding="utf-8").splitlines()])
        return 0
    except (ActionError, OSError, UnicodeError) as error:
        try:
            emit_unknown("Static comparison execution or validation failed.")
        except (ActionError, OSError):
            pass
        print(f"counterbranch action: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--preflight":
        try:
            validate_gate()
            validate_release_manifest(Path(sys.argv[2]))
        except (ActionError, OSError, UnicodeError) as error:
            print(f"counterbranch action preflight: {error}", file=sys.stderr)
            raise SystemExit(1)
        raise SystemExit(0)
    raise SystemExit(main())
