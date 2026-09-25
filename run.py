#!/usr/bin/env python3
"""Run a Counterbranch project or Discovery comparison and expose its delivered assessment."""

from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import signal
import subprocess
import sys
import tempfile
import threading
import re
import time

OUTCOMES = {"CLEAN", "VIOLATION", "INCOMPLETE", "NEEDS_OWNER_REVIEW"}
REPORT_KIND_TO_ENGINE = {"comparison": "http", "opa_comparison": "opa", "cedar_comparison": "cedar",
                         "openfga_comparison": "openfga", "discovery_coverage_comparison": "discovery"}
SUPPORTED_ENGINES = {"http", "opa", "cedar", "openfga"}
MAX_CAPTURE_BYTES = 64 * 1024
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_VALIDATED_ENVELOPE_BYTES = 16 * 1024 * 1024
MAX_DISCOVERY_REPORT_BYTES = 72 * 1024 * 1024
DISCOVERY_PROFILES = {"default", "large", "xl"}
CLEANUP_GRACE_SECONDS = 180
CAPTURE_DRAIN_SECONDS = 5
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
# GitHub rejects step summaries over 1 MiB; leave room for the heading lines.
MAX_SUMMARY_BODY_BYTES = 960 * 1024


class ActionError(Exception):
    pass


class ActionCancelled(ActionError):
    pass


CANCEL_REQUESTED = threading.Event()


def ensure_not_cancelled() -> None:
    if CANCEL_REQUESTED.is_set():
        raise ActionCancelled("Counterbranch Action was cancelled")


def interrupt_cli(process: subprocess.Popen[bytes], cancelled: bool) -> None:
    try:
        os.killpg(process.pid, signal.SIGINT)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=CLEANUP_GRACE_SECONDS)
    except subprocess.TimeoutExpired as error:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        exception = ActionCancelled if cancelled or CANCEL_REQUESTED.is_set() else ActionError
        raise exception(
            "Counterbranch CLI required forced termination; cleanup is uncertain, inspect resources owned by this run"
        ) from error


def cli_environment() -> dict[str, str]:
    allowed = {"PATH", "HOME", "XDG_CACHE_HOME", "TMPDIR", "LANG", "LC_ALL"}
    environment = {key: value for key, value in os.environ.items() if key in allowed}
    if os.environ.get("COUNTERBRANCH_ACTION_TESTING") == "1":
        environment.update({key: value for key, value in os.environ.items() if key.startswith("FAKE_")})
    return environment


def delivered_run_directory(stdout: bytes, overflow: bool) -> Path:
    if overflow:
        raise ActionError("run directory output exceeds 64 KiB")
    try:
        value = stdout.decode("utf-8")
    except UnicodeError as error:
        raise ActionError("run did not return a UTF-8 directory path") from error
    lines = value.splitlines()
    if len(lines) != 1 or not lines[0] or "\r" in value or "\x00" in value:
        raise ActionError("run did not return exactly one directory path")
    directory = Path(lines[0])
    if not directory.is_absolute():
        raise ActionError("run did not return an absolute directory path")
    return directory


def run_bounded(argv: list[str], timeout: int, stdout_limit: int = MAX_CAPTURE_BYTES) -> tuple[int, bytes, bool, bool]:
    ensure_not_cancelled()
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            env=cli_environment(),
        )
    except OSError as error:
        raise ActionError("could not start the Counterbranch CLI") from error

    captures = [bytearray(), bytearray()]
    overflow = [False, False]

    def drain(stream: object, capture: bytearray, limit: int, index: int) -> None:
        while True:
            try:
                chunk = os.read(stream.fileno(), 8192)  # type: ignore[attr-defined]
            except OSError:
                return
            if not chunk:
                return
            remaining = limit - len(capture)
            if remaining > 0:
                capture.extend(chunk[:remaining])
            if len(chunk) > remaining:
                overflow[index] = True

    threads = [
        threading.Thread(target=drain, args=(process.stdout, captures[0], stdout_limit, 0), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, captures[1], MAX_CAPTURE_BYTES, 1), daemon=True),
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        deadline = time.monotonic() + timeout
        while True:
            if CANCEL_REQUESTED.is_set():
                interrupt_cli(process, cancelled=True)
                raise ActionCancelled("Counterbranch Action was cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                interrupt_cli(process, cancelled=False)
                status = process.returncode
                timed_out = True
                break
            try:
                status = process.wait(timeout=min(remaining, 0.2))
                break
            except subprocess.TimeoutExpired:
                continue
    finally:
        for thread in threads:
            thread.join(timeout=CAPTURE_DRAIN_SECONDS)
        if any(thread.is_alive() for thread in threads):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
            for thread in threads:
                thread.join(timeout=CAPTURE_DRAIN_SECONDS)
            exception = ActionCancelled if CANCEL_REQUESTED.is_set() else ActionError
            if any(thread.is_alive() for thread in threads):
                raise exception("Counterbranch CLI descendant cleanup is uncertain")
            raise exception("Counterbranch CLI descendants retained output streams after the command exited")
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
    ensure_not_cancelled()
    return status, bytes(captures[0]), overflow[0], timed_out


def write_github_file(variable: str, lines: list[str]) -> None:
    filename = os.environ.get(variable)
    if not filename:
        raise ActionError(f"{variable} is unavailable")
    try:
        with open(filename, "a", encoding="utf-8") as destination:
            destination.write("\n".join(lines) + "\n")
    except OSError as error:
        raise ActionError(f"cannot write {variable}") from error


def emit(outcome: str, incomplete: bool, engine: str, directory: Path | None, detail: str,
         report: Path | None = None, markdown: Path | None = None, bodies: tuple[Path, ...] = ()) -> None:
    output_lines = [f"outcome={outcome}", f"has_incomplete={str(incomplete).lower()}", f"engine={engine}"]
    if directory is not None:
        output_lines.extend([
            f"report={report or directory / 'comparison.json'}",
            f"markdown_report={markdown or directory / 'comparison.md'}",
            f"run_directory={directory}",
        ])
        revisions = directory / "revisions.json"
        if revisions.is_file():
            output_lines.append(f"revisions={revisions}")
    write_github_file("GITHUB_OUTPUT", output_lines)
    summary = [
        "## Counterbranch", "",
        f"Outcome: **{outcome}**",
        f"Incomplete: **{str(incomplete).lower()}**",
        f"Engine: **{engine}**",
        "", detail,
    ]
    remaining = MAX_SUMMARY_BODY_BYTES
    for body in bodies:
        try:
            size = body.stat().st_size
            if size > remaining:
                summary += ["", f"`{body.name}` exceeds the job summary size limit; read it from the run directory."]
            else:
                summary += ["", body.read_text(encoding="utf-8")]
                remaining -= size
        except (OSError, UnicodeError):
            summary += ["", f"`{body.name}` could not be read into the job summary."]
    write_github_file("GITHUB_STEP_SUMMARY", summary)


def validate_report(binary: Path, report: Path, timeout: int,
                    revisions: tuple[str, str] | None = None) -> tuple[str, bool, str]:
    """Validate through the CLI; `revisions` selects the Discovery contract and its exact pair."""
    ensure_not_cancelled()
    limit = MAX_DISCOVERY_REPORT_BYTES if revisions else MAX_REPORT_BYTES
    envelope_limit = 2 * limit if revisions else MAX_VALIDATED_ENVELOPE_BYTES
    if not report.is_file():
        raise ActionError("comparison did not create a report")
    try:
        if report.stat().st_size > limit:
            raise ActionError(f"saved report exceeds {limit >> 20} MiB")
    except OSError as error:
        raise ActionError("saved report could not be inspected") from error
    status, rendered, overflow, timed_out = run_bounded(
        [str(binary), "report", "--input", str(report), "--format", "json"],
        timeout,
        envelope_limit,
    )
    if overflow:
        raise ActionError(f"validated report envelope exceeds {envelope_limit >> 20} MiB")
    if timed_out:
        raise ActionError("saved report validation timed out")
    if status != 0:
        raise ActionError("saved report failed Counterbranch validation")
    try:
        envelope = json.loads(rendered)
        if envelope["authentication"] != "unauthenticated_import":
            raise ActionError("validated report has an unsupported authentication label")
        outcome = envelope["report"]["outcome"]
        incomplete = envelope["report"]["has_incomplete"]
        report_kind = envelope["report"].get("report_kind", "comparison")
        pair = revisions and (envelope["report"]["base"]["revision"], envelope["report"]["candidate"]["revision"])
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, AttributeError) as error:
        raise ActionError("validated report could not be read") from error
    if not isinstance(outcome, str) or outcome not in OUTCOMES or not isinstance(incomplete, bool):
        raise ActionError("validated report has an unsupported assessment")
    engine = REPORT_KIND_TO_ENGINE.get(report_kind) if isinstance(report_kind, str) else None
    if engine is None or (engine == "discovery") != bool(revisions):
        raise ActionError("validated report has an unsupported report kind")
    if revisions and (pair != revisions or outcome == "VIOLATION"):
        raise ActionError("validated Discovery comparison has an unexpected revision pair or outcome")
    return outcome, incomplete, engine


def discovery_delivery(directory: Path, head: str) -> tuple[Path, Path]:
    """Return the only pair's comparison.json and report.md; a FAILED pair has none."""
    if not (directory / "index.md").is_file():
        raise ActionError("discovery did not deliver index.md")
    comparisons = list(directory.glob("*/comparison.json"))
    if len(comparisons) != 1 or comparisons[0].parent.name != head[:12]:
        raise ActionError("discovery did not deliver exactly one comparison for the requested pair")
    report, markdown = comparisons[0], comparisons[0].with_name("report.md")
    if not markdown.is_file():
        raise ActionError("discovery did not deliver report.md")
    if report.stat().st_size == 0 or not 0 < markdown.stat().st_size <= MAX_DISCOVERY_REPORT_BYTES:
        raise ActionError("discovery delivered an empty or oversized report")
    return report, markdown


def validate_revisions(directory: Path, repository: str, base: str, head: str,
                       engine: str) -> None:
    path = directory / "revisions.json"
    if not path.is_file():
        raise ActionError("automatic comparison did not create revisions.json")
    try:
        if path.stat().st_size < 2 or path.stat().st_size > MAX_REPORT_BYTES:
            raise ActionError("revisions.json is empty or exceeds 8 MiB")
        revisions = json.loads(path.read_bytes())
        if (revisions["schema_version"] != 1 or revisions["engine"] != engine
                or engine not in {"opa", "cedar", "openfga"}
                or revisions["repository"] != str(Path(repository).resolve())
                or not isinstance(revisions["git"], str) or not Path(revisions["git"]).is_absolute()):
            raise ActionError("revisions.json has an unsupported execution identity")
        sides = (("base", base), ("candidate", head))
        for name, commit in sides:
            side = revisions[name]
            if (not isinstance(side, dict) or side.get("ref") != commit
                    or side.get("commit") != commit or not isinstance(side.get("label"), str)
                    or not side["label"]):
                raise ActionError("revisions.json has an incomplete revision identity")
            identities = side.get("models") if engine == "openfga" else side.get("policies")
            if not isinstance(identities, list) or (engine == "openfga" and len(identities) != 1):
                raise ActionError("revisions.json has an incomplete revision identity")
            for policy in identities:
                if not isinstance(policy, dict):
                    raise ActionError("revisions.json has an invalid policy identity")
                policy_path = policy.get("path")
                if (not isinstance(policy_path, str) or not policy_path
                        or PurePosixPath(policy_path).is_absolute() or "\\" in policy_path
                        or any(part in ("", ".", "..") for part in PurePosixPath(policy_path).parts)
                        or not isinstance(policy.get("blob"), str)
                        or not COMMIT_RE.fullmatch(policy["blob"])
                        or not isinstance(policy.get("size"), int) or isinstance(policy["size"], bool)
                        or policy["size"] < 0 or not isinstance(policy.get("sha256"), str)
                        or not re.fullmatch(r"[0-9a-f]{64}", policy["sha256"])):
                    raise ActionError("revisions.json has an invalid policy identity")
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ActionError("revisions.json could not be validated") from error


def cancelled_result(error: BaseException) -> int:
    try:
        emit("UNKNOWN", True, "unknown", None, "Assessment execution was cancelled.")
    except ActionError:
        pass
    print(f"counterbranch action: {error}", file=sys.stderr)
    return 1


def _main() -> int:
    directory: Path | None = None
    report: Path | None = None
    binary: Path | None = None
    timeout: int | None = None
    repository = ""
    discovery = False
    try:
        ensure_not_cancelled()
        binary = Path(os.environ.get("COUNTERBRANCH_ACTION_BINARY", ""))
        if not binary.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
            raise ActionError("binary must be an absolute path to an executable file")
        try:
            timeout = int(os.environ.get("COUNTERBRANCH_ACTION_TIMEOUT_SECONDS", "900"))
        except ValueError as error:
            raise ActionError("timeout-seconds must be an integer") from error
        if timeout < 1 or timeout > 3600:
            raise ActionError("timeout-seconds must be between 1 and 3600")
        requested_engine = os.environ.get("COUNTERBRANCH_ACTION_ENGINE", "")
        if requested_engine and requested_engine not in SUPPORTED_ENGINES:
            raise ActionError("engine must be one of http, opa, cedar, openfga")
        discovery = os.environ.get("COUNTERBRANCH_ACTION_DISCOVERY", "false")
        profile = os.environ.get("COUNTERBRANCH_ACTION_PROFILE", "")
        if discovery not in ("true", "false"):
            raise ActionError("discovery must be true or false")
        discovery = discovery == "true"
        if profile and (not discovery or profile not in DISCOVERY_PROFILES):
            raise ActionError("profile must be default, large or xl and requires discovery")
        repository = os.environ.get("COUNTERBRANCH_ACTION_REPOSITORY", "")
        config = os.environ.get("COUNTERBRANCH_ACTION_CONFIG", "")
        archive = os.environ.get("COUNTERBRANCH_ACTION_CLI_ARCHIVE", "")
        input_binary = os.environ.get("COUNTERBRANCH_ACTION_INPUT_BINARY", "")
        base = os.environ.get("COUNTERBRANCH_ACTION_BASE", "")
        head = os.environ.get("COUNTERBRANCH_ACTION_HEAD", "")
        selectors = os.environ.get("COUNTERBRANCH_ACTION_SELECT", "")
        if bool(repository) == bool(config):
            raise ActionError("provide exactly one of config or repository/base/head")
        if config and archive:
            raise ActionError("config/binary and archive/repository modes are mutually exclusive")
        if discovery and (not repository or any((archive, input_binary, selectors, requested_engine))):
            raise ActionError("discovery requires repository/base/head and rejects binary, config, select and engine")
        if repository and not archive and not discovery:
            raise ActionError("automatic repository mode requires cli-archive")
        if repository and input_binary:
            raise ActionError("config/binary and archive/repository modes are mutually exclusive")
        if config and any((base, head, selectors)):
            raise ActionError("config/binary and archive/repository modes are mutually exclusive")
        if repository:
            values = {"repository": repository, "base": base, "head": head}
            if any(not value or "\n" in value or "\r" in value or "\x00" in value
                   for value in values.values()):
                raise ActionError("repository, base, and head must be nonempty and contain no control line breaks")
            if not COMMIT_RE.fullmatch(base) or not COMMIT_RE.fullmatch(head):
                raise ActionError("base and head must be exact lowercase 40-character commit IDs")
            argv = [str(binary), "run", "--repository", repository, "--base", base, "--head", head]
            if discovery:
                directory = Path(tempfile.mkdtemp(prefix="counterbranch-discovery-",
                                                  dir=os.environ.get("RUNNER_TEMP") or None)) / "discovery"
                argv[1:2] = ["discovery"]
                argv += ["--output-dir", str(directory)] + (["--profile", profile] if profile else [])
            if "\r" in selectors or "\x00" in selectors:
                raise ActionError("select must contain newline-separated repository-relative paths")
            for selector in selectors.splitlines():
                path = PurePosixPath(selector)
                if (not selector or str(path) != selector or path.is_absolute() or "\\" in selector
                        or any(part in ("", ".", "..") for part in path.parts)):
                    raise ActionError("select must contain repository-relative paths")
                argv.extend(["--select", selector])
        else:
            if not config or "\n" in config or "\r" in config:
                raise ActionError("config must be a nonempty path without line breaks")
            if os.environ.get("COUNTERBRANCH_ACTION_SELECT", ""):
                raise ActionError("select is supported only with repository/base/head")
            argv = [str(binary), "run", "--config", config]
        status, stdout, overflow, timed_out = run_bounded(argv, timeout)
        ensure_not_cancelled()
        if discovery:
            if status != 0 or timed_out:
                reason = "timed out" if timed_out else f"failed with exit status {status}"
                raise ActionError(f"discovery {reason}")
            report, markdown = discovery_delivery(directory, head)
            outcome, incomplete, engine = validate_report(binary, report, timeout, (base, head))
            ensure_not_cancelled()
            emit(outcome, incomplete, engine, directory,
                 "The saved report is unauthenticated, static Discovery evidence. Its assessment is advisory; delivery does not establish a passing result.",
                 # index.md carries per-side notes, such as cleanup errors, absent from report.md.
                 report, markdown, (markdown, directory / "index.md"))
            return 0
        directory = delivered_run_directory(stdout, overflow)
        report = directory / "comparison.json"
        markdown = directory / "comparison.md"
        if not markdown.is_file():
            raise ActionError("run did not deliver comparison.md")
        if report.stat().st_size == 0 or markdown.stat().st_size == 0:
            raise ActionError("run delivered an empty report")
        if markdown.stat().st_size > MAX_REPORT_BYTES:
            raise ActionError("saved Markdown report exceeds 8 MiB")
        outcome, incomplete, engine = validate_report(binary, report, timeout)
        ensure_not_cancelled()
        if repository:
            validate_revisions(directory, repository, base, head, engine)
        if requested_engine and engine != requested_engine:
            # Deliberately does not raise into the `except` block below:
            # that block re-validates the saved report (a second CLI
            # invocation) to recover an outcome/incomplete/engine it
            # already has here, and this mismatch is not itself a failure
            # of report validation.
            emit(
                outcome,
                incomplete,
                engine,
                directory,
                "The saved report is unauthenticated. Its assessment was preserved, but the delivered report's engine did not match the requested engine.",
            )
            print(
                f"counterbranch action: delivered report engine {engine} does not match the requested engine {requested_engine}",
                file=sys.stderr,
            )
            return 1
        if status != 0 or timed_out:
            emit(outcome, incomplete, engine, directory, "The saved report is unauthenticated. Its assessment was preserved, but project execution failed.")
            reason = "timed out" if timed_out else f"failed with exit status {status}"
            print(f"counterbranch action: project execution {reason}", file=sys.stderr)
            return 1
        ensure_not_cancelled()
        emit(outcome, incomplete, engine, directory, "The saved report is unauthenticated. Its assessment is advisory; delivery does not establish a passing result.")
        return 0
    except ActionCancelled as error:
        return cancelled_result(error)
    except (ActionError, OSError) as error:
        if CANCEL_REQUESTED.is_set():
            return cancelled_result(error)
        try:
            index = directory / "index.md" if discovery and directory is not None else None
            if index is not None and index.is_file():
                # A FAILED or interrupted pair still explains itself in index.md.
                write_github_file("GITHUB_OUTPUT", [f"run_directory={directory}"])
                emit("UNKNOWN", True, "unknown", None, "Discovery execution or validation failed.", bodies=(index,))
            elif (not repository and binary is not None and timeout is not None and directory is not None
                    and report is not None and report.is_file()
                    and (directory / "comparison.md").is_file()
                    and 0 < (directory / "comparison.md").stat().st_size <= MAX_REPORT_BYTES):
                outcome, incomplete, engine = validate_report(binary, report, timeout)
                emit(outcome, incomplete, engine, directory, "The saved report is unauthenticated. Its assessment was preserved, but project execution failed.")
            else:
                emit("UNKNOWN", True, "unknown", None, "Assessment execution or validation failed.")
        except (ActionError, OSError):
            try:
                emit("UNKNOWN", True, "unknown", None, "Assessment execution or validation failed.")
            except ActionError:
                pass
        print(f"counterbranch action: {error}", file=sys.stderr)
        return 1


def main() -> int:
    CANCEL_REQUESTED.clear()
    previous = {item: signal.getsignal(item) for item in (signal.SIGTERM, signal.SIGINT)}
    for item in previous:
        signal.signal(item, lambda _signal, _frame: CANCEL_REQUESTED.set())
    try:
        return _main()
    finally:
        for item, handler in previous.items():
            signal.signal(item, handler)


if __name__ == "__main__":
    raise SystemExit(main())
