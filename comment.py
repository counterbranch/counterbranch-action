#!/usr/bin/env python3
"""Publish one bounded, commit-bound scanner comparison comment on a pull request."""

from __future__ import annotations

import argparse
import html
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


SCHEMA = "counterbranch-discovery-comparison/3"
REPORT_KIND = "discovery_coverage_comparison"
MARKER = "<!-- counterbranch:scanner-action:v1 -->"
RUN_MARKER = re.compile(
    r"<!-- counterbranch:scanner-action-run:v1 run=([1-9][0-9]*) attempt=([1-9][0-9]*) "
    r"base=([0-9a-f]{40}) head=([0-9a-f]{40}) -->"
)
COMMIT = re.compile(r"[0-9a-f]{40}")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
OUTCOMES = {"CLEAN", "INCOMPLETE", "NEEDS_OWNER_REVIEW"}
MAX_EVENT_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 72 * 1024 * 1024
MAX_API_BYTES = 2 * 1024 * 1024
MAX_COMMENT_BYTES = 48 * 1024
MAX_COMMENT_PAGES = 5
MAX_FINDINGS = 5
MAX_UNMODELLED_PATHS = 256
MAX_CONSTRUCTS_PER_PATH = 64
MAX_METADATA_TEXT = 512
API_TIMEOUT_SECONDS = 20
BOT_LOGIN = "github-actions[bot]"


class CommentError(RuntimeError):
    """A safe, user-facing comment publication failure."""


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def parse_json(data: bytes, label: str) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise CommentError(f"{label} is not strict JSON") from error


def read_bounded(path: Path, limit: int, label: str) -> bytes:
    try:
        if not path.is_file() or path.is_symlink():
            raise CommentError(f"{label} is not a regular file")
        size = path.stat().st_size
        if size > limit:
            raise CommentError(f"{label} exceeds the size limit")
        data = path.read_bytes()
    except OSError as error:
        raise CommentError(f"{label} could not be read") from error
    if len(data) != size:
        raise CommentError(f"{label} changed while it was read")
    return data


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CommentError(f"{label} must be an object")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise CommentError(f"{label} must be an array")
    return value


def require_string(value: Any, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or any(c in value for c in "\r\n\x00"):
        raise CommentError(f"{label} must be a bounded single-line string")
    return value


def require_commit(value: Any, label: str) -> str:
    value = require_string(value, label, 40)
    if not COMMIT.fullmatch(value):
        raise CommentError(f"{label} must be an exact lowercase commit")
    return value


def require_positive(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CommentError(f"{label} must be a positive integer")
    return value


def require_count(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CommentError(f"{label} must be a non-negative integer")
    return value


def require_bool_text(value: str, label: str) -> bool:
    if value not in ("true", "false"):
        raise CommentError(f"{label} must be true or false")
    return value == "true"


def safe_path(value: Any, label: str) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 512
            or len(value.encode("utf-8")) > 2048 or value.startswith(("/", "\\"))
            or any(ord(character) < 32 or 127 <= ord(character) <= 159
                   for character in value)):
        raise CommentError(f"{label} must be a repository-relative path")
    parts = re.split(r"[/\\\\]", value)
    if any(part in ("", ".", "..") or part.endswith(":") for part in parts):
        raise CommentError(f"{label} must be a repository-relative path")
    return value


def safe_line(value: Any, label: str) -> int:
    return require_positive(value, label)


def md(value: Any, maximum: int = 160) -> str:
    text = value if isinstance(value, str) else "unknown"
    text = " ".join(text.split())
    if len(text) > maximum:
        text = text[:maximum - 1].rstrip() + "…"
    special = "@`|[]()!*_~#>\\"
    return "".join(f"&#{ord(character)};" if character in special
                   else html.escape(character, quote=False) for character in text)


def mermaid(value: Any, maximum: int = 96) -> str:
    text = value if isinstance(value, str) else "unknown"
    text = " ".join(text.split())
    if len(text) > maximum:
        text = text[:maximum - 1].rstrip() + "…"
    text = re.sub(r"[\[\]{}()<>`|@\"']", " ", text)
    return " ".join(text.split()) or "unknown"


def commit_url(repository: str, revision: str) -> str:
    return f"https://github.com/{repository}/commit/{revision}"


def blob_url(repository: str, revision: str, path: str, line: int) -> str:
    return (f"https://github.com/{repository}/blob/{revision}/"
            f"{quote(path, safe='/-._~')}#L{line}")


def run_url(repository: str, run_id: int, attempt: int) -> str:
    return f"https://github.com/{repository}/actions/runs/{run_id}/attempts/{attempt}"


def validate_artifact_url(value: str, repository: str, run_id: int) -> str | None:
    if not value:
        return None
    expected = re.compile(
        rf"https://github\.com/{re.escape(repository)}/actions/runs/{run_id}/artifacts/[1-9][0-9]*"
    )
    if len(value) > 512 or expected.fullmatch(value) is None:
        raise CommentError("report artifact URL does not match this repository and workflow run")
    return value


def validate_event(event_name: str, event_path: Path, repository: str,
                   expected_base: str, expected_head: str) -> tuple[dict[str, Any] | None, str | None]:
    if event_name != "pull_request":
        return None, f"event {event_name!r} is not the supported pull_request event"
    event = require_object(parse_json(read_bounded(event_path, MAX_EVENT_BYTES, "event"), "event"), "event")
    event_repository = require_object(event.get("repository"), "event.repository")
    if require_string(event_repository.get("full_name"), "event.repository.full_name") != repository:
        raise CommentError("event repository does not match GITHUB_REPOSITORY")
    repository_id = require_positive(event_repository.get("id"), "event.repository.id")
    pull = require_object(event.get("pull_request"), "event.pull_request")
    number = require_positive(event.get("number"), "event.number")
    base = require_object(pull.get("base"), "event.pull_request.base")
    head = require_object(pull.get("head"), "event.pull_request.head")
    base_repo = require_object(base.get("repo"), "event.pull_request.base.repo")
    head_repo = require_object(head.get("repo"), "event.pull_request.head.repo")
    base_repo_id = require_positive(base_repo.get("id"), "event.pull_request.base.repo.id")
    head_repo_id = require_positive(head_repo.get("id"), "event.pull_request.head.repo.id")
    if base_repo_id != repository_id or head_repo_id != repository_id:
        return None, "fork pull requests are not supported by the initial comment publisher"
    base_sha = require_commit(base.get("sha"), "event.pull_request.base.sha")
    head_sha = require_commit(head.get("sha"), "event.pull_request.head.sha")
    if (base_sha, head_sha) != (expected_base, expected_head):
        raise CommentError("Action inputs do not match the pull request event commits")
    return {
        "repository": repository,
        "repository_id": repository_id,
        "number": number,
        "base": base_sha,
        "head": head_sha,
        "base_ref": require_string(base.get("ref"), "event.pull_request.base.ref", 255),
        "head_ref": require_string(head.get("ref"), "event.pull_request.head.ref", 255),
    }, None


def validate_summary(value: Any, fields: tuple[str, ...], label: str) -> dict[str, int]:
    summary = require_object(value, label)
    return {field: require_count(summary.get(field), f"{label}.{field}") for field in fields}


def require_metadata_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_METADATA_TEXT:
        raise CommentError(f"{label} must be bounded metadata text")
    if any(ord(character) < 32 and character not in "\n\r\t" for character in value) \
            or any(127 <= ord(character) <= 159 for character in value):
        raise CommentError(f"{label} must be bounded metadata text")
    return value


def display_metadata_text(value: Any) -> str | None:
    """Return valid producer metadata for display, without rejecting the report."""
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_METADATA_TEXT:
        return None
    if any(ord(character) < 32 and character not in "\n\r\t" for character in value) \
            or any(127 <= ord(character) <= 159 for character in value):
        return None
    return value


def validate_limitations(value: Any, label: str) -> list[str]:
    limitations = require_list(value, label)
    if len(limitations) > 32:
        raise CommentError(f"{label} exceeds its bound")
    return [require_string(item, f"{label}[{index}]", MAX_METADATA_TEXT)
            for index, item in enumerate(limitations)]


def limitation_summary(values: list[str]) -> str:
    shown = "; ".join(md(value) for value in values[:3])
    extra = max(0, len(values) - 3)
    if extra:
        shown += f"; and {extra} more in the report"
    return shown or "no explanation was retained"


def validate_unmodelled(value: Any) -> dict[str, Any]:
    changes = require_object(value, "report.unmodelled_changes")
    paths = require_list(changes.get("paths"), "report.unmodelled_changes.paths")
    if len(paths) > MAX_UNMODELLED_PATHS:
        raise CommentError("report.unmodelled_changes.paths exceeds its bound")
    omitted = require_count(changes.get("omitted", 0), "report.unmodelled_changes.omitted")
    truncated = changes.get("unmodelled_truncated", False)
    if type(truncated) is not bool:
        raise CommentError("report.unmodelled_changes.unmodelled_truncated must be a boolean")
    languages = require_list(changes.get("unmapped_languages", []),
                             "report.unmodelled_changes.unmapped_languages")
    if len(languages) > MAX_UNMODELLED_PATHS:
        raise CommentError("report.unmodelled_changes.unmapped_languages exceeds its bound")
    checked_languages = [
        require_metadata_text(language, f"report.unmodelled_changes.unmapped_languages[{index}]")
        for index, language in enumerate(languages)
    ]
    if checked_languages != sorted(set(checked_languages)):
        raise CommentError("report.unmodelled_changes.unmapped_languages must be sorted and unique")

    checked_paths = []
    for index, item in enumerate(paths):
        label = f"report.unmodelled_changes.paths[{index}]"
        item = require_object(item, label)
        path = safe_path(item.get("path"), f"{label}.path")
        constructs = require_list(item.get("constructs", []), f"{label}.constructs")
        if len(constructs) > MAX_CONSTRUCTS_PER_PATH:
            raise CommentError(f"{label}.constructs exceeds its bound")
        checked_constructs = [
            require_metadata_text(construct, f"{label}.constructs[{construct_index}]")
            for construct_index, construct in enumerate(constructs)
        ]
        if checked_constructs != sorted(set(checked_constructs)):
            raise CommentError(f"{label}.constructs must be sorted and unique")
        language = item.get("no_adapter_language")
        if language is not None:
            language = require_metadata_text(language, f"{label}.no_adapter_language")
        if not checked_constructs and language is None:
            raise CommentError(f"{label} must retain a construct or no-adapter language")
        checked_paths.append({"path": path, "constructs": checked_constructs,
                              "no_adapter_language": language})
    if [item["path"] for item in checked_paths] != sorted({item["path"] for item in checked_paths}):
        raise CommentError("report.unmodelled_changes.paths must be sorted and unique")
    if omitted > 0 and len(checked_paths) != MAX_UNMODELLED_PATHS:
        raise CommentError("report.unmodelled_changes.omitted contradicts retained paths")
    if not checked_paths and omitted == 0 and not truncated and not checked_languages:
        raise CommentError("report.unmodelled_changes contains no evidence or limitation")
    return {"paths": checked_paths, "omitted": omitted,
            "unmodelled_truncated": truncated, "unmapped_languages": checked_languages}


def validate_report(path: Path, outcome: str, incomplete: bool,
                    tested_base: str, head: str) -> dict[str, Any]:
    report = require_object(parse_json(read_bounded(path, MAX_REPORT_BYTES, "comparison report"),
                                       "comparison report"), "comparison report")
    if report.get("schema_version") != SCHEMA or report.get("report_kind") != REPORT_KIND:
        raise CommentError("comparison report is not the supported /3 coverage comparison")
    if report.get("outcome") != outcome or report.get("has_incomplete") is not incomplete:
        raise CommentError("comparison report status does not match Action outputs")
    if outcome not in OUTCOMES:
        raise CommentError("comparison report outcome is unsupported")
    if outcome == "INCOMPLETE" and not incomplete:
        raise CommentError("INCOMPLETE report must retain incomplete evidence")
    if outcome == "CLEAN" and incomplete:
        raise CommentError("CLEAN report cannot retain incomplete evidence")
    base = require_object(report.get("base"), "report.base")
    candidate = require_object(report.get("candidate"), "report.candidate")
    if require_commit(base.get("revision"), "report.base.revision") != tested_base:
        raise CommentError("report base is not the computed merge base")
    if require_commit(candidate.get("revision"), "report.candidate.revision") != head:
        raise CommentError("report candidate is not the current pull request head")
    validate_summary(report.get("summary"),
                     ("added", "changed", "removed", "status_changed", "evidence_or_path_changed"),
                     "report.summary")
    for field in ("added", "changed", "removed"):
        require_list(report.get(field), f"report.{field}")
    candidate_evidence = require_object(report.get("candidate_evidence"), "report.candidate_evidence")
    candidate_status = require_string(candidate_evidence.get("status"),
                                      "report.candidate_evidence.status", 64)
    if candidate_status not in {"unknown", "no_retained_change", "retained_change"}:
        raise CommentError("report.candidate_evidence.status is unsupported")
    validate_summary(candidate_evidence.get("summary"), ("added", "changed", "moved", "removed"),
                     "report.candidate_evidence.summary")
    for field in ("added", "changed", "moved", "removed"):
        require_list(candidate_evidence.get(field), f"report.candidate_evidence.{field}")
    validate_limitations(candidate_evidence.get("limitations"),
                         "report.candidate_evidence.limitations")
    externalized = require_object(report.get("externalized_authorization"),
                                  "report.externalized_authorization")
    externalized_status = require_string(externalized.get("status"),
                                         "report.externalized_authorization.status", 64)
    if externalized_status not in {"unknown", "no_retained_change", "retained_change"}:
        raise CommentError("report.externalized_authorization.status is unsupported")
    validate_summary(externalized.get("summary"), ("added", "changed", "removed"),
                     "report.externalized_authorization.summary")
    for field in ("added", "changed", "removed"):
        require_list(externalized.get(field), f"report.externalized_authorization.{field}")
    known_paths = require_list(externalized.get("known_changed_artifact_paths"),
                               "report.externalized_authorization.known_changed_artifact_paths")
    for index, path in enumerate(known_paths):
        safe_path(path, f"report.externalized_authorization.known_changed_artifact_paths[{index}]")
    validate_limitations(externalized.get("limitations"),
                         "report.externalized_authorization.limitations")
    validate_limitations(report.get("limitations"), "report.limitations")
    unmodelled = report.get("unmodelled_changes")
    if unmodelled is not None:
        validate_unmodelled(unmodelled)
    return report


class GitHubAPI:
    def __init__(self, token: str):
        if not token or any(c in token for c in "\r\n\x00"):
            raise CommentError("GH_TOKEN is missing or invalid")
        self.token = token

    def __call__(self, method: str, endpoint: str, payload: dict[str, Any] | None = None) -> Any:
        data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        request = Request(
            "https://api.github.com/" + endpoint.lstrip("/"), data=data, method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "counterbranch-scanner-action",
                **({"Content-Type": "application/json"} if data is not None else {}),
            },
        )
        try:
            with urlopen(request, timeout=API_TIMEOUT_SECONDS) as response:
                length = response.headers.get("Content-Length")
                if length is not None and int(length) > MAX_API_BYTES:
                    raise CommentError("GitHub API response exceeds the size limit")
                body = response.read(MAX_API_BYTES + 1)
        except HTTPError as error:
            raise CommentError(f"GitHub API request failed with status {error.code}") from error
        except (URLError, OSError, TimeoutError, ValueError) as error:
            raise CommentError("GitHub API request failed") from error
        if len(body) > MAX_API_BYTES:
            raise CommentError("GitHub API response exceeds the size limit")
        return parse_json(body, "GitHub API response")


def validate_current_pr(api: Callable[..., Any], identity: dict[str, Any]) -> None:
    value = require_object(api("GET", f"repos/{identity['repository']}/pulls/{identity['number']}"),
                           "current pull request")
    if value.get("state") != "open":
        raise CommentError("pull request is no longer open")
    base = require_object(value.get("base"), "current pull request base")
    head = require_object(value.get("head"), "current pull request head")
    base_repo = require_object(base.get("repo"), "current pull request base repository")
    head_repo = require_object(head.get("repo"), "current pull request head repository")
    current = (
        require_commit(base.get("sha"), "current pull request base sha"),
        require_commit(head.get("sha"), "current pull request head sha"),
        require_positive(base_repo.get("id"), "current pull request base repository id"),
        require_positive(head_repo.get("id"), "current pull request head repository id"),
    )
    expected = (identity["base"], identity["head"], identity["repository_id"], identity["repository_id"])
    if current != expected:
        raise CommentError("pull request commits changed after this scan; no comment was published")


def existing_comment(api: Callable[..., Any], identity: dict[str, Any],
                     run_id: int, attempt: int) -> dict[str, Any] | None:
    owned: list[dict[str, Any]] = []
    for page in range(1, MAX_COMMENT_PAGES + 1):
        values = require_list(api(
            "GET", f"repos/{identity['repository']}/issues/{identity['number']}/comments"
                   f"?per_page=100&page={page}"), "pull request comments")
        for index, raw in enumerate(values):
            item = require_object(raw, f"pull request comments[{index}]")
            body = item.get("body")
            user = item.get("user")
            if not isinstance(body, str) or not body.startswith(MARKER):
                continue
            if not isinstance(user, dict) or user.get("login") != BOT_LOGIN or user.get("type") != "Bot":
                continue
            match = RUN_MARKER.search(body[:512])
            if match is None:
                raise CommentError("existing scanner bot comment has invalid ownership metadata")
            item["_run"] = int(match.group(1))
            item["_attempt"] = int(match.group(2))
            owned.append(item)
        if len(values) < 100:
            break
        if page == MAX_COMMENT_PAGES:
            raise CommentError("pull request comments exceed the bounded ownership search")
    if len(owned) > 1:
        raise CommentError("more than one scanner bot comment exists; no comment was changed")
    if not owned:
        return None
    old = owned[0]
    if (run_id, attempt) < (old["_run"], old["_attempt"]):
        raise CommentError("a newer scanner run already owns the pull request comment")
    require_positive(old.get("id"), "existing comment id")
    return old


def guard_details(side: Any, label: str) -> tuple[str, str, int, str, str | None, int | None, int] | None:
    side = require_object(side, label)
    handler = side.get("handler")
    requirement = side.get("requirement")
    if not isinstance(handler, dict) or not isinstance(requirement, dict):
        return None
    handler_path = safe_path(handler.get("path"), f"{label}.handler.path")
    handler_line = safe_line(handler.get("line_start"), f"{label}.handler.line_start")
    operation = display_metadata_text(side.get("operation"))
    if operation is None:
        return None
    opaque = require_list(requirement.get("opaque"), f"{label}.requirement.opaque")
    guards = [item[6:] for item in opaque if isinstance(item, str) and item.startswith("guard:") and len(item) > 6]
    sources = require_list(requirement.get("sources"), f"{label}.requirement.sources")
    if len(guards) != 1:
        return None
    checked_sources = []
    for index, source in enumerate(sources):
        source = require_object(source, f"{label}.requirement.sources[{index}]")
        checked_sources.append((
            safe_path(source.get("path"), f"{label}.requirement.sources[{index}].path"),
            safe_line(source.get("line_start"), f"{label}.requirement.sources[{index}].line_start"),
        ))
    source_path, source_line = checked_sources[0] if len(checked_sources) == 1 else (None, None)
    return (operation, handler_path, handler_line, guards[0], source_path, source_line,
            len(checked_sources))


def guard_only_change(change: dict[str, Any], before: tuple, after: tuple) -> bool:
    if (before[3] == after[3] or change.get("status_changed") is not False
            or change.get("route_changed", False) is not False
            or change.get("requirement_changed", False) is not True):
        return False
    base = require_object(change.get("base"), "report.changed item base")
    candidate = require_object(change.get("candidate"), "report.changed item candidate")
    operation_fields = (
        "kind", "framework", "operation", "http_method", "route_path", "handler",
        "location", "status", "limitations",
    )
    if any(base.get(field) != candidate.get(field) for field in operation_fields):
        return False
    base_requirement = require_object(base.get("requirement"),
                                      "report.changed item base.requirement")
    candidate_requirement = require_object(candidate.get("requirement"),
                                           "report.changed item candidate.requirement")
    requirement_fields = ("authentication", "any_of", "all_of", "ownership", "complete")
    if any(base_requirement.get(field) != candidate_requirement.get(field)
           for field in requirement_fields):
        return False

    def other_opaque(requirement: dict[str, Any]) -> list[Any]:
        opaque = require_list(requirement.get("opaque"), "operation requirement opaque")
        return [item for item in opaque
                if not (isinstance(item, str) and item.startswith("guard:"))]

    return other_opaque(base_requirement) == other_opaque(candidate_requirement)


def operation_change_dimensions(change: dict[str, Any]) -> str:
    dimensions = []
    for field, label in (
            ("status_changed", "status"),
            ("route_changed", "route or handler"),
            ("requirement_changed", "access requirement"),
            ("evidence_or_path_changed", "evidence or source path")):
        if change.get(field) is True:
            dimensions.append(label)
    return ", ".join(dimensions) if dimensions else "retained operation evidence"


def guard_evidence_cell(repository: str, revision: str,
                        details: tuple[str, str, int, str, str | None, int | None, int]) -> str:
    _, handler_path, handler_line, guard, source_path, source_line, source_count = details
    if source_path is not None and source_line is not None:
        return (f"[{md(guard)}]({blob_url(repository, revision, source_path, source_line)}) "
                "(sole retained requirement source)")
    handler = f"[{md(handler_path)}:{handler_line}]({blob_url(repository, revision, handler_path, handler_line)})"
    if source_count:
        return (f"{md(guard)}; {handler} handler reference; {source_count} aggregate requirement "
                "sources retained in the report")
    return f"{md(guard)}; {handler} handler reference; no requirement source location retained"


def render_operation(repository: str, base_revision: str, head_revision: str,
                     change: Any) -> str:
    change = require_object(change, "report.changed item")
    identity = require_string(change.get("identity"), "report.changed item identity", 512)
    before = guard_details(change.get("base"), "report.changed item base")
    after = guard_details(change.get("candidate"), "report.changed item candidate")
    if (before is None or after is None or before[1] != after[1] or before[2] != after[2]
            or not guard_only_change(change, before, after)):
        base_side = require_object(change.get("base"), "report.changed item base")
        candidate_side = require_object(change.get("candidate"), "report.changed item candidate")
        before_text = operation_reference(repository, base_revision, base_side, "before")
        after_text = operation_reference(repository, head_revision, candidate_side, "after")
        dimensions = operation_change_dimensions(change)
        return (f"- Modelled operation **{md(identity)}** changed: {before_text} → {after_text}. "
                f"Changed dimensions recorded by the comparison: {dimensions}. Review the retained "
                "static evidence; this is not an effective-access verdict.")
    operation, path, handler_line, before_guard, _, _, _ = before
    _, _, _, after_guard, _, _, _ = after
    before_handler = blob_url(repository, base_revision, path, handler_line)
    after_handler = blob_url(repository, head_revision, path, handler_line)
    before_evidence = guard_evidence_cell(repository, base_revision, before)
    after_evidence = guard_evidence_cell(repository, head_revision, after)
    lines = [
        f"#### {md(operation)}",
        "",
        "Static guard evidence changed for this modelled handler. Guard names are static evidence, not an effective-access verdict.",
        "",
        "| Revision | Modelled handler | Static requirement evidence |",
        "| --- | --- | --- |",
        f"| Before | [{md(path)}:{handler_line}]({before_handler}) | {before_evidence} |",
        f"| After | [{md(path)}:{handler_line}]({after_handler}) | {after_evidence} |",
        "",
        "```mermaid",
        "flowchart LR",
        "  subgraph Before",
        f"    BH[\"{mermaid(operation)}\"] --> BG[\"Static guard evidence: {mermaid(before_guard)}\"]",
        "  end",
        "  subgraph After",
        f"    AH[\"{mermaid(operation)}\"] --> AG[\"Static guard evidence: {mermaid(after_guard)}\"]",
        "  end",
        "```",
    ]
    return "\n".join(lines)


def operation_plain_meaning(report: dict[str, Any]) -> str:
    summary = report["summary"]
    counts = (f"Modelled operation changes: {summary['added']} added, "
              f"{summary['changed']} changed, {summary['removed']} removed.")
    owner_action = ("Confirm that the reported edits match the intended authorization policy, then "
                    "inspect the relevant guard or role definitions and their wiring before merge. "
                    "Guard names alone do not establish whether runtime access broadened or narrowed.")
    if (summary["added"] != 0 or summary["changed"] != 1 or summary["removed"] != 0
            or len(report["changed"]) != 1):
        return f"{counts} {owner_action}"
    change = require_object(report["changed"][0], "report.changed item")
    before = guard_details(change.get("base"), "report.changed item base")
    after = guard_details(change.get("candidate"), "report.changed item candidate")
    if (before is None or after is None or before[1] != after[1] or before[2] != after[2]
            or not guard_only_change(change, before, after)):
        return f"{counts} {owner_action}"
    return (f"{counts} For the single changed modelled operation **{md(before[0])}**, retained "
            f"static guard evidence changed from **{md(before[3])}** to **{md(after[3])}**. "
            f"{owner_action}")


def operation_reference(repository: str, revision: str, operation: dict[str, Any], label: str) -> str:
    location = operation.get("handler")
    if not isinstance(location, dict):
        location = require_object(operation.get("location"), f"operation {label} location")
    path = safe_path(location.get("path"), f"operation {label} path")
    line = safe_line(location.get("line_start"), f"operation {label} line")
    status = require_string(operation.get("status"), f"operation {label} status", 64)
    return f"[{md(status)} at {md(path)}:{line}]({blob_url(repository, revision, path, line)})"


def render_single_operation(repository: str, revision: str, operation: Any, change: str) -> str:
    operation = require_object(operation, f"report.{change} operation")
    location = require_object(operation.get("location"), f"report.{change} operation location")
    identity = require_string(location.get("identity"), f"report.{change} operation identity", 512)
    reference = operation_reference(repository, revision, operation, change)
    return (f"- Modelled operation {change} **{md(identity)}**: {reference}. "
            "Static evidence only; runtime access was not established.")


def candidate_capture(side: Any, name: str) -> str | None:
    if not isinstance(side, dict) or not isinstance(side.get("full_candidate"), dict):
        return None
    captures = side["full_candidate"].get("captures")
    if not isinstance(captures, dict) or not isinstance(captures.get(name), list) or not captures[name]:
        return None
    value = captures[name][0]
    if not isinstance(value, dict) or not isinstance(value.get("source"), str):
        return None
    return display_metadata_text(value["source"])


def render_candidate(repository: str, base_revision: str, head_revision: str,
                     value: Any, change: str) -> str:
    value = require_object(value, f"report.candidate_evidence.{change} item")
    identity = require_string(value.get("identity"), f"candidate {change} identity", 512)
    path = safe_path(value.get("path"), f"candidate {change} path")
    pattern = value.get("pattern_rule")
    pattern_text = f"; pattern **{md(pattern)}**" if isinstance(pattern, str) and pattern else ""
    if change == "added":
        line = safe_line(value.get("line_start"), "candidate added line")
        location = f"[{md(path)}:{line}]({blob_url(repository, head_revision, path, line)})"
    elif change == "removed":
        line = safe_line(value.get("line_start"), "candidate removed line")
        location = f"[{md(path)}:{line}]({blob_url(repository, base_revision, path, line)})"
    else:
        before = require_object(value.get("base"), f"candidate {change} base")
        after = require_object(value.get("candidate"), f"candidate {change} candidate")
        before_line = safe_line(before.get("line_start"), f"candidate {change} base line")
        after_line = safe_line(after.get("line_start"), f"candidate {change} candidate line")
        location = (f"[{md(path)}:{before_line}]({blob_url(repository, base_revision, path, before_line)}) → "
                    f"[{md(path)}:{after_line}]({blob_url(repository, head_revision, path, after_line)})")
    capture_text = ""
    if change == "changed":
        before_role = candidate_capture(value.get("base"), "roles")
        after_role = candidate_capture(value.get("candidate"), "roles")
        if before_role is not None and after_role is not None:
            capture_text = f"; static role capture {md(before_role)} → {md(after_role)}"
    return (f"- Static candidate evidence {change} **{md(identity)}** at {location}{pattern_text}"
            f"{capture_text}. Candidate evidence is not a runtime grant.")


def unmodelled_limit_summary(changes: dict[str, Any] | None) -> str | None:
    if changes is None:
        return None
    parts = []
    if changes["omitted"]:
        parts.append(f"{changes['omitted']} changed path row(s) omitted by the producer bound")
    if changes["unmodelled_truncated"]:
        parts.append("an adapter's unmodelled list was truncated")
    if changes["unmapped_languages"]:
        shown = ", ".join(md(language) for language in changes["unmapped_languages"][:3])
        extra = len(changes["unmapped_languages"]) - 3
        if extra:
            shown += f", and {extra} more in the report"
        parts.append(f"no-adapter language files could not be mapped to changed paths: {shown}")
    return "; ".join(parts) if parts else None


def render_unmodelled_path(item: dict[str, Any]) -> str:
    language = item["no_adapter_language"]
    label = f"Unmodelled {md(language)} path" if language is not None else "Unmodelled path"
    reasons = []
    if item["constructs"]:
        constructs = ", ".join(md(construct) for construct in item["constructs"][:3])
        extra = len(item["constructs"]) - 3
        if extra:
            constructs += f", and {extra} more in the report"
        reasons.append(f"unmodelled constructs retained by the scanner: {constructs}")
    if language is not None:
        reasons.append(f"no operation adapter for language {md(language)}")
    return (f"- **{label}:** {md(item['path'])}. Reason(s): {'; '.join(reasons)}. "
            "Runtime operation coverage was not established for this path.")


def external_location(record: Any) -> tuple[str, int] | None:
    if not isinstance(record, dict):
        return None
    path, line = record.get("path"), record.get("line_start")
    if path is None or line is None:
        return None
    return safe_path(path, "externalized evidence path"), safe_line(line, "externalized evidence line")


def render_external(repository: str, base_revision: str, head_revision: str,
                    value: Any, change: str) -> str:
    value = require_object(value, f"externalized {change} item")
    identity = require_string(value.get("identity"), f"externalized {change} identity", 8192)
    if change == "changed":
        before = external_location(value.get("base"))
        after = external_location(value.get("candidate"))
        links = []
        if before:
            links.append(f"[before {md(before[0])}:{before[1]}]({blob_url(repository, base_revision, *before)})")
        if after:
            links.append(f"[after {md(after[0])}:{after[1]}]({blob_url(repository, head_revision, *after)})")
    else:
        location = external_location(value)
        revision = head_revision if change == "added" else base_revision
        links = ([f"[{md(location[0])}:{location[1]}]({blob_url(repository, revision, *location)})"]
                 if location else [])
    suffix = ": " + " → ".join(links) if links else ""
    return (f"- Externalized authorization inventory {change} **{md(identity)}**{suffix}. "
            "This static inventory does not establish runtime policy loading or decisions.")


def render_comment(repository: str, number: int, report: dict[str, Any] | None,
                   outcome: str, incomplete: bool, tested_base: str | None, head: str,
                   run_id: int, attempt: int, artifact_url: str | None) -> str:
    url = run_url(repository, run_id, attempt)
    metadata_base = tested_base or "0" * 40
    lines = [
        MARKER,
        f"<!-- counterbranch:scanner-action-run:v1 run={run_id} attempt={attempt} base={metadata_base} head={head} -->",
        "## Counterbranch static comparison",
        "",
        f"Outcome: **{outcome}**" + (" · incomplete evidence retained" if incomplete else ""),
    ]
    finding_lines = ["### Findings", ""]
    unmodelled_details = None
    if report is None:
        finding_lines.append("No validated comparison report was available. The workflow failed during setup, acquisition, scanning, or validation.")
    else:
        base_revision = report["base"]["revision"]
        head_revision = report["candidate"]["revision"]
        findings: list[str] = []
        operation_summary = report["summary"]
        candidate = report["candidate_evidence"]
        candidate_summary = candidate["summary"]
        externalized = report["externalized_authorization"]
        external_summary = externalized["summary"]
        if report.get("unmodelled_changes") is not None:
            unmodelled_details = validate_unmodelled(report["unmodelled_changes"])
        unmodelled_paths = [] if unmodelled_details is None else unmodelled_details["paths"]
        unmodelled_limit = unmodelled_limit_summary(unmodelled_details)
        known_policy_paths = externalized["known_changed_artifact_paths"]
        report_limitations = validate_limitations(report["limitations"], "report.limitations")
        candidate_limitations = validate_limitations(candidate["limitations"],
                                                     "report.candidate_evidence.limitations")
        external_limitations = validate_limitations(externalized["limitations"],
                                                    "report.externalized_authorization.limitations")
        total = (operation_summary["added"] + operation_summary["changed"] + operation_summary["removed"]
                 + candidate_summary["added"] + candidate_summary["changed"]
                 + candidate_summary["moved"] + candidate_summary["removed"]
                 + external_summary["added"] + external_summary["changed"] + external_summary["removed"]
                 + len(unmodelled_paths) + len(known_policy_paths)
                 + (1 if unmodelled_limit is not None else 0)
                 + (1 if incomplete else 0)
                 + (1 if candidate["status"] == "unknown" else 0)
                 + (1 if externalized["status"] == "unknown" else 0))
        if incomplete:
            findings.append("- **Operation deltas are unknown:** comparison evidence is incomplete. "
                            f"Reported limitation(s): {limitation_summary(report_limitations)}.")
        if candidate["status"] == "unknown" and len(findings) < MAX_FINDINGS:
            findings.append("- **Candidate-evidence comparison is unknown:** no classified candidate "
                            "delta is established. Reported limitation(s): "
                            f"{limitation_summary(candidate_limitations)}.")
        if unmodelled_limit is not None:
            findings.append(f"- **Unmodelled coverage limitations:** {unmodelled_limit}. "
                            "Changed files may be unmodelled without a retained path row.")
        for operation in report["added"]:
            if len(findings) < MAX_FINDINGS:
                findings.append(render_single_operation(repository, head_revision, operation, "added"))
        for operation in report["removed"]:
            if len(findings) < MAX_FINDINGS:
                findings.append(render_single_operation(repository, base_revision, operation, "removed"))
        for change in report["changed"]:
            if len(findings) < MAX_FINDINGS:
                findings.append(render_operation(repository, base_revision, head_revision, change))
        for change in candidate["changed"]:
            if len(findings) < MAX_FINDINGS:
                findings.append(render_candidate(repository, base_revision, head_revision,
                                                 change, "changed"))
        if unmodelled_details is not None:
            for item in unmodelled_details["paths"]:
                if len(findings) >= MAX_FINDINGS:
                    continue
                findings.append(render_unmodelled_path(item))
        for change_kind in ("added", "removed", "changed"):
            for change in externalized[change_kind]:
                if len(findings) < MAX_FINDINGS:
                    findings.append(render_external(repository, base_revision, head_revision,
                                                    change, change_kind))
        for path in known_policy_paths:
            if len(findings) < MAX_FINDINGS:
                path = safe_path(path, "known changed policy path")
                url_path = quote(path, safe="/-._~")
                link = f"https://github.com/{repository}/blob/{head_revision}/{url_path}"
                findings.append(f"- Changed policy artifact path: [{md(path)}]({link}). Inventory metadata "
                                "does not establish source-content or runtime-policy equivalence.")
        if externalized["status"] == "unknown":
            if len(findings) < MAX_FINDINGS:
                findings.append("- Externalized authorization inventory remains uncertain. "
                                f"Reported limitation(s): {limitation_summary(external_limitations)}. "
                                "This uncertainty independently requires review.")
        for change_kind in ("added", "removed", "moved"):
            for change in candidate[change_kind]:
                if len(findings) < MAX_FINDINGS:
                    findings.append(render_candidate(repository, base_revision, head_revision,
                                                     change, change_kind))
        shown = len(findings)
        if not findings:
            if total:
                findings.append(f"The report records {total} retained static change(s), but their bounded detail rows are omitted; inspect the report ZIP.")
            else:
                findings.append("No retained operation, candidate-evidence, or known externalized-authorization changes were found.")
        finding_lines.append("\n\n".join(findings))
        if total > shown:
            finding_lines.extend(["", f"{total - shown} additional bounded finding(s) are available in the workflow report."])
    lines.extend(["", "### Plain meaning", ""])
    if report is None:
        lines.append("The scanner could not establish a comparison result. Open the run, identify and "
                     "correct the first failed stage, and obtain a validated comparison before relying "
                     "on this result. It is not a clean result.")
    elif incomplete:
        lines.append("The static comparison retained incomplete evidence. Resolve or assess the gaps before relying on the result.")
    elif outcome == "CLEAN":
        lines.append("The supported static comparison found no review-triggering retained change. This does not establish runtime enforcement.")
    elif report["summary"]["changed"] or report["summary"]["added"] or report["summary"]["removed"]:
        lines.append(operation_plain_meaning(report))
    elif (sum(report["candidate_evidence"]["summary"].values())
          or report["candidate_evidence"]["status"] == "unknown"
          or sum(report["externalized_authorization"]["summary"].values())
          or report["externalized_authorization"]["known_changed_artifact_paths"]
          or report.get("unmodelled_changes")):
        lines.append("Static candidate, unmodelled, or externalized-authorization evidence needs review. An owner should inspect the exact commit-bound findings before merge.")
    else:
        lines.append("No modelled operation change was retained. Review the remaining findings and "
                     "limitations, and confirm the reported evidence matches the intended authorization policy.")
    lines.append("Successful Action execution alone does not establish a clean assessment or merge approval.")
    limitation = unmodelled_limit_summary(unmodelled_details)
    if limitation is not None:
        lines.append(f"Unmodelled coverage remains bounded: {limitation}. Empty retained path rows do not establish that every changed file was modelled.")
    lines.extend(["", "### Where to look", ""])
    if report is not None:
        lines.append(f"- Compared merge base [{tested_base[:12]}]({commit_url(repository, tested_base)}) with "
                     f"head [{head[:12]}]({commit_url(repository, head)}).")
    else:
        lines.append(f"- Requested head: [{head[:12]}]({commit_url(repository, head)}).")
    lines.append(f"- [Open the complete Actions run]({url}).")
    if artifact_url is not None:
        lines.append(f"- [Download the report ZIP]({artifact_url}) and load it into your coding agent for further exploration. Available for one day. Start with `REPORT-GUIDE.md`, which contains a copyable prompt.")
    else:
        lines.append("- Report bundle upload was unavailable. Inspect the workflow steps before looking for a downloadable ZIP.")
    lines.extend(["", *finding_lines])
    body = "\n".join(lines).rstrip() + "\n"
    if len(body.encode("utf-8")) > MAX_COMMENT_BYTES:
        raise CommentError("rendered comment exceeds the size limit")
    return body


def validate_comment_response(value: Any, identity: dict[str, Any]) -> str:
    value = require_object(value, "comment response")
    comment_id = require_positive(value.get("id"), "comment response id")
    author = require_object(value.get("user"), "comment response user")
    if author.get("login") != BOT_LOGIN or author.get("type") != "Bot":
        raise CommentError("GitHub did not attribute the comment to the GitHub Actions bot")
    expected = f"https://github.com/{identity['repository']}/pull/{identity['number']}#issuecomment-{comment_id}"
    if value.get("html_url") != expected:
        raise CommentError("comment response URL does not match the pull request")
    return expected


def publish(api: Callable[..., Any], identity: dict[str, Any], body: str,
            run_id: int, attempt: int) -> str:
    # GitHub issue comments have no atomic compare-and-swap for ownership. The
    # documented integration contract requires one repository-wide serialized
    # publisher per PR. These repeated ref and marker checks detect stale state,
    # but cannot close a read/mutate race between independent publishers.
    validate_current_pr(api, identity)
    current = existing_comment(api, identity, run_id, attempt)
    validate_current_pr(api, identity)
    if current is None:
        response = api("POST", f"repos/{identity['repository']}/issues/{identity['number']}/comments",
                       {"body": body})
    else:
        response = api("PATCH", f"repos/{identity['repository']}/issues/comments/{current['id']}",
                       {"body": body})
    return validate_comment_response(response, identity)


def append_output(path: str | None, name: str, value: str) -> None:
    if not path:
        return
    try:
        with Path(path).open("a", encoding="utf-8") as output:
            output.write(f"{name}={value}\n")
    except OSError as error:
        raise CommentError("GITHUB_OUTPUT could not be written") from error


def append_summary(path: str | None, text: str) -> None:
    if not path:
        return
    try:
        with Path(path).open("a", encoding="utf-8") as output:
            output.write(text.rstrip() + "\n")
    except OSError as error:
        raise CommentError("GITHUB_STEP_SUMMARY could not be written") from error


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--event", type=Path, required=True)
    result.add_argument("--event-name", required=True)
    result.add_argument("--repository", required=True)
    result.add_argument("--base", required=True)
    result.add_argument("--head", required=True)
    result.add_argument("--merge-base", default="")
    result.add_argument("--report", default="")
    result.add_argument("--outcome", required=True)
    result.add_argument("--incomplete", required=True)
    result.add_argument("--artifact-url", default="")
    result.add_argument("--run-id", type=int, required=True)
    result.add_argument("--run-attempt", type=int, required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        repository = require_string(arguments.repository, "repository", 200)
        if not REPOSITORY.fullmatch(repository):
            raise CommentError("repository must be OWNER/REPOSITORY")
        base = require_commit(arguments.base, "base")
        head = require_commit(arguments.head, "head")
        incomplete = require_bool_text(arguments.incomplete, "incomplete")
        run_id = require_positive(arguments.run_id, "run-id")
        attempt = require_positive(arguments.run_attempt, "run-attempt")
        artifact_url = validate_artifact_url(arguments.artifact_url, repository, run_id)
        identity, skip = validate_event(arguments.event_name, arguments.event, repository, base, head)
        if skip is not None:
            append_output(os.environ.get("GITHUB_OUTPUT"), "comment_url", "")
            append_output(os.environ.get("GITHUB_OUTPUT"), "comment_status", "skipped")
            append_summary(os.environ.get("GITHUB_STEP_SUMMARY"),
                           f"Counterbranch PR comment skipped: {skip}.")
            return 0
        assert identity is not None
        if arguments.outcome == "UNKNOWN":
            if not incomplete or arguments.report or arguments.merge_base:
                raise CommentError("UNKNOWN requires incomplete=true and no validated report or merge base")
            report = None
            tested_base = None
        else:
            if arguments.outcome not in OUTCOMES or not arguments.report:
                raise CommentError("successful scan outputs do not identify a supported report")
            tested_base = require_commit(arguments.merge_base, "merge-base")
            report = validate_report(Path(arguments.report), arguments.outcome, incomplete,
                                     tested_base, head)
        body = render_comment(repository, identity["number"], report, arguments.outcome,
                              incomplete, tested_base, head, run_id, attempt, artifact_url)
        url = publish(GitHubAPI(os.environ.get("GH_TOKEN", "")), identity, body, run_id, attempt)
        append_output(os.environ.get("GITHUB_OUTPUT"), "comment_url", url)
        append_output(os.environ.get("GITHUB_OUTPUT"), "comment_status", "published")
        append_summary(os.environ.get("GITHUB_STEP_SUMMARY"), f"Counterbranch PR comment: {url}")
        print(url)
        return 0
    except CommentError as error:
        print(f"counterbranch comment error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
