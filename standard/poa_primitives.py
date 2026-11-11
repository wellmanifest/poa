#!/usr/bin/env python3
"""Shared deterministic validation primitives for Wellmanifest POA v1 and v2."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

RFC3339_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
SECRET_MATERIAL = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{20,}|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}|\bsk-[A-Za-z0-9_-]{20,}|"
    r"\bAKIA[0-9A-Z]{16}\b|"
    r"(?:password|passwd|token|secret|api[-_]?key)\s*[:=]\s*[^\s,;]{4,})",
    re.I,
)


class ContractError(ValueError):
    """Safe conformance error that never includes an untrusted value."""


class QueueContractError(ValueError):
    """Fail-closed diagnostic that never echoes untrusted values."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def strict_loads(raw: str, *, duplicate_error: Exception | None = None) -> Any:
    """Parse JSON while rejecting duplicate object keys."""

    def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in pairs:
            if key in obj:
                if duplicate_error is not None:
                    raise duplicate_error
                raise ContractError("duplicate JSON key")
            obj[key] = value
        return obj

    return json.loads(raw, object_pairs_hook=_unique_pairs)


def load_strict_json(path: Path, *, duplicate_error: Exception | None = None) -> Any:
    return strict_loads(path.read_text("utf-8"), duplicate_error=duplicate_error)


def canonical(value: Any) -> str:
    """Serialize the POA numeric/string subset using the RFC 8785 profile."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def exact_fields(value: Any, required: set[str], optional: set[str] | None = None) -> None:
    if not isinstance(value, dict):
        raise ContractError("document must be an object")
    optional_keys = optional or set()
    if set(value) - required - optional_keys:
        raise ContractError("document contains undeclared fields")
    if required - set(value):
        raise ContractError("document is missing required fields")


def exact_queue(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise QueueContractError("POA-DOC-001", "document must be an object")
    extra = set(value) - required - (optional or set())
    missing = required - set(value)
    if extra or missing:
        raise QueueContractError("POA-DOC-001", "document fields are not closed")
    return value


def require_string(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ContractError(f"{label} violates its declared pattern")
    return value


def bounded_int(value: Any, minimum: int, maximum: int, message: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ContractError(message)
    return value


def strict_bool(value: Any, message: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(message)
    return value


def bounded_list(
    value: Any, message: str, *, minimum: int = 0, maximum: int | None = None
) -> list[Any]:
    if not isinstance(value, list) or len(value) < minimum:
        raise ContractError(message)
    if maximum is not None and len(value) > maximum:
        raise ContractError(message)
    return value


def unique_list(
    value: Any, message: str, *, minimum: int = 0, maximum: int | None = None
) -> list[Any]:
    items = bounded_list(value, message, minimum=minimum, maximum=maximum)
    try:
        is_unique = len(items) == len(set(items))
    except TypeError as error:
        raise ContractError(message) from error
    if not is_unique:
        raise ContractError(message)
    return items


def require_datetime(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or len(value) > 40 or RFC3339_RE.fullmatch(value) is None:
        raise ContractError(f"{label} is not a bounded RFC3339 date-time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ContractError(f"{label} is not a valid date-time") from error
    if parsed.tzinfo is None:
        raise ContractError(f"{label} has no timezone")
    return parsed


def parse_queue_time(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40 or RFC3339_RE.fullmatch(value) is None:
        raise QueueContractError("POA-TIME-001", "timestamp is not RFC3339")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise QueueContractError("POA-TIME-001", "timestamp is not RFC3339") from error


def assert_closed_objects(value: Any, message: str = "an object schema is not closed") -> None:
    if isinstance(value, dict):
        if value.get("type") == "object" and value.get("additionalProperties") is not False:
            raise ContractError(message)
        for child in value.values():
            assert_closed_objects(child, message)
    elif isinstance(value, list):
        for child in value:
            assert_closed_objects(child, message)


def reject_secret_material(value: Any, *, error: Exception | None = None) -> None:
    if isinstance(value, dict):
        for child in value.values():
            reject_secret_material(child, error=error)
    elif isinstance(value, list):
        for child in value:
            reject_secret_material(child, error=error)
    elif isinstance(value, str) and SECRET_MATERIAL.search(value):
        raise (error if error is not None else ContractError("credential material is forbidden"))


def assert_dag(
    ids: list[str],
    edges: dict[str, list[str]],
    *,
    duplicate_msg: str,
    unresolved_msg: str,
    cycle_msg: str,
) -> None:
    if len(ids) != len(set(ids)):
        raise ContractError(duplicate_msg)
    known = set(ids)
    if any(
        dependency not in known or dependency == step
        for step, dependencies in edges.items()
        for dependency in dependencies
    ):
        raise ContractError(unresolved_msg)
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(step_id: str) -> None:
        if step_id in visiting:
            raise ContractError(cycle_msg)
        if step_id in visited:
            return
        visiting.add(step_id)
        for dependency in edges[step_id]:
            visit(dependency)
        visiting.remove(step_id)
        visited.add(step_id)

    for step_id in ids:
        visit(step_id)
