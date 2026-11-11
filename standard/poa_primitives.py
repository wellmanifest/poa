#!/usr/bin/env python3
"""Shared deterministic validation primitives for Wellmanifest POA v1 and v2."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64

RFC3339_RE = re.compile(
    r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
GRANT_REF_RE = re.compile(r"\Agrant:[a-zA-Z0-9._:-]+\Z")
INTENT_REF_RE = re.compile(r"\Aintent:[a-zA-Z0-9._:-]+\Z")
SUBJECT_ACTOR_RE = re.compile(r"\A(?:human|agent|service|mcp):[a-zA-Z0-9._:-]+\Z")
OWNER_ACTOR_RE = re.compile(r"\A(?:human|agent|service):[a-zA-Z0-9._:-]+\Z")
IDEMPOTENCY_KEY_RE = re.compile(r"\A[A-Za-z0-9._:-]{8,160}\Z")
SCOPE_TOKEN_RE = re.compile(r"\A[a-z][a-z0-9._:-]+\Z")
ERROR_CODE_RE = re.compile(r"\A[A-Z][A-Z0-9_-]{2,63}\Z")
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


def _err(error: Exception | None, msg: str) -> Exception:
    return error if error is not None else ContractError(msg)


def _reject_ancestor_symlinks(path: Path, error: Exception | None) -> None:
    if path.is_absolute():
        if any(anc.is_symlink() for anc in path.parents if len(anc.parts) > 2):
            raise _err(error, "symlink parent directory is forbidden")
        return
    cur = Path()
    for part in path.parts[:-1]:
        if part in ("", "."):
            continue
        cur = cur / part
        try:
            st = os.lstat(cur)
        except OSError as exc:
            raise _err(error, "file cannot be opened") from exc
        if stat.S_ISLNK(st.st_mode):
            raise _err(error, "symlink parent directory is forbidden")


def read_regular_utf8(
    path: Path,
    *,
    max_bytes: int = MAX_FILE_BYTES,
    error: Exception | None = None,
) -> str:
    """Read a bounded regular UTF-8 file without following symlinks or inode swaps."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise error if error is not None else ContractError("invalid maximum byte size")
    if not isinstance(path, Path):
        path = Path(path)
    _reject_ancestor_symlinks(path, error)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        lst = os.lstat(path)
        if not stat.S_ISREG(lst.st_mode):
            raise error if error is not None else ContractError("path is not a regular file")
        fd = os.open(path, flags)
    except OSError as exc:
        raise (error if error is not None else ContractError("file cannot be opened")) from exc
    chunks: list[bytes] = []
    total = 0
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise error if error is not None else ContractError("path is not a regular file")
        if (lst.st_dev, lst.st_ino) != (st.st_dev, st.st_ino):
            raise (
                error if error is not None else ContractError("file identity changed during open")
            )
        if st.st_size > max_bytes:
            raise error if error is not None else ContractError("file exceeds maximum byte size")
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise (
                    error if error is not None else ContractError("file exceeds maximum byte size")
                )
            chunks.append(chunk)
    except OSError as exc:
        raise (error if error is not None else ContractError("file cannot be read")) from exc
    finally:
        os.close(fd)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise (error if error is not None else ContractError("file is not valid UTF-8")) from exc


def _check_utf8_str(value: str, error: Exception | None = None) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise _err(error, "lone UTF-16 surrogate is forbidden") from exc


def _check_json_tree(
    value: Any,
    *,
    max_depth: int = MAX_JSON_DEPTH,
    error: Exception | None = None,
) -> None:
    if type(max_depth) is not int or max_depth < 1:
        raise _err(error, "invalid JSON nesting depth bound")
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise _err(error, "JSON exceeds maximum nesting depth")
        if isinstance(node, str):
            _check_utf8_str(node, error)
        elif type(node) is int:
            try:
                ok = math.isfinite(float(node))
            except OverflowError:
                ok = False
            if not ok:
                raise _err(error, "JSON integer magnitude overflow")
        elif isinstance(node, float) and not math.isfinite(node):
            raise _err(error, "non-finite JSON number is forbidden")
        elif isinstance(node, dict):
            for key, child in node.items():
                if not isinstance(key, str):
                    raise _err(error, "JSON object keys must be strings")
                _check_utf8_str(key, error)
                stack.append((child, depth + 1))
        elif isinstance(node, list):
            for child in node:
                stack.append((child, depth + 1))


def strict_loads(
    raw: str,
    *,
    duplicate_error: Exception | None = None,
    parse_error: Exception | None = None,
) -> Any:
    """Parse bounded finite JSON while rejecting duplicate keys and deep nesting."""
    if not isinstance(raw, str):
        raise _err(parse_error, "JSON input must be a bounded string")
    _check_utf8_str(raw, parse_error)
    if len(raw.encode("utf-8")) > MAX_FILE_BYTES:
        raise _err(parse_error, "JSON input must be a bounded string")

    def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, value in pairs:
            if key in obj:
                if duplicate_error is not None:
                    raise duplicate_error
                raise ContractError("duplicate JSON key")
            obj[key] = value
        return obj

    def _reject_constant(_token: str) -> Any:
        raise (
            parse_error
            if parse_error is not None
            else ContractError("non-finite JSON constant is forbidden")
        )

    def _parse_finite_float(token: str) -> float:
        parsed_val = float(token)
        if not math.isfinite(parsed_val):
            raise (
                parse_error
                if parse_error is not None
                else ContractError("non-finite JSON number is forbidden")
            )
        return parsed_val

    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
            parse_float=_parse_finite_float,
        )
    except RecursionError as exc:
        raise (
            parse_error
            if parse_error is not None
            else ContractError("JSON exceeds maximum nesting depth")
        ) from exc
    except (json.JSONDecodeError, ValueError) as exc:
        if parse_error is not None:
            raise parse_error from exc
        if isinstance(exc, json.JSONDecodeError):
            raise
        raise ContractError("invalid JSON number or syntax") from exc
    _check_json_tree(parsed, error=parse_error)
    return parsed


def load_strict_json(
    path: Path,
    *,
    duplicate_error: Exception | None = None,
    parse_error: Exception | None = None,
) -> Any:
    raw = read_regular_utf8(path, error=parse_error)
    return strict_loads(raw, duplicate_error=duplicate_error, parse_error=parse_error)


def canonical(value: Any) -> str:
    """Serialize the POA numeric/string subset using the RFC 8785 profile."""
    _check_json_tree(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ContractError("value is not RFC 8785 canonicalizable") from exc


def digest_text(value: str) -> str:
    _check_utf8_str(value)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def exact_fields(value: Any, required: set[str], optional: set[str] | None = None) -> None:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ContractError("document must be an object")
    optional_keys = optional or set()
    keys = set(value)
    if keys - required - optional_keys:
        raise ContractError("document contains undeclared fields")
    if required - keys:
        raise ContractError("document is missing required fields")


def exact_queue(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise QueueContractError("POA-DOC-001", "document must be an object")
    keys = set(value)
    extra = keys - required - (optional or set())
    missing = required - keys
    if extra or missing:
        raise QueueContractError("POA-DOC-001", "document fields are not closed")
    return value


def require_string(
    value: Any,
    pattern: re.Pattern[str],
    label: str,
    *,
    max_length: int | None = None,
) -> str:
    if (
        not isinstance(value, str)
        or (max_length is not None and len(value) > max_length)
        or pattern.fullmatch(value) is None
    ):
        raise ContractError(f"{label} violates its declared pattern")
    return value


def str_choice(value: Any, allowed: set[str], error: Exception) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise error
    return value


def validate_safe_uri_segments(value: str, *, error: Exception | None = None) -> str:
    if "\\" in value:
        raise error if error is not None else ContractError("URI contains forbidden delimiters")
    if "://" in value:
        _, rest = value.split("://", 1)
        if "?" in rest or "#" in rest:
            raise (
                error if error is not None else ContractError("URI contains forbidden delimiters")
            )
        authority, sep, path = rest.partition("/")
        if not authority or authority in {".", ".."}:
            raise error if error is not None else ContractError("URI authority is invalid")
        if sep and any(
            seg in {"", ".", ".."}
            or (":" in seg and any(sub in {"", ".", ".."} for sub in seg.split(":")))
            for seg in path.split("/")
        ):
            raise (
                error
                if error is not None
                else ContractError("URI contains unsafe or empty path segments")
            )
    elif ":" in value:
        scheme, rest = value.split(":", 1)
        if not scheme or not rest or "?" in rest or "#" in rest:
            raise (
                error if error is not None else ContractError("URI contains forbidden delimiters")
            )
        if any(seg in {"", ".", ".."} for seg in re.split(r"[/:]", rest)):
            raise (
                error
                if error is not None
                else ContractError("URI contains unsafe or empty path segments")
            )
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
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise QueueContractError("POA-TIME-001", "timestamp is not RFC3339") from error
    if parsed.tzinfo is None:
        raise QueueContractError("POA-TIME-001", "timestamp has no timezone")
    return parsed


def assert_closed_objects(value: Any, message: str = "an object schema is not closed") -> None:
    predicate_keys = {"if", "not", "contains"}
    map_keys = {"properties", "$defs", "dependentSchemas"}
    stack: list[tuple[Any, int, bool]] = [(value, 0, False)]
    while stack:
        node, depth, is_map = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ContractError("schema exceeds maximum nesting depth")
        if isinstance(node, dict):
            if (
                not is_map
                and node.get("type") == "object"
                and node.get("additionalProperties") is not False
            ):
                raise ContractError(message)
            for key, child in node.items():
                if not is_map and key in predicate_keys:
                    continue
                stack.append((child, depth + 1, not is_map and key in map_keys))
        elif isinstance(node, list):
            for child in node:
                stack.append((child, depth + 1, False))


def reject_secret_material(value: Any, *, error: Exception | None = None) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise (
                error
                if error is not None
                else ContractError("document exceeds maximum nesting depth")
            )
        if isinstance(node, dict):
            for key, child in node.items():
                if isinstance(key, str) and SECRET_MATERIAL.search(key):
                    raise (
                        error
                        if error is not None
                        else ContractError("credential material is forbidden")
                    )
                stack.append((child, depth + 1))
        elif isinstance(node, list):
            for child in node:
                stack.append((child, depth + 1))
        elif isinstance(node, str) and SECRET_MATERIAL.search(node):
            raise (
                error if error is not None else ContractError("credential material is forbidden")
            )


def assert_dag(
    ids: list[str],
    edges: dict[str, list[str]],
    *,
    duplicate_msg: str,
    unresolved_msg: str,
    cycle_msg: str,
) -> None:
    try:
        known = set(ids)
    except TypeError as exc:
        raise ContractError(duplicate_msg) from exc
    if len(ids) != len(known):
        raise ContractError(duplicate_msg)
    in_degree: dict[str, int] = dict.fromkeys(ids, 0)
    dependents: dict[str, list[str]] = {step_id: [] for step_id in ids}
    for step, dependencies in edges.items():
        if step not in known:
            raise ContractError(unresolved_msg)
        for dependency in dependencies:
            if not isinstance(dependency, str) or dependency not in known or dependency == step:
                raise ContractError(unresolved_msg)
            in_degree[step] += 1
            dependents[dependency].append(step)
    ready = deque(step_id for step_id in ids if in_degree[step_id] == 0)
    visited = 0
    while ready:
        current = ready.popleft()
        visited += 1
        for child in dependents[current]:
            in_degree[child] -= 1
            if in_degree[child] == 0:
                ready.append(child)
    if visited != len(ids):
        raise ContractError(cycle_msg)
