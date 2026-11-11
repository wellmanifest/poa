#!/usr/bin/env python3
"""Bounded regular-file UTF-8 I/O, finite JSON parsing, and secret scanning for POA."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_INT_DIGITS = 309

SECRET_MATERIAL = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRI"
    r"VATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{20,}|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}|\bsk-[A-Za-z0-9_-]{20,}|"
    r"\bAK"
    r"IA[0-9A-Z]{16}\b|"
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
    if not path.is_absolute():
        cur = Path()
        for part in path.parts[:-1]:
            if part in ("", ".", ".."):
                continue
            cur = cur / part
            try:
                st = os.lstat(cur)
            except OSError as exc:
                raise _err(error, "file cannot be opened") from exc
            if stat.S_ISLNK(st.st_mode):
                raise _err(error, "symlink parent directory is forbidden")
    abs_path = Path(os.path.abspath(os.fspath(path)))
    if any(anc.is_symlink() for anc in abs_path.parents if len(anc.parts) > 2):
        raise _err(error, "symlink parent directory is forbidden")


def read_regular_utf8(
    path: Path,
    *,
    max_bytes: int = MAX_FILE_BYTES,
    error: Exception | None = None,
) -> str:
    """Read a bounded regular UTF-8 file without following symlinks or inode swaps."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise _err(error, "invalid maximum byte size")
    if not isinstance(path, Path):
        path = Path(path)
    _reject_ancestor_symlinks(path, error)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        lst = os.lstat(path)
        if not stat.S_ISREG(lst.st_mode):
            raise _err(error, "path is not a regular file")
        fd = os.open(path, flags)
    except OSError as exc:
        raise _err(error, "file cannot be opened") from exc
    chunks: list[bytes] = []
    total = 0
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise _err(error, "path is not a regular file")
        if (lst.st_dev, lst.st_ino) != (st.st_dev, st.st_ino):
            raise _err(error, "file identity changed during open")
        if st.st_size > max_bytes:
            raise _err(error, "file exceeds maximum byte size")
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise _err(error, "file exceeds maximum byte size")
            chunks.append(chunk)
    except OSError as exc:
        raise _err(error, "file cannot be read") from exc
    finally:
        os.close(fd)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _err(error, "file is not valid UTF-8") from exc


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
                raise (
                    duplicate_error
                    if duplicate_error is not None
                    else ContractError("duplicate JSON key")
                )
            obj[key] = value
        return obj

    def _reject_constant(_token: str) -> Any:
        raise _err(parse_error, "non-finite JSON constant is forbidden")

    def _parse_finite_float(token: str) -> float:
        parsed_val = float(token)
        if not math.isfinite(parsed_val):
            raise _err(parse_error, "non-finite JSON number is forbidden")
        return parsed_val

    def _parse_finite_int(token: str) -> int:
        digits = token[1:] if token.startswith(("+", "-")) else token
        if len(digits) > MAX_JSON_INT_DIGITS:
            raise _err(parse_error, "JSON integer magnitude overflow")
        parsed_int = int(token)
        try:
            ok = math.isfinite(float(parsed_int))
        except OverflowError:
            ok = False
        if not ok:
            raise _err(parse_error, "JSON integer magnitude overflow")
        return parsed_int

    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
            parse_float=_parse_finite_float,
            parse_int=_parse_finite_int,
        )
    except RecursionError as exc:
        raise _err(parse_error, "JSON exceeds maximum nesting depth") from exc
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


def reject_secret_material(value: Any, *, error: Exception | None = None) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise _err(error, "document exceeds maximum nesting depth")
        if isinstance(node, dict):
            for key, child in node.items():
                if isinstance(key, str):
                    _check_utf8_str(key, error)
                    if SECRET_MATERIAL.search(key):
                        raise _err(error, "credential material is forbidden")
                stack.append((child, depth + 1))
        elif isinstance(node, list):
            for child in node:
                stack.append((child, depth + 1))
        elif isinstance(node, str):
            _check_utf8_str(node, error)
            if SECRET_MATERIAL.search(node):
                raise _err(error, "credential material is forbidden")
