#!/usr/bin/env python3
"""Shared deterministic validation primitives for Wellmanifest POA v1 and v2."""

from __future__ import annotations

import re
from collections import deque
from datetime import datetime
from typing import Any

try:
    from standard import poa_io as _io
except ImportError:
    import poa_io as _io  # type: ignore[no-redef]

MAX_FILE_BYTES = _io.MAX_FILE_BYTES
MAX_JSON_DEPTH = _io.MAX_JSON_DEPTH
MAX_JSON_INT_DIGITS = _io.MAX_JSON_INT_DIGITS
SECRET_MATERIAL = _io.SECRET_MATERIAL
ContractError = _io.ContractError
QueueContractError = _io.QueueContractError
_check_utf8_str = _io._check_utf8_str
_check_json_tree = _io._check_json_tree
read_regular_utf8 = _io.read_regular_utf8
strict_loads = _io.strict_loads
load_strict_json = _io.load_strict_json
canonical = _io.canonical
digest_text = _io.digest_text
reject_secret_material = _io.reject_secret_material

__all__ = [
    "ContractError",
    "ERROR_CODE_RE",
    "GRANT_REF_RE",
    "IDEMPOTENCY_KEY_RE",
    "INTENT_REF_RE",
    "MAX_FILE_BYTES",
    "MAX_JSON_DEPTH",
    "MAX_JSON_INT_DIGITS",
    "OWNER_ACTOR_RE",
    "QueueContractError",
    "RFC3339_RE",
    "SCOPE_TOKEN_RE",
    "SECRET_MATERIAL",
    "SUBJECT_ACTOR_RE",
    "_check_json_tree",
    "_check_utf8_str",
    "assert_closed_objects",
    "assert_dag",
    "bounded_int",
    "bounded_list",
    "canonical",
    "digest_text",
    "exact_fields",
    "exact_queue",
    "load_strict_json",
    "parse_queue_time",
    "read_regular_utf8",
    "reject_secret_material",
    "require_datetime",
    "require_string",
    "str_choice",
    "strict_bool",
    "strict_loads",
    "unique_list",
    "validate_binding",
    "validate_execution_envelope",
    "validate_observation",
    "validate_safe_uri_segments",
]

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


def validate_observation(contracts: Any, value: Any) -> None:
    reject_secret_material(value)
    exact_fields(
        value,
        {
            "schema",
            "observation_id",
            "target_ref",
            "observed_at",
            "valid_until",
            "fact_schema_ref",
            "facts_ref",
            "facts_sha256",
            "read_only",
        },
    )
    if value["schema"] != "poa.observation/v1" or value["read_only"] is not True:
        raise ContractError("observation contract is not read-only")
    contracts.ref("identifier", value["observation_id"])
    contracts.ref("targetRef", value["target_ref"])
    contracts.ref("schemaRef", value["fact_schema_ref"])
    contracts.ref("artifactRef", value["facts_ref"])
    contracts.ref("sha256", value["facts_sha256"])
    if require_datetime(value["valid_until"], "observation validity") <= require_datetime(
        value["observed_at"], "observation time"
    ):
        raise ContractError("observation validity is not forward-bounded")


def validate_binding(contracts: Any, value: Any) -> None:
    reject_secret_material(value)
    exact_fields(
        value,
        {
            "schema",
            "binding_id",
            "capability_ref",
            "process_uri",
            "target_ref",
            "adapter_ref",
            "observation_ref",
            "observation_sha256",
            "priority",
        },
    )
    if value["schema"] != "poa.binding/v1":
        raise ContractError("binding schema is not supported")
    contracts.ref("identifier", value["binding_id"])
    contracts.ref("capabilityRef", value["capability_ref"])
    contracts.ref("processUri", value["process_uri"])
    contracts.ref("targetRef", value["target_ref"])
    contracts.ref("adapterRef", value["adapter_ref"])
    contracts.ref("artifactRef", value["observation_ref"])
    contracts.ref("sha256", value["observation_sha256"])
    bounded_int(value["priority"], -1000, 1000, "binding priority is invalid")


def validate_execution_envelope(contracts: Any, value: Any) -> None:
    reject_secret_material(value)
    exact_fields(
        value,
        {
            "schema",
            "execution_id",
            "request_ref",
            "plan_ref",
            "grant_ref",
            "intent_ref",
            "subject",
            "lease_expires_at",
            "lease_revision",
            "idempotency_key",
        },
    )
    if value["schema"] != "poa.execution-envelope/v1":
        raise ContractError("execution envelope schema is not supported")
    contracts.ref("identifier", value["execution_id"])
    contracts.ref("sha256Ref", value["request_ref"])
    contracts.ref("sha256Ref", value["plan_ref"])
    validate_safe_uri_segments(
        require_string(value["grant_ref"], GRANT_REF_RE, "grant_ref", max_length=160)
    )
    validate_safe_uri_segments(
        require_string(value["intent_ref"], INTENT_REF_RE, "intent_ref", max_length=160)
    )
    validate_safe_uri_segments(
        require_string(value["subject"], SUBJECT_ACTOR_RE, "subject", max_length=160)
    )
    require_datetime(value["lease_expires_at"], "execution lease")
    bounded_int(value["lease_revision"], 1, 2_147_483_647, "execution lease revision is invalid")
    require_string(value["idempotency_key"], IDEMPOTENCY_KEY_RE, "idempotency_key")
