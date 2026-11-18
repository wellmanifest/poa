#!/usr/bin/env python3
"""POA operation contract v1: one closed record shape for every operation registry.

Registries with different data models (action, procedure, process and
generated-operation registries) exchange entries as ``poa.operation/v1``
documents. A document describes an operation; it never grants authority,
admits execution or carries secrets. The validator is dependency-free and
mirrors ``poa-operation.schema.v1.json``; the semantic rules below are the
part JSON Schema cannot express.
"""

from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path
from typing import Any

try:
    from standard import poa_primitives as _pr
except ImportError:
    import poa_primitives as _pr  # type: ignore[no-redef]

ContractError = _pr.ContractError
SCHEMA = "poa.operation/v1"
SCHEMA_PATH = Path(__file__).resolve().parent / "poa-operation.schema.v1.json"
SCHEMA_ID = "https://wellmanifest.dev/schemas/poa/poa-operation.schema.v1.json"
SCHEMA_DIGEST = "71a8772267d3f680eaa4f7918ea0ce225717d2486fcdda8d3432faa4edb7b578"

EFFECTS = frozenset({"read_data", "local_write", "external_write", "credential_use",
                     "quota_consumption", "remote_session", "destructive"})
LIFECYCLES = frozenset({"candidate", "admitted", "quarantined", "deprecated", "retired"})
ORIGINS = frozenset({"declared", "builtin", "generated", "imported"})
RISKS = frozenset({"low", "medium", "high"})
REQUIRED = {"schema", "operation_id", "uri", "version", "summary", "input_schema",
            "effects", "lifecycle", "provenance"}
OPTIONAL = {"summary_i18n", "keywords", "risk"}
PROVENANCE_REQUIRED = {"registry", "source_id", "source_sha256", "origin", "recorded_at"}
PROVENANCE_OPTIONAL = {"code_sha256", "generated_by"}
INPUT_SCHEMA_KEYS = {"type", "title", "description", "properties", "required", "additionalProperties"}

IDENTIFIER_RE = re.compile(r"\A[a-z][a-z0-9._:-]*\Z")
URI_RE = re.compile(r"\A[a-z][a-z0-9+.-]*://[A-Za-z0-9._:-]+(?:/[A-Za-z0-9._:-]+)*\Z")
SHA256_RE = re.compile(r"\A[a-f0-9]{64}\Z")
TEXT_RE = re.compile(r"\A[^\x00-\x1f\x7f]+\Z")
SOURCE_ID_RE = re.compile(r"\A[^\x00-\x1f\x7f\s]+\Z")
LANG_RE = re.compile(r"\A[a-z]{2}(?:-[A-Z]{2})?\Z")
MAP_KEY_RE = re.compile(r"\A[A-Za-z0-9_.:$-]{1,128}\Z")
MAX_MAP = 64
MAX_LIST = 64
MAX_STRING = 2048


def _fields(value: Any, required: set[str], optional: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    keys = set(value)
    if keys - required - optional or required - keys:
        raise ContractError(f"{label} fields are not closed")
    return value


def _text(value: Any, label: str, *, maximum: int = 300, pattern: re.Pattern[str] = TEXT_RE) -> str:
    return _pr.require_string(value, pattern, label, max_length=maximum)


def _sha256(value: Any, label: str) -> str:
    return _pr.require_string(value, SHA256_RE, label)


def _json_value(value: Any, depth: int) -> None:
    if depth > _pr.MAX_JSON_DEPTH:
        raise ContractError("input schema exceeds maximum nesting depth")
    if isinstance(value, str):
        if len(value) > MAX_STRING:
            raise ContractError("input schema string is too long")
    elif isinstance(value, list):
        if len(value) > MAX_LIST:
            raise ContractError("input schema array is too long")
        for item in value:
            _json_value(item, depth + 1)
    elif isinstance(value, dict):
        _json_map(value, depth + 1)
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise ContractError("input schema contains a non-JSON value")


def _json_map(value: Any, depth: int) -> None:
    if not isinstance(value, dict) or len(value) > MAX_MAP:
        raise ContractError("input schema map is invalid or too large")
    for key, item in value.items():
        if not isinstance(key, str) or MAP_KEY_RE.fullmatch(key) is None:
            raise ContractError("input schema key violates its declared pattern")
        _json_value(item, depth)


def validate_input_schema(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - INPUT_SCHEMA_KEYS or value.get("type") != "object":
        raise ContractError("input_schema must be a top-level object schema")
    if "title" in value:
        _text(value["title"], "input_schema.title")
    if "description" in value:
        _text(value["description"], "input_schema.description", maximum=1000)
    if "properties" in value:
        _json_map(value["properties"], 1)
    required = value.get("required", [])
    if (not isinstance(required, list) or len(required) > MAX_LIST or len(set(map(str, required))) != len(required)
            or any(not isinstance(item, str) or not 1 <= len(item) <= 128 for item in required)):
        raise ContractError("input_schema.required must be unique bounded names")
    if "additionalProperties" in value and type(value["additionalProperties"]) is not bool:
        raise ContractError("input_schema.additionalProperties must be a boolean")
    return value


def _unique_strings(value: Any, label: str, *, allowed: frozenset[str] | None = None,
                    maximum: int = MAX_LIST) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum or len(set(map(repr, value))) != len(value):
        raise ContractError(f"{label} must be a bounded unique array")
    for item in value:
        if allowed is not None:
            _pr.str_choice(item, set(allowed), ContractError(f"{label} contains an unknown value"))
        else:
            _text(item, label, maximum=64)
    return value


def validate_provenance(value: Any) -> dict[str, Any]:
    provenance = _fields(value, PROVENANCE_REQUIRED, PROVENANCE_OPTIONAL, "provenance")
    _pr.require_string(provenance["registry"], IDENTIFIER_RE, "provenance.registry", max_length=96)
    _text(provenance["source_id"], "provenance.source_id", maximum=256, pattern=SOURCE_ID_RE)
    _sha256(provenance["source_sha256"], "provenance.source_sha256")
    _pr.str_choice(provenance["origin"], set(ORIGINS), ContractError("provenance.origin is unknown"))
    _pr.require_datetime(provenance["recorded_at"], "provenance.recorded_at")
    if "code_sha256" in provenance:
        _sha256(provenance["code_sha256"], "provenance.code_sha256")
    if "generated_by" in provenance:
        _pr.require_string(provenance["generated_by"], IDENTIFIER_RE, "provenance.generated_by", max_length=96)
    if provenance["origin"] == "generated" and not {"code_sha256", "generated_by"} <= set(provenance):
        raise ContractError("a generated operation must name its generator and code digest")
    return provenance


def _check_semantics(operation: dict[str, Any]) -> None:
    if "destructive" in operation["effects"] and operation.get("risk") != "high":
        raise ContractError("a destructive operation must declare high risk")


def validate_operation(value: Any) -> dict[str, Any]:
    """Validate one ``poa.operation/v1`` document; raise ContractError when it is not accepted."""
    operation = _fields(value, REQUIRED, OPTIONAL, "operation")
    _pr.canonical(operation)
    _pr.reject_secret_material(operation, error=ContractError("operation contains secret material"))
    if operation["schema"] != SCHEMA:
        raise ContractError("operation schema is not supported")
    _pr.require_string(operation["operation_id"], IDENTIFIER_RE, "operation_id", max_length=96)
    _pr.require_string(operation["uri"], URI_RE, "uri", max_length=320)
    _pr.bounded_int(operation["version"], 1, 1_000_000, "version is outside 1..1000000")
    _text(operation["summary"], "summary")
    if "summary_i18n" in operation:
        i18n = operation["summary_i18n"]
        if not isinstance(i18n, dict) or len(i18n) > 8:
            raise ContractError("summary_i18n must be a small language map")
        for lang, text in i18n.items():
            _pr.require_string(lang, LANG_RE, "summary_i18n language")
            _text(text, "summary_i18n text")
    if "keywords" in operation:
        _unique_strings(operation["keywords"], "keywords", maximum=32)
    validate_input_schema(operation["input_schema"])
    _unique_strings(operation["effects"], "effects", allowed=EFFECTS, maximum=len(EFFECTS))
    if "risk" in operation:
        _pr.str_choice(operation["risk"], set(RISKS), ContractError("risk is unknown"))
    _pr.str_choice(operation["lifecycle"], set(LIFECYCLES), ContractError("lifecycle is unknown"))
    validate_provenance(operation["provenance"])
    _check_semantics(operation)
    return operation


def operation_sha256(operation: dict[str, Any]) -> str:
    """Canonical (RFC 8785 profile) digest of a validated operation document."""
    return _pr.digest_text(_pr.canonical(validate_operation(operation)))


def validate_schema_integrity() -> dict[str, Any]:
    schema = _pr.load_strict_json(SCHEMA_PATH)
    if schema.get("$id") != SCHEMA_ID:
        raise ContractError("unexpected operation schema identifier")
    if _pr.digest_text(_pr.canonical(schema)) != SCHEMA_DIGEST:
        raise ContractError("operation schema integrity check failed")
    _pr.assert_closed_objects(schema)
    return schema


def example_operations() -> list[dict[str, Any]]:
    """A declared read action (heyasa-style) and a generated candidate (autonom-style)."""
    declared = {
        "schema": SCHEMA,
        "operation_id": "heyasa.willpad.notes.list",
        "uri": "heyasa://willpad/notes/list",
        "version": 1,
        "summary": "List notes in the active willpad workspace",
        "summary_i18n": {"pl": "Pokaż notatki w aktywnym obszarze willpad"},
        "keywords": ["notes", "willpad"],
        "input_schema": {"type": "object"},
        "effects": ["read_data"],
        "risk": "low",
        "lifecycle": "admitted",
        "provenance": {"registry": "heyasa.action", "source_id": "willpad.notes.list",
                       "source_sha256": "a" * 64, "origin": "declared",
                       "recorded_at": "2026-11-18T12:00:00Z"},
    }
    generated = {
        "schema": SCHEMA,
        "operation_id": "gen.text.word_count",
        "uri": "autonom://operation/gen.text.word_count",
        "version": 2,
        "summary": "Count words in a text",
        "input_schema": {"type": "object", "properties": {"text": {"type": "string", "maxLength": 100000}},
                         "required": ["text"], "additionalProperties": False},
        "effects": [],
        "lifecycle": "candidate",
        "provenance": {"registry": "autonom.operation", "source_id": "gen.text.word_count@2",
                       "source_sha256": "b" * 64, "origin": "generated",
                       "recorded_at": "2026-11-18T12:00:00Z", "code_sha256": "c" * 64,
                       "generated_by": "autonom.synthesizer"},
    }
    return [declared, generated]


def _mutated(base: dict[str, Any], path: tuple[str, ...], value: Any) -> dict[str, Any]:
    doc = deepcopy(base)
    node = doc
    for key in path[:-1]:
        node = node[key]
    if value is _DELETE:
        node.pop(path[-1])
    else:
        node[path[-1]] = value
    return doc


_DELETE = object()
ADVERSARIAL: tuple[tuple[int, tuple[str, ...], Any], ...] = (
    (0, ("schema",), "poa.operation/v2"),
    (0, ("extra",), True),
    (0, ("summary",), _DELETE),
    (0, ("operation_id",), "Heyasa.Notes"),
    (0, ("uri",), "heyasa://willpad/notes/list?x=1"),
    (0, ("version",), True),
    (0, ("version",), 0),
    (0, ("summary",), "line\nbreak"),
    (0, ("summary",), "to" + "ken" + "=" + "abcdef123456"),  # split: not a real secret
    (0, ("input_schema",), {"type": "array"}),
    (0, ("input_schema",), {"type": "object", "oneOf": []}),
    (0, ("input_schema", "additionalProperties"), "no"),
    (0, ("input_schema", "properties"), {"bad key": {}}),
    (0, ("effects",), ["read_data", "read_data"]),
    (0, ("effects",), ["execute"]),
    (0, ("effects",), ["destructive"]),
    (0, ("risk",), "critical"),
    (0, ("lifecycle",), "imported"),
    (0, ("provenance", "origin"), "copied"),
    (0, ("provenance", "recorded_at"), "yesterday"),
    (0, ("provenance", "source_sha256"), "A" * 64),
    (0, ("provenance", "extra"), 1),
    (0, ("summary_i18n",), {"polish": "x"}),
    (1, ("provenance", "code_sha256"), _DELETE),
    (1, ("provenance", "generated_by"), _DELETE),
)


def run_operation_conformance() -> dict[str, Any]:
    validate_schema_integrity()
    examples = example_operations()
    digests = [operation_sha256(example) for example in examples]
    rejected = 0
    for index, path, value in ADVERSARIAL:
        try:
            validate_operation(_mutated(examples[index], path, value))
        except ContractError:
            rejected += 1
            continue
        raise ContractError(f"adversarial operation was accepted: {'.'.join(path)}")
    return {"schema_integrity": True, "examples": len(examples), "example_sha256": digests,
            "adversarial_rejections": rejected}


if __name__ == "__main__":
    import json

    print(json.dumps(run_operation_conformance(), indent=2, sort_keys=True))
