#!/usr/bin/env python3
"""POA v1 compiled plan and execution receipt validators."""

from __future__ import annotations

import copy
import re
from typing import Any

try:
    from standard import poa_fixtures as _fx
    from standard import poa_primitives as _pr
except ImportError:
    import poa_fixtures as _fx  # type: ignore[no-redef]
    import poa_primitives as _pr  # type: ignore[no-redef]

ContractError = _pr.ContractError
canonical = _pr.canonical
digest_text = _pr.digest_text
exact_fields = _pr.exact_fields
require_string = _pr.require_string
require_datetime = _pr.require_datetime
SCHEMA_DIGEST = _fx.SCHEMA_DIGEST
GRAMMAR_DIGEST = _fx.GRAMMAR_DIGEST
binding_registry = _fx.binding_registry

ALLOWED_EFFECTS = {
    "read_data",
    "local_write",
    "external_write",
    "credential_use",
    "quota_consumption",
    "remote_session",
    "destructive",
}


def validate_verification(contracts: Any, value: Any) -> None:
    exact_fields(value, {"capability_ref", "expectation_schema_ref"})
    contracts.ref("capabilityRef", value["capability_ref"])
    contracts.ref("schemaRef", value["expectation_schema_ref"])


def compile_plan_from_validated(
    contracts: Any,
    process: dict[str, Any],
    request: dict[str, Any],
    request_hash: str,
) -> dict[str, Any]:
    if request["operation"] != "plan" or request["process_ref"] != process["process_ref"]:
        raise ContractError("request does not bind the selected process")
    registry = binding_registry()
    steps = []
    for step in process["steps"]:
        binding = registry.get(step["capability_ref"])
        if binding is None:
            raise ContractError("capability binding is unavailable or ambiguous")
        contracts.ref("processUri", binding["process_uri"])
        steps.append(
            {
                "id": step["id"],
                "capability_ref": step["capability_ref"],
                "process_uri": binding["process_uri"],
                "target_ref": binding["target_ref"],
                "kind": step["kind"],
                "effects": list(step["effects"]),
                "depends_on": list(step["depends_on"]),
                "input_ref": request["input_ref"],
                "input_sha256": request["input_sha256"],
                "timeout_seconds": step["timeout_seconds"],
                "max_attempts": step["max_attempts"],
                "idempotency_key": f"run:example:{step['id']}:1",
                "verification": copy.deepcopy(step["verification"]),
            }
        )
    body = {
        "schema": "poa.plan/v1",
        "plan_id": "plan:example:001",
        "process_ref": process["process_ref"],
        "request_sha256": request_hash,
        "valid_until": "2030-01-01T00:10:00Z",
        "steps": steps,
        "dsl_contract": {
            "schema_ref": "schema://wellmanifest.dev/poa/process/v1",
            "grammar_ref": "grammar://wellmanifest.dev/poa/request/v1",
            "schema_sha256": SCHEMA_DIGEST,
            "grammar_sha256": GRAMMAR_DIGEST,
            "canonical_sha256": request_hash,
            "canonicalization": "RFC8785",
            "hash_algorithm": "SHA-256",
            "validated": True,
            "additional_properties": False,
        },
        "authority_requirements": {
            "subject": "mcp:subactor",
            "scopes": ["process.plan.execute"],
            "grant_ttl_seconds": 600,
            "intent_required": True,
            "plan_hash_binding": True,
        },
        "execution_boundary": {
            "boundary_ref": "target://example.test/workspace/release",
            "host_shell": False,
            "arbitrary_executable": False,
            "transport_from_registry": True,
        },
        "hash_profile": "RFC8785+SHA-256",
    }
    return {**body, "plan_hash": digest_text(canonical(body))}


def validate_plan(contracts: Any, value: Any) -> None:
    _pr.reject_secret_material(value)
    exact_fields(
        value,
        {
            "schema",
            "plan_id",
            "process_ref",
            "request_sha256",
            "valid_until",
            "steps",
            "dsl_contract",
            "authority_requirements",
            "execution_boundary",
            "hash_profile",
            "plan_hash",
        },
    )
    if value["schema"] != "poa.plan/v1":
        raise ContractError("plan schema is not supported")
    contracts.ref("identifier", value["plan_id"])
    contracts.ref("processRef", value["process_ref"])
    contracts.ref("sha256", value["request_sha256"])
    contracts.ref("sha256", value["plan_hash"])
    require_datetime(value["valid_until"], "plan validity")
    body = {k: value[k] for k in value if k != "plan_hash"}
    if digest_text(canonical(body)) != value["plan_hash"]:
        raise ContractError("plan hash does not bind the exact plan")
    dsl = value["dsl_contract"]
    exact_fields(
        dsl,
        {
            "schema_ref",
            "grammar_ref",
            "schema_sha256",
            "grammar_sha256",
            "canonical_sha256",
            "canonicalization",
            "hash_algorithm",
            "validated",
            "additional_properties",
        },
    )
    contracts.ref("schemaRef", dsl["schema_ref"])
    contracts.ref("grammarRef", dsl["grammar_ref"])
    for field in ("schema_sha256", "grammar_sha256", "canonical_sha256"):
        contracts.ref("sha256", dsl[field])
    if (
        dsl["schema_sha256"] != SCHEMA_DIGEST
        or dsl["grammar_sha256"] != GRAMMAR_DIGEST
        or dsl["canonical_sha256"] != value["request_sha256"]
        or dsl["canonicalization"] != "RFC8785"
        or dsl["hash_algorithm"] != "SHA-256"
        or dsl["validated"] is not True
        or dsl["additional_properties"] is not False
    ):
        raise ContractError("plan DSL receipt does not bind the validated request")
    if value["hash_profile"] != "RFC8785+SHA-256":
        raise ContractError("plan hash profile is not supported")
    authority = value["authority_requirements"]
    exact_fields(
        authority,
        {"subject", "scopes", "grant_ttl_seconds", "intent_required", "plan_hash_binding"},
    )
    subject = authority["subject"]
    if (
        not isinstance(subject, str)
        or len(subject) > 160
        or re.fullmatch(r"(?:human|agent|service|mcp):[a-zA-Z0-9._:-]+", subject) is None
    ):
        raise ContractError("plan authority subject is invalid")
    scopes = _pr.unique_list(
        authority["scopes"], "plan authority scopes are invalid", minimum=1, maximum=16
    )
    if any(
        not isinstance(s, str) or len(s) > 96 or re.fullmatch(r"[a-z][a-z0-9._:-]+", s) is None
        for s in scopes
    ):
        raise ContractError("plan authority scopes are invalid")
    _pr.bounded_int(
        authority["grant_ttl_seconds"], 1, 900, "plan authority requirements are not bounded"
    )
    if authority["intent_required"] is not True or authority["plan_hash_binding"] is not True:
        raise ContractError("plan authority requirements are not bounded")
    boundary = value["execution_boundary"]
    exact_fields(
        boundary,
        {"boundary_ref", "host_shell", "arbitrary_executable", "transport_from_registry"},
    )
    contracts.ref("targetRef", boundary["boundary_ref"])
    if boundary != {
        "boundary_ref": boundary["boundary_ref"],
        "host_shell": False,
        "arbitrary_executable": False,
        "transport_from_registry": True,
    }:
        raise ContractError("execution boundary is not fail-closed")
    steps = _pr.bounded_list(value["steps"], "planned steps are invalid", minimum=1, maximum=64)
    step_ids: list[str] = []
    graph: dict[str, list[str]] = {}
    for step in steps:
        exact_fields(
            step,
            {
                "id",
                "capability_ref",
                "process_uri",
                "target_ref",
                "kind",
                "effects",
                "depends_on",
                "input_ref",
                "input_sha256",
                "timeout_seconds",
                "max_attempts",
                "idempotency_key",
                "verification",
            },
            {"compensation_process_uri"},
        )
        step_id = contracts.ref("identifier", step["id"])
        step_ids.append(step_id)
        contracts.ref("capabilityRef", step["capability_ref"])
        process_uri = contracts.ref("processUri", step["process_uri"])
        contracts.ref("targetRef", step["target_ref"])
        contracts.ref("artifactRef", step["input_ref"])
        contracts.ref("sha256", step["input_sha256"])
        if step["kind"] not in {"query", "command"} or f"/{step['kind']}/" not in process_uri:
            raise ContractError("planned step URI and kind disagree")
        effects = _pr.unique_list(
            step["effects"], "planned effects are invalid", minimum=1, maximum=len(ALLOWED_EFFECTS)
        )
        if any(effect not in ALLOWED_EFFECTS for effect in effects):
            raise ContractError("planned effects are invalid")
        if step["kind"] == "query" and set(effects) & {
            "local_write",
            "external_write",
            "destructive",
        }:
            raise ContractError("planned query declares a mutating effect")
        dependencies = _pr.unique_list(step["depends_on"], "planned dependencies are invalid")
        for dependency in dependencies:
            contracts.ref("identifier", dependency)
        graph[step_id] = list(dependencies)
        _pr.bounded_int(step["timeout_seconds"], 1, 900, "planned timeout is invalid")
        _pr.bounded_int(step["max_attempts"], 1, 5, "planned attempt budget is invalid")
        require_string(
            step["idempotency_key"], re.compile(r"[A-Za-z0-9._:-]{8,160}"), "idempotency_key"
        )
        verifications = _pr.bounded_list(
            step["verification"], "planned verification is invalid", minimum=1, maximum=8
        )
        for check in verifications:
            validate_verification(contracts, check)
        if "compensation_process_uri" in step:
            contracts.ref("processUri", step["compensation_process_uri"])
    _pr.assert_dag(
        step_ids,
        graph,
        duplicate_msg="planned step ids are not unique",
        unresolved_msg="planned dependency is unresolved or self-referential",
        cycle_msg="planned dependency graph contains a cycle",
    )


def validate_receipt(contracts: Any, value: Any) -> None:
    _pr.reject_secret_material(value)
    exact_fields(
        value,
        {
            "schema",
            "run_id",
            "process_ref",
            "plan_ref",
            "grant_ref",
            "intent_ref",
            "state",
            "started_at",
            "completed_at",
            "steps",
            "raw_output_included",
            "secret_material_included",
            "hash_profile",
            "receipt_hash",
        },
    )
    if value["schema"] != "poa.receipt/v1":
        raise ContractError("receipt schema is not supported")
    contracts.ref("identifier", value["run_id"])
    contracts.ref("processRef", value["process_ref"])
    contracts.ref("sha256Ref", value["plan_ref"])
    contracts.ref("sha256", value["receipt_hash"])
    grant_ref = value["grant_ref"]
    if (
        not isinstance(grant_ref, str)
        or len(grant_ref) > 160
        or re.fullmatch(r"grant:[a-zA-Z0-9._:-]+", grant_ref) is None
    ):
        raise ContractError("receipt grant reference is invalid")
    intent_ref = value["intent_ref"]
    if (
        not isinstance(intent_ref, str)
        or len(intent_ref) > 160
        or re.fullmatch(r"intent:[a-zA-Z0-9._:-]+", intent_ref) is None
    ):
        raise ContractError("receipt intent reference is invalid")
    if require_datetime(value["completed_at"], "receipt completion") < require_datetime(
        value["started_at"], "receipt start"
    ):
        raise ContractError("receipt completion precedes start")
    allowed_states = {
        "succeeded",
        "failed",
        "compensated",
        "cancelled",
        "timed_out",
        "denied",
        "expired",
    }
    if value["state"] not in allowed_states:
        raise ContractError("receipt state is invalid")
    if value["hash_profile"] != "RFC8785+SHA-256":
        raise ContractError("receipt hash profile is not supported")
    if value["raw_output_included"] is not False or value["secret_material_included"] is not False:
        raise ContractError("receipt contains a forbidden data class")
    body = {k: value[k] for k in value if k != "receipt_hash"}
    if digest_text(canonical(body)) != value["receipt_hash"]:
        raise ContractError("receipt hash does not bind the exact receipt")
    steps = _pr.bounded_list(value["steps"], "receipt steps are invalid", minimum=1, maximum=64)
    step_states = allowed_states | {"skipped"}
    for step in steps:
        exact_fields(
            step,
            {
                "step_id",
                "process_uri",
                "state",
                "attempts",
                "output_sha256",
                "output_bytes",
                "effect_verified",
                "verification_refs",
            },
            {"error_code"},
        )
        contracts.ref("processUri", step["process_uri"])
        contracts.ref("sha256", step["output_sha256"])
        contracts.ref("identifier", step["step_id"])
        if step["state"] not in step_states:
            raise ContractError("step receipt state is invalid")
        _pr.bounded_int(step["attempts"], 0, 5, "step receipt attempt count is invalid")
        _pr.bounded_int(step["output_bytes"], 0, 100_000_000, "step receipt output size is invalid")
        _pr.strict_bool(step["effect_verified"], "step receipt verification flag is invalid")
        verif_refs = _pr.unique_list(
            step["verification_refs"], "step receipt verification_refs are invalid", maximum=16
        )
        for reference in verif_refs:
            contracts.ref("artifactRef", reference)
        if "error_code" in step:
            require_string(step["error_code"], re.compile(r"[A-Z][A-Z0-9_-]{2,63}"), "error_code")


def validate_event(contracts: Any, value: Any) -> None:
    _pr.reject_secret_material(value)
    exact_fields(
        value,
        {
            "schema",
            "event_id",
            "run_id",
            "sequence",
            "process_ref",
            "plan_ref",
            "event_type",
            "occurred_at",
            "artifact_refs",
            "raw_output_included",
            "secret_material_included",
        },
        {"step_id"},
    )
    if value["schema"] != "poa.event/v1":
        raise ContractError("event schema is not supported")
    for field in ("event_id", "run_id"):
        contracts.ref("identifier", value[field])
    contracts.ref("processRef", value["process_ref"])
    contracts.ref("sha256Ref", value["plan_ref"])
    if "step_id" in value:
        contracts.ref("identifier", value["step_id"])
    event_types = {
        "requested",
        "planned",
        "authorized",
        "started",
        "lease_renewed",
        "completed",
        "verified",
        "failed",
        "compensated",
        "cancelled",
        "timed_out",
        "denied",
        "expired",
    }
    if value["event_type"] not in event_types:
        raise ContractError("event type is invalid")
    _pr.bounded_int(value["sequence"], 1, 2_147_483_647, "event sequence is invalid")
    require_datetime(value["occurred_at"], "event time")
    refs = _pr.unique_list(value["artifact_refs"], "event artifacts are invalid", maximum=16)
    for reference in refs:
        contracts.ref("artifactRef", reference)
    if value["raw_output_included"] is not False or value["secret_material_included"] is not False:
        raise ContractError("event contains a forbidden data class")
