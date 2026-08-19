#!/usr/bin/env python3
"""Dependency-free POA v1 contract and adversarial conformance checks."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "poa-process.schema.v1.json"
GRAMMAR_PATH = ROOT / "poa-process.v1.gbnf"
SCHEMA_DIGEST = "77eb7ad30d304a947524b3f3fdca8dfc345e9c6fbb9651e2346fc08ffe145468"
GRAMMAR_DIGEST = "d13d736cc3f4e07dd9366378183055ff0d9ad10dd4fc5bf1f322e2dc37d919ee"
JSON_STRING = r'"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"'
CANONICAL_REQUESTS = {
    "inspect": re.compile(
        r'^\{"schema":"poa\.request/v1","operation":"inspect","process_ref":'
        + JSON_STRING
        + r"\}$"
    ),
    "plan": re.compile(
        r'^\{"schema":"poa\.request/v1","operation":"plan","process_ref":'
        + JSON_STRING
        + r',"input_ref":'
        + JSON_STRING
        + r',"input_sha256":'
        + JSON_STRING
        + r"\}$"
    ),
}


class ContractError(ValueError):
    """Safe conformance error that never includes an untrusted value."""


def canonical(value: Any) -> str:
    """Serialize the POA numeric/string subset using the RFC 8785 profile."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def exact_fields(value: Any, required: set[str], optional: set[str] | None = None) -> None:
    if not isinstance(value, dict):
        raise ContractError("document must be an object")
    optional = optional or set()
    if set(value) - required - optional:
        raise ContractError("document contains undeclared fields")
    if required - set(value):
        raise ContractError("document is missing required fields")


def require_string(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ContractError(f"{label} violates its declared pattern")
    return value


def require_datetime(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ContractError(f"{label} is not a bounded date-time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ContractError(f"{label} is not a valid date-time") from error
    if parsed.tzinfo is None:
        raise ContractError(f"{label} has no timezone")
    return parsed


class Contracts:
    def __init__(self) -> None:
        self.schema = json.loads(SCHEMA_PATH.read_text("utf-8"))
        self.grammar = GRAMMAR_PATH.read_text("utf-8")
        definitions = self.schema.get("$defs")
        if not isinstance(definitions, dict):
            raise ContractError("schema definitions are unavailable")
        self.patterns = {
            name: re.compile(str(definitions[name]["pattern"]))
            for name in (
                "identifier",
                "sha256",
                "sha256Ref",
                "processRef",
                "capabilityRef",
                "policyRef",
                "artifactRef",
                "schemaRef",
                "grammarRef",
                "adapterRef",
                "targetRef",
                "processUri",
            )
        }

    def validate_integrity(self) -> None:
        if self.schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise ContractError("unexpected JSON Schema dialect")
        if self.schema.get("$id") != "https://wellmanifest.dev/schemas/poa/poa-process.schema.v1.json":
            raise ContractError("unexpected schema identifier")
        if digest_text(canonical(self.schema)) != SCHEMA_DIGEST:
            raise ContractError("schema integrity check failed")
        if digest_text(self.grammar) != GRAMMAR_DIGEST:
            raise ContractError("grammar integrity check failed")
        required_rules = (
            "root ::= inspect | plan",
            "inspect ::=",
            "plan ::=",
            "string ::=",
            "chars ::=",
        )
        if any(rule not in self.grammar for rule in required_rules):
            raise ContractError("grammar is incomplete")
        variants = {
            item.get("$ref")
            for item in self.schema.get("oneOf", [])
            if isinstance(item, dict)
        }
        expected = {
            "#/$defs/process",
            "#/$defs/requestInspect",
            "#/$defs/requestPlan",
            "#/$defs/binding",
            "#/$defs/observation",
            "#/$defs/plan",
            "#/$defs/executionEnvelope",
            "#/$defs/event",
            "#/$defs/receipt",
        }
        if variants != expected:
            raise ContractError("document variants are incomplete")
        self._assert_closed_objects(self.schema)

    def _assert_closed_objects(self, value: Any) -> None:
        if isinstance(value, dict):
            if value.get("type") == "object" and value.get("additionalProperties") is not False:
                raise ContractError("an object schema is not closed")
            for child in value.values():
                self._assert_closed_objects(child)
        elif isinstance(value, list):
            for child in value:
                self._assert_closed_objects(child)

    def ref(self, name: str, value: Any) -> str:
        return require_string(value, self.patterns[name], name)


def request_canonical(value: dict[str, Any]) -> str:
    ordered: dict[str, Any] = {
        "schema": value["schema"],
        "operation": value["operation"],
        "process_ref": value["process_ref"],
    }
    if value["operation"] == "plan":
        ordered["input_ref"] = value["input_ref"]
        ordered["input_sha256"] = value["input_sha256"]
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":"))


def validate_request(contracts: Contracts, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError("request must be an object")
    operation = value.get("operation")
    if operation == "inspect":
        exact_fields(value, {"schema", "operation", "process_ref"})
    elif operation == "plan":
        exact_fields(
            value,
            {"schema", "operation", "process_ref", "input_ref", "input_sha256"},
        )
        contracts.ref("artifactRef", value["input_ref"])
        contracts.ref("sha256", value["input_sha256"])
    else:
        raise ContractError("request operation is not declared")
    if value.get("schema") != "poa.request/v1":
        raise ContractError("request schema is not supported")
    contracts.ref("processRef", value["process_ref"])
    encoded = request_canonical(value)
    pattern = CANONICAL_REQUESTS[operation]
    if pattern.fullmatch(encoded) is None:
        raise ContractError("canonical request violates GBNF")
    if request_canonical(json.loads(encoded)) != encoded:
        raise ContractError("canonical request round-trip failed")
    return copy.deepcopy(value)


def example_observation() -> dict[str, Any]:
    return {
        "schema": "poa.observation/v1",
        "observation_id": "observation:example:001",
        "target_ref": "target://example.test/workspace/release",
        "observed_at": "2030-01-01T00:00:00Z",
        "valid_until": "2030-01-01T00:05:00Z",
        "fact_schema_ref": "schema://example.test/target/facts/v1",
        "facts_ref": "artifact://example.test/observations/release/r1",
        "facts_sha256": "2" * 64,
        "read_only": True,
    }


def validate_observation(contracts: Contracts, value: Any) -> None:
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
    observed = require_datetime(value["observed_at"], "observation time")
    valid_until = require_datetime(value["valid_until"], "observation validity")
    if valid_until <= observed:
        raise ContractError("observation validity is not forward-bounded")


def example_binding(observation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "poa.binding/v1",
        "binding_id": "binding:example:review:001",
        "capability_ref": "capability://example.test/llm/project-review/v1",
        "process_uri": "llmcli://account/project/command/review",
        "target_ref": observation["target_ref"],
        "adapter_ref": "adapter://example.test/llm/account-container-cli/v1",
        "observation_ref": observation["facts_ref"],
        "observation_sha256": observation["facts_sha256"],
        "priority": 100,
    }


def validate_binding(contracts: Contracts, value: Any) -> None:
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
    if not isinstance(value["priority"], int) or not -1000 <= value["priority"] <= 1000:
        raise ContractError("binding priority is invalid")


def example_execution_envelope(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "poa.execution-envelope/v1",
        "execution_id": "run:example:001",
        "request_ref": f"sha256:{plan['request_sha256']}",
        "plan_ref": f"sha256:{plan['plan_hash']}",
        "grant_ref": "grant:example:001",
        "intent_ref": "intent:example:001",
        "subject": "mcp:subactor",
        "lease_expires_at": "2030-01-01T00:10:00Z",
        "lease_revision": 1,
        "idempotency_key": "run:example:001",
    }


def validate_execution_envelope(contracts: Contracts, value: Any) -> None:
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
    if not isinstance(value["grant_ref"], str) or re.fullmatch(
        r"grant:[a-zA-Z0-9._:-]+", value["grant_ref"]
    ) is None:
        raise ContractError("execution grant reference is invalid")
    if not isinstance(value["intent_ref"], str) or re.fullmatch(
        r"intent:[a-zA-Z0-9._:-]+", value["intent_ref"]
    ) is None:
        raise ContractError("execution intent reference is invalid")
    if not isinstance(value["subject"], str) or re.fullmatch(
        r"(?:human|agent|service|mcp):[a-zA-Z0-9._:-]+", value["subject"]
    ) is None:
        raise ContractError("execution subject is invalid")
    require_datetime(value["lease_expires_at"], "execution lease")
    if not isinstance(value["lease_revision"], int) or not 1 <= value["lease_revision"] <= 2_147_483_647:
        raise ContractError("execution lease revision is invalid")
    if not isinstance(value["idempotency_key"], str) or re.fullmatch(
        r"[A-Za-z0-9._:-]{8,160}", value["idempotency_key"]
    ) is None:
        raise ContractError("execution idempotency key is invalid")


def example_event(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "poa.event/v1",
        "event_id": "event:example:001",
        "run_id": "run:example:001",
        "sequence": 1,
        "process_ref": plan["process_ref"],
        "plan_ref": f"sha256:{plan['plan_hash']}",
        "event_type": "lease_renewed",
        "occurred_at": "2030-01-01T00:00:30Z",
        "artifact_refs": [],
        "raw_output_included": False,
        "secret_material_included": False,
    }


def validate_event(contracts: Contracts, value: Any) -> None:
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
    if not isinstance(value["sequence"], int) or not 1 <= value["sequence"] <= 2_147_483_647:
        raise ContractError("event sequence is invalid")
    require_datetime(value["occurred_at"], "event time")
    refs = value["artifact_refs"]
    if not isinstance(refs, list) or len(refs) > 16 or len(refs) != len(set(refs)):
        raise ContractError("event artifacts are invalid")
    for reference in refs:
        contracts.ref("artifactRef", reference)
    if value["raw_output_included"] is not False or value["secret_material_included"] is not False:
        raise ContractError("event contains a forbidden data class")


def validate_verification(contracts: Contracts, value: Any) -> None:
    exact_fields(value, {"capability_ref", "expectation_schema_ref"})
    contracts.ref("capabilityRef", value["capability_ref"])
    contracts.ref("schemaRef", value["expectation_schema_ref"])


def validate_process(contracts: Contracts, value: Any) -> dict[str, Any]:
    exact_fields(
        value,
        {
            "schema",
            "process_ref",
            "title",
            "owner",
            "input_schema_ref",
            "output_schema_ref",
            "policy_refs",
            "steps",
        },
    )
    if value["schema"] != "poa.process/v1":
        raise ContractError("process schema is not supported")
    contracts.ref("processRef", value["process_ref"])
    contracts.ref("schemaRef", value["input_schema_ref"])
    contracts.ref("schemaRef", value["output_schema_ref"])
    if not isinstance(value["title"], str) or not 1 <= len(value["title"]) <= 160:
        raise ContractError("process title is invalid")
    if not isinstance(value["owner"], str) or re.fullmatch(
        r"(?:human|agent|service):[a-zA-Z0-9._:-]+", value["owner"]
    ) is None:
        raise ContractError("process owner is invalid")
    policies = value["policy_refs"]
    if not isinstance(policies, list) or not policies or len(policies) != len(set(policies)):
        raise ContractError("process policies are invalid")
    for policy in policies:
        contracts.ref("policyRef", policy)
    steps = value["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= 64:
        raise ContractError("process steps are invalid")
    ids: list[str] = []
    edges: dict[str, list[str]] = {}
    for step in steps:
        validate_process_step(contracts, step)
        step_id = contracts.ref("identifier", step["id"])
        ids.append(step_id)
        edges[step_id] = list(step["depends_on"])
    if len(ids) != len(set(ids)):
        raise ContractError("process step ids are not unique")
    known = set(ids)
    if any(dependency not in known or dependency == step for step, deps in edges.items() for dependency in deps):
        raise ContractError("process dependency is unresolved or self-referential")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(step: str) -> None:
        if step in visiting:
            raise ContractError("process dependency graph contains a cycle")
        if step in visited:
            return
        visiting.add(step)
        for dependency in edges[step]:
            visit(dependency)
        visiting.remove(step)
        visited.add(step)

    for step_id in ids:
        visit(step_id)
    return copy.deepcopy(value)


def validate_process_step(contracts: Contracts, value: Any) -> None:
    required = {
        "id",
        "capability_ref",
        "kind",
        "effects",
        "depends_on",
        "requires_approval",
        "timeout_seconds",
        "max_attempts",
        "idempotency",
        "verification",
    }
    exact_fields(value, required, {"compensation_capability_ref"})
    contracts.ref("identifier", value["id"])
    contracts.ref("capabilityRef", value["capability_ref"])
    if "compensation_capability_ref" in value:
        contracts.ref("capabilityRef", value["compensation_capability_ref"])
    kind = value["kind"]
    effects = value["effects"]
    if kind not in {"query", "command"}:
        raise ContractError("step kind is invalid")
    allowed_effects = {
        "read_data",
        "local_write",
        "external_write",
        "credential_use",
        "quota_consumption",
        "remote_session",
        "destructive",
    }
    if (
        not isinstance(effects, list)
        or not 1 <= len(effects) <= len(allowed_effects)
        or len(effects) != len(set(effects))
        or any(effect not in allowed_effects for effect in effects)
    ):
        raise ContractError("step effects are invalid")
    if kind == "query" and (
        set(effects) & {"local_write", "external_write", "destructive"}
        or value["idempotency"] != "read_only"
    ):
        raise ContractError("query step declares a mutating behavior")
    approval_effects = {
        "external_write",
        "credential_use",
        "quota_consumption",
        "remote_session",
        "destructive",
    }
    if set(effects) & approval_effects and value["requires_approval"] is not True:
        raise ContractError("high-impact step lacks explicit approval")
    if not isinstance(value["depends_on"], list) or len(value["depends_on"]) != len(set(value["depends_on"])):
        raise ContractError("step dependencies are invalid")
    for dependency in value["depends_on"]:
        contracts.ref("identifier", dependency)
    if not isinstance(value["timeout_seconds"], int) or not 1 <= value["timeout_seconds"] <= 900:
        raise ContractError("step timeout is invalid")
    if not isinstance(value["max_attempts"], int) or not 1 <= value["max_attempts"] <= 5:
        raise ContractError("step attempt budget is invalid")
    if value["idempotency"] not in {"required", "read_only", "unsupported"}:
        raise ContractError("step idempotency mode is invalid")
    verification = value["verification"]
    if not isinstance(verification, list) or not 1 <= len(verification) <= 8:
        raise ContractError("step verification is missing")
    for check in verification:
        validate_verification(contracts, check)


def example_process() -> dict[str, Any]:
    readback = {
        "capability_ref": "capability://example.test/repository/fingerprint/v1",
        "expectation_schema_ref": "schema://example.test/release/fingerprint/v1",
    }
    return {
        "schema": "poa.process/v1",
        "process_ref": "poa://example.test/process/release-review/v1",
        "title": "Review a project through an account-scoped LLM CLI",
        "owner": "service:control",
        "input_schema_ref": "schema://example.test/release/request/v1",
        "output_schema_ref": "schema://example.test/release/result/v1",
        "policy_refs": ["policy://example.test/automation/bounded/v1"],
        "steps": [
            {
                "id": "inventory",
                "capability_ref": "capability://example.test/repository/inventory/v1",
                "kind": "query",
                "effects": ["read_data"],
                "depends_on": [],
                "requires_approval": False,
                "timeout_seconds": 30,
                "max_attempts": 1,
                "idempotency": "read_only",
                "verification": [readback],
            },
            {
                "id": "review",
                "capability_ref": "capability://example.test/llm/project-review/v1",
                "kind": "command",
                "effects": [
                    "read_data",
                    "local_write",
                    "credential_use",
                    "quota_consumption",
                    "remote_session",
                ],
                "depends_on": ["inventory"],
                "requires_approval": True,
                "timeout_seconds": 300,
                "max_attempts": 1,
                "idempotency": "required",
                "verification": [readback],
            },
            {
                "id": "verify",
                "capability_ref": "capability://example.test/repository/fingerprint/v1",
                "kind": "query",
                "effects": ["read_data"],
                "depends_on": ["review"],
                "requires_approval": False,
                "timeout_seconds": 30,
                "max_attempts": 2,
                "idempotency": "read_only",
                "verification": [readback],
            },
        ],
    }


def example_request() -> dict[str, Any]:
    return {
        "schema": "poa.request/v1",
        "operation": "plan",
        "process_ref": "poa://example.test/process/release-review/v1",
        "input_ref": "artifact://example.test/inputs/release/r1",
        "input_sha256": "1" * 64,
    }


def binding_registry() -> dict[str, dict[str, str]]:
    target = "target://example.test/workspace/release"
    return {
        "capability://example.test/repository/inventory/v1": {
            "process_uri": "repo://workspace/release/query/inventory",
            "target_ref": target,
        },
        "capability://example.test/llm/project-review/v1": {
            "process_uri": "llmcli://account/project/command/review",
            "target_ref": target,
        },
        "capability://example.test/repository/fingerprint/v1": {
            "process_uri": "repo://workspace/release/query/fingerprint",
            "target_ref": target,
        },
    }


def compile_example_plan(
    contracts: Contracts,
    process: dict[str, Any],
    request: dict[str, Any],
) -> dict[str, Any]:
    process = validate_process(contracts, process)
    request = validate_request(contracts, request)
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
    request_hash = digest_text(request_canonical(request))
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


def validate_plan(contracts: Contracts, value: Any) -> None:
    fields = {
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
    }
    exact_fields(value, fields)
    if value["schema"] != "poa.plan/v1":
        raise ContractError("plan schema is not supported")
    contracts.ref("identifier", value["plan_id"])
    contracts.ref("processRef", value["process_ref"])
    contracts.ref("sha256", value["request_sha256"])
    contracts.ref("sha256", value["plan_hash"])
    require_datetime(value["valid_until"], "plan validity")
    body = {key: value[key] for key in value if key != "plan_hash"}
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
    if not isinstance(authority["subject"], str) or re.fullmatch(
        r"(?:human|agent|service|mcp):[a-zA-Z0-9._:-]+", authority["subject"]
    ) is None or len(authority["subject"]) > 160:
        raise ContractError("plan authority subject is invalid")
    scopes = authority["scopes"]
    if (
        not isinstance(scopes, list)
        or not 1 <= len(scopes) <= 16
        or len(scopes) != len(set(scopes))
        or any(not isinstance(scope, str) or len(scope) > 96 or re.fullmatch(r"[a-z][a-z0-9._:-]+", scope) is None for scope in scopes)
    ):
        raise ContractError("plan authority scopes are invalid")
    if (
        not isinstance(authority["grant_ttl_seconds"], int)
        or not 1 <= authority["grant_ttl_seconds"] <= 900
        or authority["intent_required"] is not True
        or authority["plan_hash_binding"] is not True
    ):
        raise ContractError("plan authority requirements are not bounded")
    boundary = value["execution_boundary"]
    exact_fields(boundary, {"boundary_ref", "host_shell", "arbitrary_executable", "transport_from_registry"})
    contracts.ref("targetRef", boundary["boundary_ref"])
    if boundary != {
        "boundary_ref": boundary["boundary_ref"],
        "host_shell": False,
        "arbitrary_executable": False,
        "transport_from_registry": True,
    }:
        raise ContractError("execution boundary is not fail-closed")
    if not isinstance(value["steps"], list) or not 1 <= len(value["steps"]) <= 64:
        raise ContractError("planned steps are invalid")
    step_ids: list[str] = []
    graph: dict[str, list[str]] = {}
    for step in value["steps"]:
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
        effects = step["effects"]
        allowed_effects = {
            "read_data",
            "local_write",
            "external_write",
            "credential_use",
            "quota_consumption",
            "remote_session",
            "destructive",
        }
        if (
            not isinstance(effects, list)
            or not 1 <= len(effects) <= len(allowed_effects)
            or len(effects) != len(set(effects))
            or any(effect not in allowed_effects for effect in effects)
        ):
            raise ContractError("planned effects are invalid")
        if step["kind"] == "query" and set(step["effects"]) & {
            "local_write",
            "external_write",
            "destructive",
        }:
            raise ContractError("planned query declares a mutating effect")
        dependencies = step["depends_on"]
        if not isinstance(dependencies, list) or len(dependencies) != len(set(dependencies)):
            raise ContractError("planned dependencies are invalid")
        for dependency in dependencies:
            contracts.ref("identifier", dependency)
        graph[step_id] = list(dependencies)
        if not isinstance(step["timeout_seconds"], int) or not 1 <= step["timeout_seconds"] <= 900:
            raise ContractError("planned timeout is invalid")
        if not isinstance(step["max_attempts"], int) or not 1 <= step["max_attempts"] <= 5:
            raise ContractError("planned attempt budget is invalid")
        if not isinstance(step["idempotency_key"], str) or re.fullmatch(
            r"[A-Za-z0-9._:-]{8,160}", step["idempotency_key"]
        ) is None:
            raise ContractError("planned idempotency key is invalid")
        for check in step["verification"]:
            validate_verification(contracts, check)
        if "compensation_process_uri" in step:
            contracts.ref("processUri", step["compensation_process_uri"])
    if len(step_ids) != len(set(step_ids)):
        raise ContractError("planned step ids are not unique")
    known = set(step_ids)
    if any(dependency not in known or dependency == step for step, dependencies in graph.items() for dependency in dependencies):
        raise ContractError("planned dependency is unresolved or self-referential")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(step_id: str) -> None:
        if step_id in visiting:
            raise ContractError("planned dependency graph contains a cycle")
        if step_id in visited:
            return
        visiting.add(step_id)
        for dependency in graph[step_id]:
            visit(dependency)
        visiting.remove(step_id)
        visited.add(step_id)

    for step_id in step_ids:
        visit(step_id)


def example_receipt(plan: dict[str, Any]) -> dict[str, Any]:
    steps = [
        {
            "step_id": step["id"],
            "process_uri": step["process_uri"],
            "state": "succeeded",
            "attempts": 1,
            "output_sha256": digest_text(f"bounded:{step['id']}"),
            "output_bytes": len(step["id"]),
            "effect_verified": True,
            "verification_refs": [f"artifact://example.test/evidence/{step['id']}/r1"],
        }
        for step in plan["steps"]
    ]
    body = {
        "schema": "poa.receipt/v1",
        "run_id": "run:example:001",
        "process_ref": plan["process_ref"],
        "plan_ref": f"sha256:{plan['plan_hash']}",
        "grant_ref": "grant:example:001",
        "intent_ref": "intent:example:001",
        "state": "succeeded",
        "started_at": "2030-01-01T00:00:00Z",
        "completed_at": "2030-01-01T00:01:00Z",
        "steps": steps,
        "raw_output_included": False,
        "secret_material_included": False,
        "hash_profile": "RFC8785+SHA-256",
    }
    return {**body, "receipt_hash": digest_text(canonical(body))}


def validate_receipt(contracts: Contracts, value: Any) -> None:
    fields = {
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
    }
    exact_fields(value, fields)
    if value["schema"] != "poa.receipt/v1":
        raise ContractError("receipt schema is not supported")
    contracts.ref("identifier", value["run_id"])
    contracts.ref("processRef", value["process_ref"])
    contracts.ref("sha256Ref", value["plan_ref"])
    contracts.ref("sha256", value["receipt_hash"])
    if not isinstance(value["grant_ref"], str) or len(value["grant_ref"]) > 160 or re.fullmatch(
        r"grant:[a-zA-Z0-9._:-]+", value["grant_ref"]
    ) is None:
        raise ContractError("receipt grant reference is invalid")
    if not isinstance(value["intent_ref"], str) or len(value["intent_ref"]) > 160 or re.fullmatch(
        r"intent:[a-zA-Z0-9._:-]+", value["intent_ref"]
    ) is None:
        raise ContractError("receipt intent reference is invalid")
    started = require_datetime(value["started_at"], "receipt start")
    completed = require_datetime(value["completed_at"], "receipt completion")
    if completed < started:
        raise ContractError("receipt completion precedes start")
    if value["state"] not in {
        "succeeded",
        "failed",
        "compensated",
        "cancelled",
        "timed_out",
        "denied",
        "expired",
    }:
        raise ContractError("receipt state is invalid")
    if value["hash_profile"] != "RFC8785+SHA-256":
        raise ContractError("receipt hash profile is not supported")
    if value["raw_output_included"] is not False or value["secret_material_included"] is not False:
        raise ContractError("receipt contains a forbidden data class")
    body = {key: value[key] for key in value if key != "receipt_hash"}
    if digest_text(canonical(body)) != value["receipt_hash"]:
        raise ContractError("receipt hash does not bind the exact receipt")
    for step in value["steps"]:
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
        if step["state"] not in {
            "succeeded",
            "failed",
            "compensated",
            "skipped",
            "cancelled",
            "timed_out",
            "denied",
            "expired",
        }:
            raise ContractError("step receipt state is invalid")
        if not isinstance(step["attempts"], int) or not 0 <= step["attempts"] <= 5:
            raise ContractError("step receipt attempt count is invalid")
        if not isinstance(step["output_bytes"], int) or not 0 <= step["output_bytes"] <= 100_000_000:
            raise ContractError("step receipt output size is invalid")
        if not isinstance(step["effect_verified"], bool):
            raise ContractError("step receipt verification flag is invalid")
        for reference in step["verification_refs"]:
            contracts.ref("artifactRef", reference)
        if "error_code" in step and (
            not isinstance(step["error_code"], str)
            or re.fullmatch(r"[A-Z][A-Z0-9_-]{2,63}", step["error_code"]) is None
        ):
            raise ContractError("step receipt error code is invalid")


def expect_rejected(check: Any) -> None:
    try:
        check()
    except ContractError:
        return
    raise ContractError("adversarial fixture was accepted")


def adversarial_checks(contracts: Contracts) -> int:
    request = example_request()
    process = example_process()
    cases = []
    for key, value in (
        ("shell", "sh -c id"),
        ("arguments", ["--token", "credential-value"]),
        ("transport", "ssh"),
    ):
        candidate = {**request, key: value}
        cases.append(lambda candidate=candidate: validate_request(contracts, candidate))
    cases.extend(
        [
            lambda: validate_request(contracts, {**request, "operation": "apply"}),
            lambda: validate_request(contracts, {**request, "input_ref": "file:///etc/passwd"}),
            lambda: validate_request(contracts, {**request, "process_ref": "poa://example.test/process/../escape/v1"}),
        ]
    )
    plan = compile_example_plan(contracts, process, request)
    raw_channel_plan = copy.deepcopy(plan)
    raw_channel_plan["steps"][0]["shell"] = "not-allowed"
    substituted_plan = copy.deepcopy(plan)
    substituted_plan["steps"][0]["target_ref"] = "target://example.test/other/resource"
    unsafe_receipt = example_receipt(plan)
    unsafe_receipt["raw_output_included"] = True
    cases.extend(
        [
            lambda: validate_plan(contracts, raw_channel_plan),
            lambda: validate_plan(contracts, substituted_plan),
            lambda: validate_receipt(contracts, unsafe_receipt),
        ]
    )
    unknown = copy.deepcopy(process)
    unknown["steps"][1]["depends_on"] = ["missing"]
    cycle = copy.deepcopy(process)
    cycle["steps"][0]["depends_on"] = ["verify"]
    bound_definition = copy.deepcopy(process)
    bound_definition["steps"][0]["process_uri"] = "repo://workspace/release/query/inventory"
    mutating_query = copy.deepcopy(process)
    mutating_query["steps"][0]["effects"] = ["read_data", "external_write"]
    unapproved_remote = copy.deepcopy(process)
    unapproved_remote["steps"][1]["requires_approval"] = False
    observation = example_observation()
    stale_observation = copy.deepcopy(observation)
    stale_observation["valid_until"] = stale_observation["observed_at"]
    binding = example_binding(observation)
    injected_binding = {**binding, "transport": "shell"}
    envelope = example_execution_envelope(plan)
    injected_envelope = {**envelope, "shell": "sh -c id"}
    event = example_event(plan)
    unsafe_event = {**event, "raw_output_included": True}
    cases.extend(
        [
            lambda: validate_process(contracts, unknown),
            lambda: validate_process(contracts, cycle),
            lambda: validate_process(contracts, bound_definition),
            lambda: validate_process(contracts, mutating_query),
            lambda: validate_process(contracts, unapproved_remote),
            lambda: validate_observation(contracts, stale_observation),
            lambda: validate_binding(contracts, injected_binding),
            lambda: validate_execution_envelope(contracts, injected_envelope),
            lambda: validate_event(contracts, unsafe_event),
        ]
    )
    for case in cases:
        expect_rejected(case)
    return len(cases)


def run_all() -> dict[str, Any]:
    contracts = Contracts()
    contracts.validate_integrity()
    process = validate_process(contracts, example_process())
    request = validate_request(contracts, example_request())
    inspect = validate_request(
        contracts,
        {
            "schema": "poa.request/v1",
            "operation": "inspect",
            "process_ref": process["process_ref"],
        },
    )
    plan = compile_example_plan(contracts, process, request)
    validate_plan(contracts, plan)
    observation = example_observation()
    validate_observation(contracts, observation)
    binding = example_binding(observation)
    validate_binding(contracts, binding)
    envelope = example_execution_envelope(plan)
    validate_execution_envelope(contracts, envelope)
    event = example_event(plan)
    validate_event(contracts, event)
    receipt = example_receipt(plan)
    validate_receipt(contracts, receipt)
    rejected = adversarial_checks(contracts)
    from ticket_queue import run_ticket_queue_conformance

    ticket_queue = run_ticket_queue_conformance()
    return {
        "schema": "poa.conformance-report/v1",
        "ok": True,
        "checks": {
            "contract_integrity": True,
            "closed_json_schema": True,
            "gbnf_intersection": True,
            "process_dag": True,
            "capability_to_uri_binding": True,
            "typed_binding_contract": True,
            "fresh_observation_contract": True,
            "plan_hash_binding": True,
            "execution_envelope_binding": True,
            "lease_and_terminal_events": True,
            "rfc8785_sha256_profile": True,
            "receipt_hash_binding": True,
            "secret_free_receipt": True,
            "adversarial_rejections": rejected,
            "ticket_queue": ticket_queue,
        },
        "examples": {
            "process_ref": process["process_ref"],
            "request_operation": request["operation"],
            "inspect_operation": inspect["operation"],
            "plan_ref": f"sha256:{plan['plan_hash']}",
            "binding_id": binding["binding_id"],
            "observation_id": observation["observation_id"],
            "execution_id": envelope["execution_id"],
            "event_type": event["event_type"],
            "receipt_hash": receipt["receipt_hash"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="run the complete conformance suite")
    parser.add_argument(
        "--request",
        help="validate one POA request JSON value without executing a process",
    )
    args = parser.parse_args()
    try:
        if args.request is not None:
            contracts = Contracts()
            contracts.validate_integrity()
            result = validate_request(contracts, json.loads(args.request))
            output = {
                "schema": "poa.request-validation/v1",
                "ok": True,
                "operation": result["operation"],
                "canonical_sha256": digest_text(request_canonical(result)),
            }
        else:
            output = run_all()
    except (ContractError, json.JSONDecodeError) as error:
        output = {
            "schema": "poa.conformance-report/v1",
            "ok": False,
            "error": type(error).__name__,
        }
        print(json.dumps(output, sort_keys=True))
        return 1
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
