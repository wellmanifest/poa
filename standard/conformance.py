#!/usr/bin/env python3
"""Dependency-free POA v1 contract and adversarial conformance checks."""

from __future__ import annotations

import argparse
import copy
import json
import re
from pathlib import Path
from typing import Any

try:
    from standard import poa_fixtures as _fx
    from standard import poa_plan_receipt as _plr
    from standard import poa_primitives as _pr
except ImportError:
    import poa_fixtures as _fx  # type: ignore[no-redef]
    import poa_plan_receipt as _plr  # type: ignore[no-redef]
    import poa_primitives as _pr  # type: ignore[no-redef]

ContractError, canonical, digest_text = _pr.ContractError, _pr.canonical, _pr.digest_text
exact_fields, require_string = _pr.exact_fields, _pr.require_string
require_datetime, expect_rejected = _pr.require_datetime, _fx.expect_rejected
SCHEMA_DIGEST, GRAMMAR_DIGEST = _fx.SCHEMA_DIGEST, _fx.GRAMMAR_DIGEST
example_observation, example_binding = _fx.example_observation, _fx.example_binding
example_execution_envelope, example_event = _fx.example_execution_envelope, _fx.example_event
example_process, example_request = _fx.example_process, _fx.example_request
binding_registry, example_receipt = _fx.binding_registry, _fx.example_receipt
validate_observation = _pr.validate_observation
validate_binding = _pr.validate_binding
validate_execution_envelope = _pr.validate_execution_envelope
validate_verification = _plr.validate_verification
validate_plan = _plr.validate_plan
validate_receipt = _plr.validate_receipt
validate_event = _plr.validate_event
ALLOWED_EFFECTS = _plr.ALLOWED_EFFECTS

__all__ = [
    "ALLOWED_EFFECTS",
    "CANONICAL_REQUESTS",
    "ContractError",
    "Contracts",
    "GRAMMAR_DIGEST",
    "GRAMMAR_PATH",
    "ROOT",
    "SCHEMA_DIGEST",
    "SCHEMA_PATH",
    "adversarial_checks",
    "binding_registry",
    "canonical",
    "compile_example_plan",
    "digest_text",
    "exact_fields",
    "example_binding",
    "example_event",
    "example_execution_envelope",
    "example_observation",
    "example_process",
    "example_receipt",
    "example_request",
    "expect_rejected",
    "main",
    "request_canonical",
    "require_datetime",
    "require_string",
    "run_all",
    "validate_binding",
    "validate_event",
    "validate_execution_envelope",
    "validate_observation",
    "validate_plan",
    "validate_process",
    "validate_process_step",
    "validate_receipt",
    "validate_request",
    "validate_verification",
]

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "poa-process.schema.v1.json"
GRAMMAR_PATH = ROOT / "poa-process.v1.gbnf"
JSON_STRING = r'"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"'
CANONICAL_REQUESTS = {
    "inspect": re.compile(
        r'\A\{"schema":"poa\.request/v1","operation":"inspect","process_ref":'
        + JSON_STRING
        + r"\}\Z"
    ),
    "plan": re.compile(
        r'\A\{"schema":"poa\.request/v1","operation":"plan","process_ref":'
        + JSON_STRING
        + r',"input_ref":'
        + JSON_STRING
        + r',"input_sha256":'
        + JSON_STRING
        + r"\}\Z"
    ),
}


def _compile_schema_pattern(raw_pattern: str) -> re.Pattern[str]:
    anchored = raw_pattern
    if anchored.startswith("^"):
        anchored = r"\A" + anchored[1:]
    if anchored.endswith("$") and not anchored.endswith(r"\$"):
        anchored = anchored[:-1] + r"\Z"
    return re.compile(anchored)


class Contracts:
    def __init__(self) -> None:
        self.schema = _pr.load_strict_json(SCHEMA_PATH)
        self.grammar = _pr.read_regular_utf8(GRAMMAR_PATH)
        definitions = self.schema.get("$defs")
        if not isinstance(definitions, dict):
            raise ContractError("schema definitions are unavailable")
        ref_names = (
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
        self.patterns = {
            name: _compile_schema_pattern(str(definitions[name]["pattern"])) for name in ref_names
        }
        self.max_lengths: dict[str, int | None] = {
            name: definitions[name].get("maxLength") for name in ref_names
        }

    def validate_integrity(self) -> None:
        if self.schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise ContractError("unexpected JSON Schema dialect")
        expected_id = "https://wellmanifest.dev/schemas/poa/poa-process.schema.v1.json"
        if self.schema.get("$id") != expected_id:
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
            item.get("$ref") for item in self.schema.get("oneOf", []) if isinstance(item, dict)
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
        _pr.assert_closed_objects(self.schema)

    def ref(self, name: str, value: Any) -> str:
        checked = require_string(
            value, self.patterns[name], name, max_length=self.max_lengths[name]
        )
        return _pr.validate_safe_uri_segments(checked)


def request_canonical(value: dict[str, Any]) -> str:
    ordered: dict[str, Any] = {
        "schema": value["schema"],
        "operation": value["operation"],
        "process_ref": value["process_ref"],
    }
    if value["operation"] == "plan":
        ordered["input_ref"] = value["input_ref"]
        ordered["input_sha256"] = value["input_sha256"]
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def validate_request(contracts: Contracts, value: Any) -> dict[str, Any]:
    _pr.reject_secret_material(value)
    if not isinstance(value, dict):
        raise ContractError("request must be an object")
    operation = value.get("operation")
    if operation == "inspect":
        exact_fields(value, {"schema", "operation", "process_ref"})
    elif operation == "plan":
        exact_fields(value, {"schema", "operation", "process_ref", "input_ref", "input_sha256"})
        contracts.ref("artifactRef", value["input_ref"])
        contracts.ref("sha256", value["input_sha256"])
    else:
        raise ContractError("request operation is not declared")
    if value.get("schema") != "poa.request/v1":
        raise ContractError("request schema is not supported")
    contracts.ref("processRef", value["process_ref"])
    encoded = request_canonical(value)
    if CANONICAL_REQUESTS[operation].fullmatch(encoded) is None:
        raise ContractError("canonical request violates GBNF")
    if request_canonical(_pr.strict_loads(encoded)) != encoded:
        raise ContractError("canonical request round-trip failed")
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
    kind = _pr.str_choice(
        value["kind"], {"query", "command"}, ContractError("step kind is invalid")
    )
    idempotency = _pr.str_choice(
        value["idempotency"],
        {"required", "read_only", "unsupported"},
        ContractError("step idempotency mode is invalid"),
    )
    effects = _pr.unique_list(
        value["effects"], "step effects are invalid", minimum=1, maximum=len(ALLOWED_EFFECTS)
    )
    if any(not isinstance(effect, str) or effect not in ALLOWED_EFFECTS for effect in effects):
        raise ContractError("step effects are invalid")
    if kind == "query" and (
        set(effects) & {"local_write", "external_write", "destructive"}
        or idempotency != "read_only"
    ):
        raise ContractError("query step declares a mutating behavior")
    approval_effects = {
        "external_write",
        "credential_use",
        "quota_consumption",
        "remote_session",
        "destructive",
    }
    _pr.strict_bool(value["requires_approval"], "step requires_approval must be boolean")
    if set(effects) & approval_effects and value["requires_approval"] is not True:
        raise ContractError("high-impact step lacks explicit approval")
    deps = _pr.unique_list(value["depends_on"], "step dependencies are invalid", maximum=32)
    for dependency in deps:
        contracts.ref("identifier", dependency)
    _pr.bounded_int(value["timeout_seconds"], 1, 900, "step timeout is invalid")
    _pr.bounded_int(value["max_attempts"], 1, 5, "step attempt budget is invalid")
    verification = _pr.bounded_list(
        value["verification"], "step verification is missing", minimum=1, maximum=8
    )
    for check in verification:
        validate_verification(contracts, check)


def validate_process(contracts: Contracts, value: Any) -> dict[str, Any]:
    _pr.reject_secret_material(value)
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
    title = value["title"]
    if (
        not isinstance(title, str)
        or not 1 <= len(title) <= 160
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in title)
    ):
        raise ContractError("process title is invalid")
    _pr._check_utf8_str(title)
    _pr.validate_safe_uri_segments(
        require_string(value["owner"], _pr.OWNER_ACTOR_RE, "owner", max_length=160)
    )
    policies = _pr.unique_list(
        value["policy_refs"], "process policies are invalid", minimum=1, maximum=16
    )
    for policy in policies:
        contracts.ref("policyRef", policy)
    steps = _pr.bounded_list(value["steps"], "process steps are invalid", minimum=1, maximum=64)
    ids: list[str] = []
    edges: dict[str, list[str]] = {}
    for step in steps:
        validate_process_step(contracts, step)
        step_id = contracts.ref("identifier", step["id"])
        ids.append(step_id)
        edges[step_id] = list(step["depends_on"])
    _pr.assert_dag(
        ids,
        edges,
        duplicate_msg="process step ids are not unique",
        unresolved_msg="process dependency is unresolved or self-referential",
        cycle_msg="process dependency graph contains a cycle",
    )
    return copy.deepcopy(value)


def compile_example_plan(
    contracts: Contracts, process: dict[str, Any], request: dict[str, Any]
) -> dict[str, Any]:
    validated_process = validate_process(contracts, process)
    validated_request = validate_request(contracts, request)
    req_hash = digest_text(request_canonical(validated_request))
    return _plr.compile_plan_from_validated(
        contracts, validated_process, validated_request, req_hash
    )


def adversarial_checks(contracts: Contracts) -> int:
    return _fx.run_adversarial_suite(
        validate_request_fn=lambda d: validate_request(contracts, d),
        validate_process_fn=lambda d: validate_process(contracts, d),
        validate_plan_fn=lambda d: validate_plan(contracts, d),
        validate_observation_fn=lambda d: validate_observation(contracts, d),
        validate_binding_fn=lambda d: validate_binding(contracts, d),
        validate_envelope_fn=lambda d: validate_execution_envelope(contracts, d),
        validate_event_fn=lambda d: validate_event(contracts, d),
        validate_receipt_fn=lambda d: validate_receipt(contracts, d),
        compile_plan_fn=lambda p, r: compile_example_plan(contracts, p, r),
    )


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
    try:
        from standard.ticket_queue import run_ticket_queue_conformance
    except ImportError:
        from ticket_queue import run_ticket_queue_conformance  # type: ignore[no-redef]

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="run the complete conformance suite")
    parser.add_argument(
        "--request", help="validate one POA request JSON value without executing a process"
    )
    args = parser.parse_args(argv)
    try:
        if args.request is not None:
            contracts = Contracts()
            contracts.validate_integrity()
            result = validate_request(contracts, _pr.strict_loads(args.request))
            output = {
                "schema": "poa.request-validation/v1",
                "ok": True,
                "operation": result["operation"],
                "canonical_sha256": digest_text(request_canonical(result)),
            }
        else:
            output = run_all()
    except (ContractError, json.JSONDecodeError, OSError) as error:
        report = {"schema": "poa.conformance-report/v1", "ok": False, "error": type(error).__name__}
        print(json.dumps(report, sort_keys=True))
        return 1
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
