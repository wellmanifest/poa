#!/usr/bin/env python3
"""Reference positive and adversarial POA v1 fixtures."""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

try:
    from standard import poa_primitives as _pr
except ImportError:
    import poa_primitives as _pr  # type: ignore[no-redef]

ContractError = _pr.ContractError
canonical = _pr.canonical
digest_text = _pr.digest_text

SCHEMA_DIGEST = "77eb7ad30d304a947524b3f3fdca8dfc345e9c6fbb9651e2346fc08ffe145468"
GRAMMAR_DIGEST = "d13d736cc3f4e07dd9366378183055ff0d9ad10dd4fc5bf1f322e2dc37d919ee"


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


def expect_rejected(check: Callable[[], Any]) -> None:
    try:
        check()
    except ContractError:
        return
    raise ContractError("adversarial fixture was accepted")


def run_adversarial_suite(
    *,
    validate_request_fn: Callable[[dict[str, Any]], Any],
    validate_process_fn: Callable[[dict[str, Any]], Any],
    validate_plan_fn: Callable[[dict[str, Any]], Any],
    validate_observation_fn: Callable[[dict[str, Any]], Any],
    validate_binding_fn: Callable[[dict[str, Any]], Any],
    validate_envelope_fn: Callable[[dict[str, Any]], Any],
    validate_event_fn: Callable[[dict[str, Any]], Any],
    validate_receipt_fn: Callable[[dict[str, Any]], Any],
    compile_plan_fn: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]],
) -> int:
    request = example_request()
    process = example_process()
    canary = "gh" + "p_" + ("A1b2C3" * 5)
    cases: list[Callable[[], Any]] = []
    for key, val in (
        ("shell", "sh -c id"),
        ("arguments", ["--flag", "extra"]),
        ("transport", "ssh"),
    ):
        candidate = {**request, key: val}
        cases.append(lambda candidate=candidate: validate_request_fn(candidate))
    cases.extend(
        [
            lambda: validate_request_fn({**request, "operation": "apply"}),
            lambda: validate_request_fn({**request, "input_ref": "file:///etc/passwd"}),
            lambda: validate_request_fn(
                {**request, "process_ref": "poa://example.test/process/../escape/v1"}
            ),
            lambda: _pr.strict_loads('{"schema":"poa.request/v1","schema":"dup"}'),
        ]
    )
    plan = compile_plan_fn(process, request)
    raw_channel_plan = copy.deepcopy(plan)
    raw_channel_plan["steps"][0]["shell"] = "not-allowed"
    substituted_plan = copy.deepcopy(plan)
    substituted_plan["steps"][0]["target_ref"] = "target://example.test/other/resource"
    empty_verif_plan = copy.deepcopy(plan)
    empty_verif_plan["steps"][0]["verification"] = []
    empty_verif_plan["plan_hash"] = digest_text(
        canonical({k: v for k, v in empty_verif_plan.items() if k != "plan_hash"})
    )
    bool_ttl_plan = copy.deepcopy(plan)
    bool_ttl_plan["authority_requirements"]["grant_ttl_seconds"] = True
    bool_ttl_plan["plan_hash"] = digest_text(
        canonical({k: v for k, v in bool_ttl_plan.items() if k != "plan_hash"})
    )
    unsafe_receipt = example_receipt(plan)
    unsafe_receipt["raw_output_included"] = True
    bool_attempts_receipt = example_receipt(plan)
    bool_attempts_receipt["steps"][0]["attempts"] = True
    bool_attempts_receipt["receipt_hash"] = digest_text(
        canonical({k: v for k, v in bool_attempts_receipt.items() if k != "receipt_hash"})
    )
    cases.extend(
        [
            lambda: validate_plan_fn(raw_channel_plan),
            lambda: validate_plan_fn(substituted_plan),
            lambda: validate_plan_fn(empty_verif_plan),
            lambda: validate_plan_fn(bool_ttl_plan),
            lambda: validate_receipt_fn(unsafe_receipt),
            lambda: validate_receipt_fn(bool_attempts_receipt),
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
    bool_timeout = copy.deepcopy(process)
    bool_timeout["steps"][0]["timeout_seconds"] = True
    secret_title = copy.deepcopy(process)
    secret_title["title"] = canary

    observation = example_observation()
    stale_observation = copy.deepcopy(observation)
    stale_observation["valid_until"] = stale_observation["observed_at"]
    space_dt_obs = {**observation, "observed_at": "2030-01-01 00:00:00Z"}
    binding = example_binding(observation)
    injected_binding = {**binding, "transport": "shell"}
    bool_prio_binding = {**binding, "priority": True}
    envelope = example_execution_envelope(plan)
    injected_envelope = {**envelope, "shell": "sh -c id"}
    bool_rev_envelope = {**envelope, "lease_revision": True}
    event = example_event(plan)
    unsafe_event = {**event, "raw_output_included": True}
    bool_seq_event = {**event, "sequence": True}
    unhashable_refs_event = {**event, "artifact_refs": [{"bad": 1}]}

    cases.extend(
        [
            lambda: validate_process_fn(unknown),
            lambda: validate_process_fn(cycle),
            lambda: validate_process_fn(bound_definition),
            lambda: validate_process_fn(mutating_query),
            lambda: validate_process_fn(unapproved_remote),
            lambda: validate_process_fn(bool_timeout),
            lambda: validate_process_fn(secret_title),
            lambda: validate_observation_fn(stale_observation),
            lambda: validate_observation_fn(space_dt_obs),
            lambda: validate_binding_fn(injected_binding),
            lambda: validate_binding_fn(bool_prio_binding),
            lambda: validate_envelope_fn(injected_envelope),
            lambda: validate_envelope_fn(bool_rev_envelope),
            lambda: validate_event_fn(unsafe_event),
            lambda: validate_event_fn(bool_seq_event),
            lambda: validate_event_fn(unhashable_refs_event),
        ]
    )
    for case in cases:
        expect_rejected(case)
    return len(cases)
