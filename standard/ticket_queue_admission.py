#!/usr/bin/env python3
"""POA v1/v2 ticket queue contract constants, plan-hash, seed, proto, and schema validators."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

try:
    from standard import poa_primitives as _pr
except ImportError:
    import poa_primitives as _pr  # type: ignore[no-redef]

QueueContractError = _pr.QueueContractError
exact = _pr.exact_queue
parse_time = _pr.parse_queue_time

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "ticket-queue.schema.v1.json"
ADMISSION_SCHEMA_PATH = ROOT / "ticket-queue.schema.v2.json"
SEED_PATH = ROOT / "seed" / "p0p1-tickets.v1.json"
PROTO_PATH = ROOT / "wellmanifest" / "poa" / "v1" / "ticket_queue.proto"
ADMISSION_PROTO_PATH = ROOT / "wellmanifest" / "poa" / "v2" / "ticket_queue.proto"

IDENTIFIER = re.compile(r"^[a-z][a-z0-9._:-]*$")
ACTOR = re.compile(r"^(?:human|agent|service|mcp):[a-zA-Z0-9._:-]+$")
PROCESS_REF = re.compile(r"^poa://[a-z0-9.-]+/process/[a-z][a-z0-9._:-]*/v[1-9][0-9]*$")
PROCESS_URI = re.compile(r"^[a-z][a-z0-9+.-]*://[A-Za-z0-9._~:/?#@!$&'()+,;=%-]+$")
AUTHORITY_REF = re.compile(r"^(?:|grant://[A-Za-z0-9._~:/?#@!$&'()+,;=%-]+)$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")

REQUIRED_PROTO = (
    "message Ticket",
    "message Task",
    "message ScheduledTicket",
    "message TicketDependency",
    "message ProcessQueueView",
    "message DigitalTwinPlan",
    "message AccountQuota",
    "message EnqueueTask",
    "message RegisterInternalProcess",
    "message ScheduleTicket",
    "message PlanTwinWork",
    "message ConsumeOperation",
    "message AllocateTwinNode",
    "message GetTicketWithProcessQueue",
    "message GetProcessQueueView",
    "message ListIfUriNodes",
    "rpc EnqueueTask",
    "rpc GetProcessQueueView",
    "rpc ListIfUriNodes",
)
REQUIRED_ADMISSION_PROTO = (
    "message QueuePlan",
    "message QueueAdmission",
    "message ReplanProcessQueue",
    "message StartAdmittedProcessQueue",
    "message QueueAdmissionView",
    "rpc ProposeProcessQueue",
    "rpc DecideProcessQueueAdmission",
    "rpc ReplanProcessQueue",
    "rpc StartAdmittedProcessQueue",
    "rpc GetProcessQueueAdmissionView",
)
EVENT_TYPES = {
    "TicketOpened",
    "ProcessRegistered",
    "TaskQueued",
    "TaskStarted",
    "TaskCompleted",
    "EnqueueRejected",
    "TicketScheduled",
    "TicketDue",
    "DigitalTwinPlanRegistered",
    "ProcessStepConsumedOperation",
    "OperationsQuotaExhausted",
    "TwinNodeAllocated",
    "TwinNodeQuotaExhausted",
    "ProcessQueuePlanned",
    "ProcessQueueRejected",
    "ProcessQueueAdmitted",
    "ProcessQueueReplanned",
    "ProcessQueueStarted",
}


def require_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise QueueContractError("POA-ID-001", f"{label} is not a closed identifier")
    return value


def require_actor(value: Any, label: str) -> str:
    if not isinstance(value, str) or ACTOR.fullmatch(value) is None:
        raise QueueContractError("POA-ID-001", f"{label} is not a closed actor")
    return value


def require_authority_ref(value: Any, message: str = "authority reference is invalid") -> str:
    if not isinstance(value, str) or AUTHORITY_REF.fullmatch(value) is None:
        raise QueueContractError("POA-AUTH-004", message)
    return value


def queue_plan_hash(plan: dict[str, Any]) -> str:
    """Hash the closed ASCII-only v2 plan domain with RFC 8785-equivalent bytes."""
    body = {key: value for key, value in plan.items() if key != "plan_hash"}
    return _pr.digest_text(_pr.canonical(body))


def validate_queue_plan(plan: dict[str, Any]) -> None:
    _pr.reject_secret_material(
        plan, error=QueueContractError("POA-DOC-001", "credential material is forbidden")
    )
    exact(
        plan,
        {
            "schema",
            "plan_id",
            "ticket_id",
            "queue_revision",
            "proposed_by",
            "created_at",
            "steps",
            "authority_ref",
            "hash_profile",
            "plan_hash",
        },
    )
    if plan["schema"] != "poa.queue-plan/v2":
        raise QueueContractError("POA-ADMISSION-001", "queue plan schema is invalid")
    for label in ("plan_id", "ticket_id"):
        require_id(plan[label], label)
    require_actor(plan["proposed_by"], "proposer")
    parse_time(plan["created_at"])
    revision = plan["queue_revision"]
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise QueueContractError("POA-REVISION-001", "queue revision is invalid")
    authority_ref = require_authority_ref(plan["authority_ref"])
    steps = plan["steps"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= 16:
        raise QueueContractError("POA-DAG-001", "queue plan steps are invalid")
    step_ids: set[str] = set()
    irreversible = False
    for step in steps:
        exact(
            step,
            {
                "id",
                "capability_ref",
                "process_uri",
                "kind",
                "depends_on",
                "rollback",
                "rollback_process_uri",
            },
        )
        step_id = require_id(step["id"], "step id")
        if step_id in step_ids:
            raise QueueContractError("POA-DAG-001", "queue step ids are not unique")
        step_ids.add(step_id)
        if (
            not isinstance(step["capability_ref"], str)
            or PROCESS_URI.fullmatch(step["capability_ref"]) is None
            or not isinstance(step["process_uri"], str)
            or PROCESS_URI.fullmatch(step["process_uri"]) is None
        ):
            raise QueueContractError("POA-URI-001", "queue step URI binding is invalid")
        if step["kind"] not in {"query", "command"}:
            raise QueueContractError("POA-DAG-001", "queue step kind is invalid")
        dependencies = step["depends_on"]
        if (
            not isinstance(dependencies, list)
            or len(dependencies) > 16
            or any(not isinstance(dep, str) for dep in dependencies)
        ):
            raise QueueContractError("POA-DAG-001", "queue dependencies are invalid")
        rollback = step["rollback"]
        rollback_uri = step["rollback_process_uri"]
        if not isinstance(rollback_uri, str):
            raise QueueContractError("POA-ROLLBACK-001", "rollback URI must be a string")
        if rollback == "compensating":
            if PROCESS_URI.fullmatch(rollback_uri) is None:
                raise QueueContractError("POA-ROLLBACK-001", "compensation URI is missing")
        elif rollback in {"automatic", "none"}:
            if rollback_uri:
                raise QueueContractError("POA-ROLLBACK-001", "rollback URI is not allowed")
            irreversible = irreversible or rollback == "none"
        else:
            raise QueueContractError("POA-ROLLBACK-001", "rollback mode is invalid")
    for step in steps:
        dependencies = step["depends_on"]
        if len(dependencies) != len(set(dependencies)) or any(
            dependency not in step_ids or dependency == step["id"] for dependency in dependencies
        ):
            raise QueueContractError("POA-DAG-001", "queue dependency is invalid")
    pending = {step["id"]: set(step["depends_on"]) for step in steps}
    while pending:
        ready = {step_id for step_id, deps in pending.items() if not deps}
        if not ready:
            raise QueueContractError("POA-DAG-001", "queue plan contains a cycle")
        pending = {
            step_id: deps - ready for step_id, deps in pending.items() if step_id not in ready
        }
    if irreversible and not authority_ref:
        raise QueueContractError(
            "POA-AUTH-004", "irreversible queue plan requires higher authority"
        )
    if plan["hash_profile"] != "RFC8785+SHA-256":
        raise QueueContractError("POA-PLAN-002", "plan hash profile is invalid")
    plan_hash = plan["plan_hash"]
    if (
        not isinstance(plan_hash, str)
        or SHA256.fullmatch(plan_hash) is None
        or queue_plan_hash(plan) != plan_hash
    ):
        raise QueueContractError("POA-PLAN-002", "plan hash does not bind the queue plan")


def load_seed() -> dict[str, Any]:
    dup_err = QueueContractError("POA-SEED-001", "seed JSON contains duplicate keys")
    seed = _pr.load_strict_json(SEED_PATH, duplicate_error=dup_err)
    if seed.get("schema") != "poa.ticket-queue-seed/v1":
        raise QueueContractError("POA-SEED-001", "seed schema is invalid")
    ticket_ids = [item["ticket_id"] for item in seed["tickets"]]
    if len(ticket_ids) != len(set(ticket_ids)):
        raise QueueContractError("POA-SEED-001", "seed ticket ids are not unique")
    process_ids = [item["ticket_id"] for item in seed["processes"]]
    if set(process_ids) != set(ticket_ids):
        raise QueueContractError("POA-SEED-001", "every ticket must have a process queue")
    if "www-sub-actor-16-merged" not in seed["completed_not_tickets"]:
        raise QueueContractError("POA-SEED-002", "merged 16 must not be an open ticket")
    if any(item["ticket_id"] == "poa.tkt.www-sub-actor-16" for item in seed["tickets"]):
        raise QueueContractError("POA-SEED-002", "merged 16 must not be seeded as work")
    if "control-restart" not in seed["do_not_execute"]:
        raise QueueContractError("POA-SEED-002", "control restart must stay unexecuted")
    if seed["runtime_owner"] != "subactor" or seed["home"] != "wellmanifest":
        raise QueueContractError("POA-SEED-001", "placement is not the adopted pack")
    for trigger in seed["triggers"]:
        if trigger["ticket_required"] is not True or not trigger["ticket_id"]:
            raise QueueContractError("POA-QUEUE-001", "trigger is missing a ticket")
    return seed


def validate_proto() -> None:
    text = PROTO_PATH.read_text("utf-8")
    if any(name not in text for name in REQUIRED_PROTO):
        raise QueueContractError("POA-PROTO-001", "protobuf contract is incomplete")
    if "This file is a closed document family, not" not in text:
        raise QueueContractError("POA-PROTO-001", "protobuf must declare it is not a daemon")
    admission_text = ADMISSION_PROTO_PATH.read_text("utf-8")
    if any(name not in admission_text for name in REQUIRED_ADMISSION_PROTO) or (
        "RuntimeOwner is Subactor" not in admission_text
    ):
        raise QueueContractError("POA-PROTO-002", "admission protobuf is incomplete")


def validate_schema() -> None:
    dup_err = QueueContractError("POA-DOC-001", "schema JSON contains duplicate keys")
    schema = _pr.load_strict_json(SCHEMA_PATH, duplicate_error=dup_err)
    if schema.get("$id") != "https://wellmanifest.dev/schemas/poa/ticket-queue.schema.v1.json":
        raise QueueContractError("POA-DOC-001", "schema identity is wrong")
    serialized = json.dumps(schema)
    if "POA-QUEUE" not in serialized and "ticket_id" not in serialized:
        raise QueueContractError("POA-DOC-001", "schema must require ticket_id")
    defs = schema["$defs"]
    expected_task_req = [
        "schema",
        "task_id",
        "ticket_id",
        "queue",
        "process_step_id",
        "actor",
        "status",
    ]
    if defs["task"]["required"] != expected_task_req:
        raise QueueContractError("POA-QUEUE-001", "task contract dropped ticket_id")
    if defs["eventTrigger"]["properties"]["ticket_required"]["const"] is not True:
        raise QueueContractError("POA-QUEUE-001", "triggers must require a ticket")
    admission_schema = _pr.load_strict_json(ADMISSION_SCHEMA_PATH, duplicate_error=dup_err)
    if admission_schema.get("$id") != (
        "https://wellmanifest.dev/schemas/poa/ticket-queue.schema.v2.json"
    ):
        raise QueueContractError("POA-DOC-002", "admission schema identity is wrong")
    admission_defs = admission_schema.get("$defs") or {}
    required_defs = {
        "queuePlan",
        "queueAdmission",
        "queueReplan",
        "queueStart",
        "queueAdmissionView",
        "queueAdmissionEvent",
    }
    if not required_defs.issubset(admission_defs):
        raise QueueContractError("POA-DOC-002", "admission document family is incomplete")
    if admission_defs["queueAdmission"]["properties"]["independent"]["const"] is not True:
        raise QueueContractError("POA-ADMISSION-002", "admission must be independent")
