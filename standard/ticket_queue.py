#!/usr/bin/env python3
"""Reference ticketed process-queue adapter. Not a daemon.

RuntimeOwner is subactor (planfile / doctor-agent / control). HOME is
wellmanifest/poa. Enqueue without a registered inspectable ticket_id is
rejected. Operation consume binds ticket + process step. Scheduler is
sequential and honors happens-after dependencies.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "ticket-queue.schema.v1.json"
SEED_PATH = ROOT / "seed" / "p0p1-tickets.v1.json"
PROTO_PATH = ROOT / "wellmanifest" / "poa" / "v1" / "ticket_queue.proto"
IDENTIFIER = re.compile(r"^[a-z][a-z0-9._:-]*$")
ACTOR = re.compile(r"^(?:human|agent|service|mcp):[a-zA-Z0-9._:-]+$")
RFC3339 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
PROCESS_REF = re.compile(r"^poa://[a-z0-9.-]+/process/[a-z][a-z0-9._:-]*/v[1-9][0-9]*$")
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
}


class QueueContractError(ValueError):
    """Fail-closed diagnostic that never echoes untrusted values."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _parse_time(value: str) -> datetime:
    if RFC3339.fullmatch(value) is None:
        raise QueueContractError("POA-TIME-001", "timestamp is not RFC3339")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _require_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise QueueContractError("POA-ID-001", f"{label} is not a closed identifier")
    return value


def exact(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise QueueContractError("POA-DOC-001", "document must be an object")
    extra = set(value) - required - (optional or set())
    missing = required - set(value)
    if extra or missing:
        raise QueueContractError("POA-DOC-001", "document fields are not closed")
    return value


class TicketQueue:
    """In-memory event-sourced projection used by conformance, not production."""

    def __init__(self, seed: dict[str, Any]) -> None:
        self.seed = seed
        self.tickets: dict[str, dict[str, Any]] = {
            item["ticket_id"]: deepcopy(item) for item in seed["tickets"]
        }
        self.processes: dict[str, dict[str, Any]] = {
            item["ticket_id"]: deepcopy(item) for item in seed["processes"]
        }
        self.schedules: dict[str, dict[str, Any]] = {
            item["ticket_id"]: deepcopy(item) for item in seed["schedules"]
        }
        self.dependencies = [deepcopy(item) for item in seed["dependencies"]]
        self.quota = deepcopy(seed["account_quota"])
        self.events: list[dict[str, Any]] = []
        self.running_queues: set[str] = set()
        self.sequence = 0

    def _emit(self, event_type: str, ticket_id: str, causation_id: str) -> dict[str, Any]:
        if event_type not in EVENT_TYPES:
            raise QueueContractError("POA-EVENT-001", "event type is not registered")
        self.sequence += 1
        event = {
            "schema": "poa.ticket-event/v1",
            "event_id": f"evt.{self.sequence:06d}",
            "event_type": event_type,
            "ticket_id": ticket_id,
            "occurred_at": "2026-08-16T08:00:00+02:00",
            "sequence": self.sequence,
            "causation_id": causation_id,
            "raw_output_included": False,
            "secret_material_included": False,
        }
        self.events.append(event)
        return event

    def _ticket(self, ticket_id: str) -> dict[str, Any]:
        ticket = self.tickets.get(ticket_id)
        if ticket is None:
            raise QueueContractError("POA-QUEUE-002", "ticket is not registered")
        if ticket.get("inspectable") is not True:
            raise QueueContractError("POA-QUEUE-003", "ticket is not inspectable")
        return ticket

    def enqueue_task(self, task: dict[str, Any]) -> dict[str, Any]:
        exact(
            task,
            {"schema", "task_id", "ticket_id", "queue", "process_step_id", "actor", "status"},
        )
        if task["schema"] != "poa.task/v1":
            raise QueueContractError("POA-QUEUE-001", "task schema is invalid")
        ticket_id = task.get("ticket_id")
        if not ticket_id:
            raise QueueContractError("POA-QUEUE-001", "enqueue requires ticket_id")
        ticket = self._ticket(_require_id(ticket_id, "ticket_id"))
        if task["queue"] != ticket["queue"]:
            raise QueueContractError("POA-QUEUE-004", "task queue does not match ticket")
        process = self.processes[ticket_id]
        step_ids = {step["id"] for step in process["steps"]}
        if task["process_step_id"] not in step_ids:
            raise QueueContractError("POA-QUEUE-005", "process step is not on the ticket")
        if ACTOR.fullmatch(str(task["actor"])) is None:
            raise QueueContractError("POA-ID-001", "actor is not a closed identifier")
        event = self._emit("TaskQueued", ticket_id, task["task_id"])
        return event

    def register_internal_process(self, ticket: dict[str, Any], process: dict[str, Any]) -> dict[str, Any]:
        ticket_id = _require_id(ticket["ticket_id"], "ticket_id")
        if PROCESS_REF.fullmatch(str(process["process_ref"])) is None:
            raise QueueContractError("POA-DOC-001", "process_ref is invalid")
        ticket = deepcopy(ticket)
        ticket["inspectable"] = True
        ticket["runtime_owner"] = "subactor"
        self.tickets[ticket_id] = ticket
        self.processes[ticket_id] = deepcopy(process)
        self._emit("TicketOpened", ticket_id, "register-internal-process")
        return self._emit("ProcessRegistered", ticket_id, "register-internal-process")

    def schedule_ticket(self, scheduled: dict[str, Any], dependencies: list[dict[str, Any]]) -> dict[str, Any]:
        ticket_id = _require_id(scheduled["ticket_id"], "ticket_id")
        self._ticket(ticket_id)
        _parse_time(scheduled["not_before"])
        self.schedules[ticket_id] = deepcopy(scheduled)
        for dep in dependencies:
            if dep["type"] != "happens-after":
                raise QueueContractError("POA-SCHED-002", "dependency type is not happens-after")
            self._ticket(dep["from_ticket_id"])
            self._ticket(dep["to_ticket_id"])
            self.dependencies.append(deepcopy(dep))
        ticket = self.tickets[ticket_id]
        ticket["status"] = "scheduled"
        return self._emit("TicketScheduled", ticket_id, "schedule-ticket")

    def plan_twin_work(self, plan: dict[str, Any]) -> dict[str, Any]:
        ticket_id = _require_id(plan["ticket_id"], "ticket_id")
        if ticket_id not in self.tickets:
            raise QueueContractError("POA-QUEUE-002", "twin plan needs a registered ticket")
        self.processes[ticket_id] = {
            "ticket_id": ticket_id,
            "process_ref": self.tickets[ticket_id]["process_ref"],
            "title": "digital-twin local plan",
            "steps": deepcopy(plan["steps"]),
        }
        self.schedules[ticket_id] = {
            "schema": "poa.scheduled-ticket/v1",
            "ticket_id": ticket_id,
            "not_before": plan["not_before"],
            "timezone": plan["timezone"],
            "local_hour": _parse_time(plan["not_before"]).hour,
            "rrule": "",
            "trigger": "twin_plan",
        }
        return self._emit("DigitalTwinPlanRegistered", ticket_id, plan["plan_id"])

    def _deps_ready(self, ticket_id: str) -> bool:
        for dep in self.dependencies:
            if dep["to_ticket_id"] != ticket_id:
                continue
            predecessor = self.tickets[dep["from_ticket_id"]]
            if predecessor["status"] != "completed":
                return False
        return True

    def due_tickets(self, now: str) -> list[str]:
        moment = _parse_time(now)
        due: list[str] = []
        for ticket_id, schedule in self.schedules.items():
            ticket = self.tickets[ticket_id]
            if ticket["status"] not in {"scheduled", "ready", "blocked_dependency"}:
                continue
            if _parse_time(schedule["not_before"]) > moment:
                continue
            if ticket["queue"] in self.running_queues:
                continue
            if not self._deps_ready(ticket_id):
                ticket["status"] = "blocked_dependency"
                continue
            ticket["status"] = "ready"
            self._emit("TicketDue", ticket_id, "clock")
            due.append(ticket_id)
        return due

    def start_next_step(self, ticket_id: str, account_id: str) -> dict[str, Any]:
        ticket = self._ticket(ticket_id)
        if ticket["status"] == "blocked_quota":
            raise QueueContractError("POA-QUOTA-001", "ticket is blocked by operations quota")
        if not self._deps_ready(ticket_id):
            ticket["status"] = "blocked_dependency"
            raise QueueContractError("POA-SCHED-001", "dependency is not completed")
        process = self.processes[ticket_id]
        remaining_steps = process["steps"]
        if not remaining_steps:
            ticket["status"] = "completed"
            return self._emit("TaskCompleted", ticket_id, "queue-empty")
        step = remaining_steps[0]
        consume = self.consume_operation(ticket_id, step["id"], account_id)
        if consume["event_type"] == "OperationsQuotaExhausted":
            return consume
        ticket["status"] = "running"
        self.running_queues.add(ticket["queue"])
        self._emit("TaskStarted", ticket_id, step["id"])
        return consume

    def complete_current_step(self, ticket_id: str) -> dict[str, Any]:
        ticket = self._ticket(ticket_id)
        process = self.processes[ticket_id]
        if process["steps"]:
            process["steps"].pop(0)
        self.running_queues.discard(ticket["queue"])
        if process["steps"]:
            ticket["status"] = "ready"
        else:
            ticket["status"] = "completed"
        return self._emit("TaskCompleted", ticket_id, "complete-step")

    def consume_operation(self, ticket_id: str, process_step_id: str, account_id: str) -> dict[str, Any]:
        if not ticket_id or not process_step_id:
            raise QueueContractError("POA-QUOTA-003", "consume requires ticket and process step")
        self._ticket(ticket_id)
        if account_id != self.quota["account_id"]:
            raise QueueContractError("POA-QUOTA-004", "account is not the registered quota holder")
        step_ids = {step["id"] for step in self.processes[ticket_id]["steps"]}
        if process_step_id not in step_ids:
            raise QueueContractError("POA-QUEUE-005", "process step is not on the ticket")
        if self.quota["operations_remaining"] <= 0:
            self.tickets[ticket_id]["status"] = "blocked_quota"
            return self._emit("OperationsQuotaExhausted", ticket_id, process_step_id)
        self.quota["operations_remaining"] -= 1
        return self._emit("ProcessStepConsumedOperation", ticket_id, process_step_id)

    def allocate_twin_node(self, ticket_id: str, account_id: str, node_ref: str) -> dict[str, Any]:
        self._ticket(ticket_id)
        if account_id != self.quota["account_id"]:
            raise QueueContractError("POA-QUOTA-004", "account is not the registered quota holder")
        if not IDENTIFIER.fullmatch(node_ref):
            raise QueueContractError("POA-ID-001", "node_ref is not a closed identifier")
        if self.quota["twin_clones_in_use"] >= self.quota["twin_nodes_allowed"]:
            return self._emit("TwinNodeQuotaExhausted", ticket_id, node_ref)
        self.quota["twin_clones_in_use"] += 1
        return self._emit("TwinNodeAllocated", ticket_id, node_ref)

    def get_process_queue_view(self, ticket_id: str) -> dict[str, Any]:
        ticket = deepcopy(self._ticket(ticket_id))
        process = self.processes[ticket_id]
        schedule = self.schedules.get(ticket_id) or {
            "schema": "poa.scheduled-ticket/v1",
            "ticket_id": ticket_id,
            "not_before": "2026-08-16T08:00:00+02:00",
            "timezone": "Europe/Warsaw",
            "local_hour": 8,
            "rrule": "",
            "trigger": "clock",
        }
        deps = [dep for dep in self.dependencies if dep["to_ticket_id"] == ticket_id]
        return {
            "schema": "poa.process-queue-view/v1",
            "ticket": ticket,
            "steps": deepcopy(process["steps"]),
            "schedule": deepcopy(schedule),
            "dependencies": deepcopy(deps),
            "trigger": schedule["trigger"],
            "eta": process["steps"][0]["eta"] if process["steps"] else schedule["not_before"],
            "quota": deepcopy(self.quota),
        }

    def list_if_uri_nodes(self) -> dict[str, Any]:
        return deepcopy(self.seed["if_uri_catalog"])

    def get_operator_node_view(self) -> dict[str, Any]:
        return {
            "schema": "poa.operator-node-view/v1",
            "twin_clones": ["twin.clone.plesk-8791"],
            "if_uri_catalog": self.list_if_uri_nodes(),
            "twin_label": "Zakupione klony digital twin",
            "if_uri_label": "Nody (if-uri)",
        }


def load_seed() -> dict[str, Any]:
    seed = json.loads(SEED_PATH.read_text("utf-8"))
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
    missing = [name for name in REQUIRED_PROTO if name not in text]
    if missing:
        raise QueueContractError("POA-PROTO-001", "protobuf contract is incomplete")
    if "This file is a closed document family, not" not in text:
        raise QueueContractError("POA-PROTO-001", "protobuf must declare it is not a daemon")


def validate_schema() -> None:
    schema = json.loads(SCHEMA_PATH.read_text("utf-8"))
    if schema.get("$id") != "https://wellmanifest.dev/schemas/poa/ticket-queue.schema.v1.json":
        raise QueueContractError("POA-DOC-001", "schema identity is wrong")
    if "POA-QUEUE" not in json.dumps(schema) and "ticket_id" not in json.dumps(schema):
        raise QueueContractError("POA-DOC-001", "schema must require ticket_id")
    defs = schema["$defs"]
    if defs["task"]["required"] != [
        "schema",
        "task_id",
        "ticket_id",
        "queue",
        "process_step_id",
        "actor",
        "status",
    ]:
        raise QueueContractError("POA-QUEUE-001", "task contract dropped ticket_id")
    if defs["eventTrigger"]["properties"]["ticket_required"]["const"] is not True:
        raise QueueContractError("POA-QUEUE-001", "triggers must require a ticket")


def _task(ticket_id: str, step_id: str, queue: str) -> dict[str, Any]:
    return {
        "schema": "poa.task/v1",
        "task_id": f"task.{ticket_id.split('.')[-1]}",
        "ticket_id": ticket_id,
        "queue": queue,
        "process_step_id": step_id,
        "actor": "service:subactor-control",
        "status": "queued",
    }


def run_ticket_queue_conformance() -> dict[str, Any]:
    validate_proto()
    validate_schema()
    seed = load_seed()
    queue = TicketQueue(seed)
    rejected = 0

    def expect_code(code: str, action: Any) -> None:
        nonlocal rejected
        try:
            action()
        except QueueContractError as error:
            if error.code != code:
                raise
            rejected += 1
            return
        raise QueueContractError("POA-TEST-001", "expected a closed rejection")

    expect_code(
        "POA-QUEUE-001",
        lambda: queue.enqueue_task(
            {
                "schema": "poa.task/v1",
                "task_id": "task.naked",
                "ticket_id": "",
                "queue": "ops.auth",
                "process_step_id": "observe-worktree-5552b4a",
                "actor": "service:subactor-control",
                "status": "queued",
            }
        ),
    )
    expect_code(
        "POA-QUEUE-002",
        lambda: queue.enqueue_task(_task("poa.tkt.missing", "step", "ops.auth")),
    )
    queued = queue.enqueue_task(
        _task("poa.tkt.control-origin-unify", "observe-worktree-5552b4a", "ops.auth")
    )
    if queued["event_type"] != "TaskQueued":
        raise QueueContractError("POA-TEST-001", "registered ticket must enqueue")

    too_early = queue.due_tickets("2026-08-16T08:00:00+02:00")
    if "poa.tkt.control-origin-unify" in too_early:
        raise QueueContractError("POA-SCHED-001", "clock must honor not_before")
    due = queue.due_tickets("2026-08-16T09:00:00+02:00")
    if "poa.tkt.control-origin-unify" not in due:
        raise QueueContractError("POA-SCHED-001", "due clock ticket is missing")
    if "poa.tkt.saas-access-request" in due:
        raise QueueContractError("POA-SCHED-001", "dependent ticket ran before predecessor")

    predecessor = queue.tickets["poa.tkt.control-origin-unify"]
    predecessor["status"] = "completed"
    later = queue.due_tickets("2026-08-16T11:30:00+02:00")
    if "poa.tkt.saas-access-request" not in later:
        raise QueueContractError("POA-SCHED-001", "event trigger did not release the dependent ticket")

    consume = queue.consume_operation(
        "poa.tkt.quota-operations",
        "observe-remaining",
        "acct.subactor.basic",
    )
    if consume["event_type"] != "ProcessStepConsumedOperation":
        raise QueueContractError("POA-QUOTA-001", "quota consume did not emit the step event")
    queue.quota["operations_remaining"] = 0
    exhausted = queue.start_next_step("poa.tkt.prod-tls-handshake", "acct.subactor.basic")
    if exhausted["event_type"] != "OperationsQuotaExhausted":
        raise QueueContractError("POA-QUOTA-001", "zero remaining must stop the next step")
    if queue.tickets["poa.tkt.prod-tls-handshake"]["status"] != "blocked_quota":
        raise QueueContractError("POA-QUOTA-001", "exhausted ticket must stay inspectable as blocked_quota")
    expect_code(
        "POA-QUOTA-003",
        lambda: queue.consume_operation("", "observe-remaining", "acct.subactor.basic"),
    )

    queue.quota["twin_clones_in_use"] = queue.quota["twin_nodes_allowed"]
    node_full = queue.allocate_twin_node(
        "poa.tkt.quota-twin-nodes", "acct.subactor.basic", "twin.clone.extra"
    )
    if node_full["event_type"] != "TwinNodeQuotaExhausted":
        raise QueueContractError("POA-QUOTA-002", "full twin slots must block allocation")

    view = queue.get_process_queue_view("poa.tkt.control-origin-unify")
    if view["schema"] != "poa.process-queue-view/v1" or view["ticket"]["ticket_id"] != "poa.tkt.control-origin-unify":
        raise QueueContractError("POA-VIEW-001", "process queue view is not bound to the ticket")
    before = len(queue.events)
    queue.get_process_queue_view("poa.tkt.doctor-hygiene-2h")
    if len(queue.events) != before:
        raise QueueContractError("POA-VIEW-001", "query must not append events")

    catalog = queue.list_if_uri_nodes()
    nodes = queue.get_operator_node_view()
    if catalog["label"] != "Nody (if-uri)" or nodes["if_uri_label"] != "Nody (if-uri)":
        raise QueueContractError("POA-VIEW-002", "if-uri catalog lost its operator label")
    if "twin.clone.plesk-8791" not in nodes["twin_clones"]:
        raise QueueContractError("POA-VIEW-002", "purchased twin clones are missing")
    if catalog["source_uri"] != "file:///home/tom/github/if-uri":
        raise QueueContractError("POA-VIEW-002", "if-uri catalog must reference the live workspace")

    twin = queue.plan_twin_work(seed["twin_plans"][0])
    if twin["event_type"] != "DigitalTwinPlanRegistered":
        raise QueueContractError("POA-TWIN-001", "twin plan must become a ticketed process")

    return {
        "ok": True,
        "seed_tickets": len(seed["tickets"]),
        "triggers": len(seed["triggers"]),
        "adversarial_rejections": rejected,
        "events": [event["event_type"] for event in queue.events],
        "runtime_owner": seed["runtime_owner"],
    }


def main() -> int:
    try:
        report = run_ticket_queue_conformance()
    except QueueContractError as error:
        print(json.dumps({"ok": False, "error": error.code}, sort_keys=True))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
