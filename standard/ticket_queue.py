#!/usr/bin/env python3
"""Reference ticketed process-queue adapter. Not a daemon.

RuntimeOwner is subactor (planfile / doctor-agent / control). HOME is
wellmanifest/poa. Enqueue without a registered inspectable ticket_id is
rejected. Operation consume binds ticket + process step. Scheduler is
sequential and honors happens-after dependencies.
"""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

try:
    from standard import poa_primitives as _pr
    from standard import ticket_queue_admission as _adm
    from standard import ticket_queue_conformance as _qc
except ImportError:
    import poa_primitives as _pr  # type: ignore[no-redef]
    import ticket_queue_admission as _adm  # type: ignore[no-redef]
    import ticket_queue_conformance as _qc  # type: ignore[no-redef]

QueueContractError = _adm.QueueContractError
exact = _adm.exact
queue_plan_hash = _adm.queue_plan_hash
validate_queue_plan = _adm.validate_queue_plan
load_seed = _adm.load_seed
validate_proto = _adm.validate_proto
validate_schema = _adm.validate_schema
EVENT_TYPES = _adm.EVENT_TYPES
IDENTIFIER = _adm.IDENTIFIER
PROCESS_REF = _adm.PROCESS_REF


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
        self.queue_plans: dict[str, dict[str, Any]] = {}
        self.queue_admissions: dict[str, dict[str, Any]] = {}
        self.queue_admission_states: dict[str, str] = {}

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

    def _emit_admission(self, event_type: str, plan: dict[str, Any]) -> dict[str, Any]:
        if event_type not in EVENT_TYPES:
            raise QueueContractError("POA-EVENT-001", "event type is not registered")
        self.sequence += 1
        event = {
            "schema": "poa.queue-admission-event/v2",
            "event_id": f"evt.{self.sequence:06d}",
            "event_type": event_type,
            "ticket_id": plan["ticket_id"],
            "queue_revision": plan["queue_revision"],
            "plan_hash": plan["plan_hash"],
        }
        self.events.append(event)
        return event

    def _ticket(self, ticket_id: Any) -> dict[str, Any]:
        if not isinstance(ticket_id, str):
            raise QueueContractError("POA-ID-001", "ticket_id must be a string")
        ticket = self.tickets.get(ticket_id)
        if ticket is None:
            raise QueueContractError("POA-QUEUE-002", "ticket is not registered")
        if ticket.get("inspectable") is not True:
            raise QueueContractError("POA-QUEUE-003", "ticket is not inspectable")
        return ticket

    def propose_process_queue(self, plan: dict[str, Any]) -> dict[str, Any]:
        validate_queue_plan(plan)
        ticket_id = plan["ticket_id"]
        self._ticket(ticket_id)
        current = self.queue_plans.get(ticket_id)
        expected_revision = 1 if current is None else current["queue_revision"] + 1
        if plan["queue_revision"] != expected_revision:
            raise QueueContractError(
                "POA-REVISION-001", "queue plan does not advance current revision"
            )
        if current is not None:
            raise QueueContractError(
                "POA-REPLAN-001", "an existing queue must use same-ticket replan"
            )
        self.queue_plans[ticket_id] = deepcopy(plan)
        self.queue_admissions.pop(ticket_id, None)
        self.queue_admission_states[ticket_id] = "planned"
        return self._emit_admission("ProcessQueuePlanned", plan)

    def decide_process_queue_admission(self, admission: dict[str, Any]) -> dict[str, Any]:
        exact(
            admission,
            {
                "schema",
                "admission_id",
                "ticket_id",
                "queue_revision",
                "plan_hash",
                "decision",
                "decided_by",
                "independent",
                "reason_code",
                "authority_ref",
            },
        )
        if admission["schema"] != "poa.queue-admission/v2":
            raise QueueContractError("POA-ADMISSION-001", "admission schema is invalid")
        for label in ("admission_id", "ticket_id", "reason_code"):
            _adm.require_id(admission[label], label)
        decision = _pr.str_choice(
            admission["decision"],
            {"accept", "reject"},
            QueueContractError("POA-ADMISSION-001", "admission decision is invalid"),
        )
        if admission["independent"] is not True:
            raise QueueContractError("POA-ADMISSION-002", "admission is not independent")
        _adm.require_actor(admission["decided_by"], "admitter")
        ticket_id = admission["ticket_id"]
        plan = self.queue_plans.get(ticket_id)
        if plan is None:
            raise QueueContractError("POA-ADMISSION-001", "queue plan is not registered")
        rev = admission["queue_revision"]
        if (
            isinstance(rev, bool)
            or not isinstance(rev, int)
            or rev != plan["queue_revision"]
            or admission["plan_hash"] != plan["plan_hash"]
        ):
            raise QueueContractError(
                "POA-REVISION-001", "admission does not bind current revision and hash"
            )
        if admission["decided_by"] == plan["proposed_by"]:
            raise QueueContractError(
                "POA-ADMISSION-002", "proposer cannot admit its own queue plan"
            )
        authority_ref = _adm.require_authority_ref(
            admission["authority_ref"], "admission authority is invalid"
        )
        if decision == "accept" and authority_ref != plan["authority_ref"]:
            raise QueueContractError(
                "POA-AUTH-004", "admission authority does not bind the exact plan"
            )
        self.queue_admissions[ticket_id] = deepcopy(admission)
        state = "admitted" if admission["decision"] == "accept" else "rejected"
        self.queue_admission_states[ticket_id] = state
        event_type = "ProcessQueueAdmitted" if state == "admitted" else "ProcessQueueRejected"
        return self._emit_admission(event_type, plan)

    def replan_process_queue(self, command: dict[str, Any]) -> dict[str, Any]:
        exact(command, {"schema", "ticket_id", "expected_queue_revision", "replacement"})
        if command["schema"] != "poa.queue-replan/v2":
            raise QueueContractError("POA-REPLAN-001", "replan schema is invalid")
        ticket_id = _adm.require_id(command["ticket_id"], "ticket_id")
        current = self.queue_plans.get(ticket_id)
        admission = self.queue_admissions.get(ticket_id)
        if current is None or admission is None or admission["decision"] != "reject":
            raise QueueContractError("POA-REPLAN-001", "only a rejected queue can replan")
        replacement = command["replacement"]
        validate_queue_plan(replacement)
        expected_rev = command["expected_queue_revision"]
        if (
            isinstance(expected_rev, bool)
            or not isinstance(expected_rev, int)
            or expected_rev != current["queue_revision"]
            or replacement["ticket_id"] != ticket_id
            or replacement["queue_revision"] != current["queue_revision"] + 1
            or replacement["plan_hash"] == current["plan_hash"]
        ):
            raise QueueContractError(
                "POA-REVISION-001", "replan must replace the current revision in one ticket"
            )
        self.queue_plans[ticket_id] = deepcopy(replacement)
        self.queue_admissions.pop(ticket_id, None)
        self.queue_admission_states[ticket_id] = "planned"
        return self._emit_admission("ProcessQueueReplanned", replacement)

    def start_admitted_queue(self, command: dict[str, Any]) -> dict[str, Any]:
        exact(command, {"schema", "ticket_id", "queue_revision", "plan_hash", "executor"})
        if command["schema"] != "poa.queue-start/v2":
            raise QueueContractError("POA-ADMISSION-003", "queue start schema is invalid")
        ticket_id = _adm.require_id(command["ticket_id"], "ticket_id")
        queue_revision = command["queue_revision"]
        plan_hash = command["plan_hash"]
        executor = _adm.require_actor(command["executor"], "executor")
        self._ticket(ticket_id)
        plan = self.queue_plans.get(ticket_id)
        admission = self.queue_admissions.get(ticket_id)
        if (
            plan is None
            or admission is None
            or admission["decision"] != "accept"
            or self.queue_admission_states.get(ticket_id) != "admitted"
        ):
            raise QueueContractError("POA-ADMISSION-003", "queue plan is not admitted")
        if (
            isinstance(queue_revision, bool)
            or not isinstance(queue_revision, int)
            or queue_revision != plan["queue_revision"]
            or plan_hash != plan["plan_hash"]
        ):
            raise QueueContractError("POA-REVISION-001", "executor received a stale queue plan")
        if executor in {plan["proposed_by"], admission["decided_by"]}:
            raise QueueContractError(
                "POA-ADMISSION-002", "executor must be independent of proposer and admitter"
            )
        if admission["authority_ref"] != plan["authority_ref"]:
            raise QueueContractError("POA-AUTH-004", "executor authority binding changed")
        self.queue_admission_states[ticket_id] = "running"
        return self._emit_admission("ProcessQueueStarted", plan)

    def get_process_queue_admission_view(self, ticket_id: str) -> dict[str, Any]:
        ticket_id = _adm.require_id(ticket_id, "ticket_id")
        self._ticket(ticket_id)
        plan = self.queue_plans.get(ticket_id)
        if plan is None:
            raise QueueContractError("POA-VIEW-003", "ticket has no planned process queue")
        return {
            "schema": "poa.queue-admission-view/v2",
            "ticket_id": ticket_id,
            "queue_revision": plan["queue_revision"],
            "state": self.queue_admission_states[ticket_id],
            "plan": deepcopy(plan),
            "admission": deepcopy(self.queue_admissions.get(ticket_id)),
        }

    def enqueue_task(self, task: dict[str, Any]) -> dict[str, Any]:
        exact(
            task, {"schema", "task_id", "ticket_id", "queue", "process_step_id", "actor", "status"}
        )
        if task["schema"] != "poa.task/v1":
            raise QueueContractError("POA-QUEUE-001", "task schema is invalid")
        ticket_id = task.get("ticket_id")
        if not ticket_id:
            raise QueueContractError("POA-QUEUE-001", "enqueue requires ticket_id")
        ticket = self._ticket(_adm.require_id(ticket_id, "ticket_id"))
        if task["queue"] != ticket["queue"]:
            raise QueueContractError("POA-QUEUE-004", "task queue does not match ticket")
        step_id = task["process_step_id"]
        step_ids = {step["id"] for step in self.processes[ticket_id]["steps"]}
        if not isinstance(step_id, str) or step_id not in step_ids:
            raise QueueContractError("POA-QUEUE-005", "process step is not on the ticket")
        _pr.str_choice(
            task["status"],
            {"queued", "started", "completed", "rejected"},
            QueueContractError("POA-QUEUE-001", "task status is invalid"),
        )
        _adm.require_actor(task["actor"], "actor")
        _adm.require_id(task["task_id"], "task_id")
        return self._emit("TaskQueued", ticket_id, task["task_id"])

    def register_internal_process(
        self, ticket: dict[str, Any], process: dict[str, Any]
    ) -> dict[str, Any]:
        if not isinstance(ticket, dict) or not isinstance(process, dict):
            raise QueueContractError("POA-DOC-001", "ticket and process must be objects")
        ticket_id = _adm.require_id(ticket.get("ticket_id"), "ticket_id")
        queue_name = ticket.get("queue")
        if not isinstance(queue_name, str) or not queue_name:
            raise QueueContractError("POA-QUEUE-001", "ticket requires a non-empty queue")
        _adm.require_process_ref(process.get("process_ref"))
        _adm.validate_internal_process_steps(process.get("steps"))
        ticket = deepcopy(ticket)
        ticket["inspectable"] = True
        ticket["runtime_owner"] = "subactor"
        self.tickets[ticket_id] = ticket
        self.processes[ticket_id] = deepcopy(process)
        self._emit("TicketOpened", ticket_id, "register-internal-process")
        return self._emit("ProcessRegistered", ticket_id, "register-internal-process")

    def schedule_ticket(
        self, scheduled: dict[str, Any], dependencies: list[dict[str, Any]]
    ) -> dict[str, Any]:
        if not isinstance(scheduled, dict):
            raise QueueContractError("POA-DOC-001", "schedule must be an object")
        ticket_id = _adm.require_id(scheduled.get("ticket_id"), "ticket_id")
        self._ticket(ticket_id)
        _adm.parse_time(scheduled.get("not_before"))
        validated_deps = _adm.validate_ticket_dependencies(
            self.tickets, self.dependencies, dependencies, self._ticket
        )
        self.schedules[ticket_id] = deepcopy(scheduled)
        self.dependencies.extend(validated_deps)
        self.tickets[ticket_id]["status"] = "scheduled"
        return self._emit("TicketScheduled", ticket_id, "schedule-ticket")

    def plan_twin_work(self, plan: dict[str, Any]) -> dict[str, Any]:
        _adm.validate_twin_plan(plan)
        ticket_id = plan["ticket_id"]
        self._ticket(ticket_id)
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
            "local_hour": _adm.parse_time(plan["not_before"]).hour,
            "rrule": "",
            "trigger": "twin_plan",
        }
        return self._emit("DigitalTwinPlanRegistered", ticket_id, plan["plan_id"])

    def _deps_ready(self, ticket_id: str) -> bool:
        return all(
            self.tickets[dep["from_ticket_id"]]["status"] == "completed"
            for dep in self.dependencies
            if dep["to_ticket_id"] == ticket_id
        )

    def due_tickets(self, now: str) -> list[str]:
        moment = _adm.parse_time(now)
        due: list[str] = []
        for ticket_id, schedule in self.schedules.items():
            ticket = self.tickets[ticket_id]
            if ticket["status"] not in {"scheduled", "ready", "blocked_dependency"}:
                continue
            if _adm.parse_time(schedule["not_before"]) > moment:
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
        remaining_steps = self.processes[ticket_id]["steps"]
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
        ticket["status"] = "ready" if process["steps"] else "completed"
        return self._emit("TaskCompleted", ticket_id, "complete-step")

    def consume_operation(
        self, ticket_id: str, process_step_id: str, account_id: str
    ) -> dict[str, Any]:
        if (
            not isinstance(ticket_id, str)
            or not isinstance(process_step_id, str)
            or not ticket_id
            or not process_step_id
        ):
            raise QueueContractError("POA-QUOTA-003", "consume requires ticket and process step")
        self._ticket(ticket_id)
        if not isinstance(account_id, str) or account_id != self.quota["account_id"]:
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
        if not isinstance(account_id, str) or account_id != self.quota["account_id"]:
            raise QueueContractError("POA-QUOTA-004", "account is not the registered quota holder")
        _adm.require_id(node_ref, "node_ref")
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


def run_ticket_queue_conformance() -> dict[str, Any]:
    return _qc.run_queue_conformance(TicketQueue)


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
