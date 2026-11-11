#!/usr/bin/env python3
"""POA v1/v2 ticket queue positive and adversarial conformance runner."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

try:
    from standard import ticket_queue_admission as _adm
except ImportError:
    import ticket_queue_admission as _adm  # type: ignore[no-redef]

QueueContractError = _adm.QueueContractError
queue_plan_hash = _adm.queue_plan_hash


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


def _queue_plan(
    ticket_id: str,
    revision: int,
    plan_id: str,
    *,
    authority_ref: str,
    rollback: str = "none",
) -> dict[str, Any]:
    plan = {
        "schema": "poa.queue-plan/v2",
        "plan_id": plan_id,
        "ticket_id": ticket_id,
        "queue_revision": revision,
        "proposed_by": "agent:subactor-orchestrator",
        "created_at": "2026-08-25T16:20:00+02:00",
        "steps": [
            {
                "id": "apply-change",
                "capability_ref": "capability://repository/change/apply",
                "process_uri": "repo://subactor/platform/ticket/change/apply",
                "kind": "command",
                "depends_on": [],
                "rollback": rollback,
                "rollback_process_uri": (
                    "repo://subactor/platform/ticket/change/compensate"
                    if rollback == "compensating"
                    else ""
                ),
            }
        ],
        "authority_ref": authority_ref,
        "hash_profile": "RFC8785+SHA-256",
        "plan_hash": "0" * 64,
    }
    plan["plan_hash"] = queue_plan_hash(plan)
    return plan


def _admission(plan: dict[str, Any], decision: str, decided_by: str) -> dict[str, Any]:
    return {
        "schema": "poa.queue-admission/v2",
        "admission_id": f"admission.{plan['queue_revision']}",
        "ticket_id": plan["ticket_id"],
        "queue_revision": plan["queue_revision"],
        "plan_hash": plan["plan_hash"],
        "decision": decision,
        "decided_by": decided_by,
        "independent": True,
        "reason_code": "policy.conformance",
        "authority_ref": plan["authority_ref"],
    }


def _queue_start(
    plan: dict[str, Any],
    executor: str,
    *,
    revision: int | None = None,
) -> dict[str, Any]:
    return {
        "schema": "poa.queue-start/v2",
        "ticket_id": plan["ticket_id"],
        "queue_revision": plan["queue_revision"] if revision is None else revision,
        "plan_hash": plan["plan_hash"],
        "executor": executor,
    }


def run_queue_conformance(queue_cls: type[Any]) -> dict[str, Any]:
    _adm.validate_proto()
    _adm.validate_schema()
    seed = _adm.load_seed()
    queue = queue_cls(seed)
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

    irreversible_without_authority = _queue_plan(
        "poa.tkt.mailpit", 1, "plan.mailpit.1", authority_ref=""
    )
    expect_code(
        "POA-AUTH-004",
        lambda: queue.propose_process_queue(irreversible_without_authority),
    )

    plan = _queue_plan(
        "poa.tkt.ingress-caddy",
        1,
        "plan.ingress-caddy.1",
        authority_ref="grant://human/founder/ingress-caddy-plan-1",
    )
    invalid_hash = deepcopy(plan)
    invalid_hash["plan_hash"] = "f" * 64
    expect_code("POA-PLAN-002", lambda: queue.propose_process_queue(invalid_hash))

    bool_rev = deepcopy(plan)
    bool_rev["queue_revision"] = True
    bool_rev["plan_hash"] = queue_plan_hash(bool_rev)
    expect_code("POA-REVISION-001", lambda: queue.propose_process_queue(bool_rev))

    unhashable_deps = deepcopy(plan)
    unhashable_deps["steps"][0]["depends_on"] = [{"bad": 1}]
    unhashable_deps["plan_hash"] = queue_plan_hash(unhashable_deps)
    expect_code("POA-DAG-001", lambda: queue.propose_process_queue(unhashable_deps))

    non_str_auth = deepcopy(plan)
    non_str_auth["authority_ref"] = None
    non_str_auth["plan_hash"] = queue_plan_hash(non_str_auth)
    expect_code("POA-AUTH-004", lambda: queue.propose_process_queue(non_str_auth))

    planned = queue.propose_process_queue(plan)
    if planned["event_type"] != "ProcessQueuePlanned":
        raise QueueContractError("POA-TEST-001", "queue plan did not enter admission")
    before_view = len(queue.events)
    planned_view = queue.get_process_queue_admission_view(plan["ticket_id"])
    if planned_view["state"] != "planned" or len(queue.events) != before_view:
        raise QueueContractError("POA-VIEW-003", "admission view is not read-only")

    self_admission = _admission(plan, "accept", plan["proposed_by"])
    expect_code(
        "POA-ADMISSION-002",
        lambda: queue.decide_process_queue_admission(self_admission),
    )
    rejection = _admission(plan, "reject", "service:subactor-validator")
    rejected_event = queue.decide_process_queue_admission(rejection)
    if rejected_event["event_type"] != "ProcessQueueRejected":
        raise QueueContractError("POA-TEST-001", "rejection event is missing")
    expect_code(
        "POA-ADMISSION-003",
        lambda: queue.start_admitted_queue(_queue_start(plan, "service:subactor-executor")),
    )

    replacement = _queue_plan(
        plan["ticket_id"],
        2,
        "plan.ingress-caddy.2",
        authority_ref="grant://human/founder/ingress-caddy-plan-2",
        rollback="compensating",
    )
    wrong_ticket_replacement = deepcopy(replacement)
    wrong_ticket_replacement["ticket_id"] = "poa.tkt.mailpit"
    wrong_ticket_replacement["plan_hash"] = queue_plan_hash(wrong_ticket_replacement)
    expect_code(
        "POA-REVISION-001",
        lambda: queue.replan_process_queue(
            {
                "schema": "poa.queue-replan/v2",
                "ticket_id": plan["ticket_id"],
                "expected_queue_revision": 1,
                "replacement": wrong_ticket_replacement,
            }
        ),
    )
    replanned = queue.replan_process_queue(
        {
            "schema": "poa.queue-replan/v2",
            "ticket_id": plan["ticket_id"],
            "expected_queue_revision": 1,
            "replacement": replacement,
        }
    )
    if replanned["event_type"] != "ProcessQueueReplanned":
        raise QueueContractError("POA-TEST-001", "same-ticket replan event is missing")

    stale_admission = _admission(plan, "accept", "service:subactor-validator")
    expect_code(
        "POA-REVISION-001",
        lambda: queue.decide_process_queue_admission(stale_admission),
    )
    admitted = _admission(replacement, "accept", "service:subactor-validator")
    admitted_event = queue.decide_process_queue_admission(admitted)
    if admitted_event["event_type"] != "ProcessQueueAdmitted":
        raise QueueContractError("POA-TEST-001", "admission event is missing")
    expect_code(
        "POA-ADMISSION-002",
        lambda: queue.start_admitted_queue(_queue_start(replacement, "service:subactor-validator")),
    )
    expect_code(
        "POA-REVISION-001",
        lambda: queue.start_admitted_queue(
            _queue_start(
                replacement,
                "service:subactor-executor",
                revision=replacement["queue_revision"] - 1,
            )
        ),
    )
    started = queue.start_admitted_queue(_queue_start(replacement, "service:subactor-executor"))
    if started["event_type"] != "ProcessQueueStarted":
        raise QueueContractError("POA-TEST-001", "admitted queue did not start")

    too_early = queue.due_tickets("2026-08-16T08:00:00+02:00")
    if "poa.tkt.control-origin-unify" in too_early:
        raise QueueContractError("POA-SCHED-001", "clock must honor not_before")
    due = queue.due_tickets("2026-08-16T09:00:00+02:00")
    if "poa.tkt.control-origin-unify" not in due:
        raise QueueContractError("POA-SCHED-001", "due clock ticket is missing")
    if "poa.tkt.saas-access-request" in due:
        raise QueueContractError("POA-SCHED-001", "dependent ticket ran before predecessor")

    queue.tickets["poa.tkt.control-origin-unify"]["status"] = "completed"
    later = queue.due_tickets("2026-08-16T11:30:00+02:00")
    if "poa.tkt.saas-access-request" not in later:
        raise QueueContractError("POA-SCHED-001", "event trigger did not release dependent ticket")

    consume = queue.consume_operation(
        "poa.tkt.quota-operations", "observe-remaining", "acct.subactor.basic"
    )
    if consume["event_type"] != "ProcessStepConsumedOperation":
        raise QueueContractError("POA-QUOTA-001", "quota consume did not emit the step event")
    queue.quota["operations_remaining"] = 0
    exhausted = queue.start_next_step("poa.tkt.prod-tls-handshake", "acct.subactor.basic")
    if exhausted["event_type"] != "OperationsQuotaExhausted":
        raise QueueContractError("POA-QUOTA-001", "zero remaining must stop the next step")
    if queue.tickets["poa.tkt.prod-tls-handshake"]["status"] != "blocked_quota":
        raise QueueContractError("POA-QUOTA-001", "exhausted ticket must stay blocked_quota")
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
    if (
        view["schema"] != "poa.process-queue-view/v1"
        or view["ticket"]["ticket_id"] != "poa.tkt.control-origin-unify"
    ):
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
    if catalog["source_uri"] != seed["if_uri_catalog"]["source_uri"] or not str(
        catalog["source_uri"]
    ).endswith("/if-uri"):
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
        "queue_admission": {
            "ticket_id": replacement["ticket_id"],
            "queue_revision": replacement["queue_revision"],
            "plan_hash": replacement["plan_hash"],
            "state": queue.get_process_queue_admission_view(replacement["ticket_id"])["state"],
        },
    }
