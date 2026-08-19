# Ticket 003: Ticket queue CQRS ES with schedule quota and if-uri view

- **ID**: ticket-003
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-08-15

## Goal and scope

Adopt wellmanifest/poa as the ticketed process-queue pack. Every queue job,
including internal system processes and digital-twin local plans, is a
registered inspectable ticket with a process-queue. Commands append events.
`GetProcessQueueView` is a CQRS query, not a second source of truth.

The founder request and the 2026-08-15 ~20:46 UTC+2 system analysis are
`SESSION_EXECUTION_AUTHORIZATION` for `standard/**` and this ticket. They do
not authorize a Control restart, a GitHub pull request, or writes into
doctor-hygiene / policy-dsl 4 / dirty occupied trees.

## Acceptance criteria

- [x] AC-01: Scope is the analysis P0/P1/P2 seed plus schedule, deps, quotas and if-uri view.
- [x] AC-02: Queue adapter rejects enqueue without a registered inspectable `ticket_id`.
- [x] AC-03: Existing POA conformance still passes and includes ticket-queue checks.
- [x] AC-04: Seed does not treat www-sub-actor #16 as open work and does not execute Control restart.
- [x] AC-05: Doctor 2h hygiene is a ticketed process (`poa.tkt.doctor-hygiene-2h`), not a naked cron.

## How to inspect tickets + process queue

```bash
python3 -c 'from pathlib import Path; import json, sys; sys.path.insert(0, "standard"); from ticket_queue import TicketQueue, load_seed; q=TicketQueue(load_seed()); print(json.dumps(q.get_process_queue_view("poa.tkt.control-origin-unify"), indent=2, sort_keys=True))'
```

RuntimeOwner is subactor (planfile / doctor-agent / control). Those runtimes
MUST read this seed; this pack does not start a daemon.

## Participants

- Human participant: unresolved; no user-* file was created by the agent.
- Agent participant: [ai-grok.md](ai-grok.md)
