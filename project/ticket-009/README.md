# Ticket 009: Harden POA file/JSON bounds, ticket dependency cycle checks, and type guards

- **ID**: ticket-009
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-11-11

## Goal and scope

Harden POA v1 and v2 validators across `standard/` with `O_NOFOLLOW | O_NONBLOCK`
bounded regular-file reads, finite-number and nesting-depth (`<= 64`) JSON
parsing and RFC 8785 canonicalization (including `1e999` float overflow),
iterative schema/secret/DAG traversals, `$defs` `maxLength` and URI
path-segment traversal guards, unhashable enum/identifier type guards, and
atomic ticket-dependency cycle and self-dependency rejection in
`TicketQueue.schedule_ticket`, and reconcile merged `ticket-008` to `DONE` /
`PUBLICATION`.

## Acceptance criteria

- [x] AC-01: Enforce bounded regular-file UTF-8 reads (`O_NOFOLLOW | O_NONBLOCK`),
      finite JSON / RFC 8785 bounds (`NaN`, `Infinity`, `1e999`, depth `<= 64`),
      iterative tree/DAG traversals, and URI segment / `maxLength` parity across
      `standard/poa_primitives.py`, `standard/conformance.py`, and
      `standard/poa_plan_receipt.py`.
- [x] AC-02: Enforce atomic ticket-dependency DAG cycle and self-dependency
      rejection in `TicketQueue.schedule_ticket`, task status validation, and
      unhashable type guards across `standard/ticket_queue.py` and
      `standard/ticket_queue_admission.py`, keeping every module `< 500` lines.
- [x] AC-03: Add `standard/test_poa_hardening.py`, reconcile merged
      `project/ticket-008/README.md` to `DONE` / `PUBLICATION`, and pass `ruff`,
      `pytest`, `standard/conformance.py --all`, `governance-check.sh`, and
      `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
