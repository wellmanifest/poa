# Ticket 008: Add pytest conformance suite for POA v1 and v2

- **ID**: ticket-008
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-11-11

## Goal and scope

Add a standalone `pytest` / `unittest` conformance suite under
`tests/test_poa_conformance.py` covering POA v1 and v2 conformance reports,
duplicate JSON key rejection, `bool`-for-`int` rejection across v1 and v2,
unhashable list item handling, non-string queue admission rejection, inline
credential material rejection, strict RFC3339 timestamp checking, and CLI exit
codes, and reconcile merged `ticket-007` to `DONE` / `PUBLICATION`.

## Acceptance criteria

- [x] AC-01: Add `tests/test_poa_conformance.py` exercising POA v1 and v2
      validators and CLI entry points under both `pytest` and `unittest`.
- [x] AC-02: Reconcile merged `project/ticket-007/README.md` to `DONE` /
      `PUBLICATION` and pass `ruff check tests`, `pytest -q`,
      `./project/governance-check.sh --base origin/main`, and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
