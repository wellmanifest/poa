# Ticket 007: Modularize POA conformance under 500 lines and harden strict JSON and type validation

- **ID**: ticket-007
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-11-11

## Goal and scope

Modularize `wellmanifest/poa` conformance (`standard/conformance.py` down from
1,196 lines and `standard/ticket_queue.py` down from 981 lines) so every Python
module stays strictly under 500 lines, eliminate cross-module helper
duplication, harden strict JSON duplicate-key rejection, `bool`-for-`int`
rejection, unhashable list item handling, bounded `verification`/`steps` list
checks, strict RFC3339 timestamp parsing, inline secret material scanning, and
non-coercive `str` validation in v2 queue admission, add `pyproject.toml`, and
reconcile merged `ticket-005` and `ticket-006`.

## Acceptance criteria

- [x] AC-01: Split `standard/conformance.py` and `standard/ticket_queue.py`
      under 500 lines (`poa_primitives.py`, `poa_fixtures.py`, `conformance.py`,
      `ticket_queue_admission.py`, `ticket_queue_conformance.py`,
      `ticket_queue.py`) while preserving all public entry points.
- [x] AC-02: Fix `bool`-for-`int` acceptance, unhashable list crashes,
      unbounded `verification` / `steps` / `verification_refs` lists,
      non-RFC3339 timestamps, `str(...)` coercion of non-strings, duplicate JSON
      key acceptance, and inline secret material scanning across POA v1 and v2.
- [x] AC-03: Add `pyproject.toml`, close `ticket-005` and `ticket-006`, and pass
      `ruff check standard`, `python3 standard/conformance.py --all`,
      `python3 standard/ticket_queue.py`, networkless Docker conformance,
      `./project/governance-check.sh --base origin/main`, and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
