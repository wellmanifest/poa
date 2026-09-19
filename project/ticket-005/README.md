# Ticket 005: Adopt wellmanifest/new-project 0.20.32 and resolve fleet drift

- **ID**: ticket-005
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-09-19

## Goal and scope

Adopt `wellmanifest/new-project` 0.20.32 into `wellmanifest/poa`, refresh managed governance files to published commit `b6ba9c21a65a6a5648ecf904b64c3b75295e136f`, retire legacy reusable workflow caller, eliminate fleet conformance errors, and align required check names to published workflows.

## Acceptance criteria

- [x] AC-01: Adopt `wellmanifest/new-project` 0.20.32 with clean `manifest.lock.json`.
- [x] AC-02: `fleet_conformance.py` passes with 0 errors and 0 warnings.
- [x] AC-03: `governance_check.py` passes with `GOV-PASS`.
