# Ticket 010: Harden POA regular-file inode checks, colon URI segments, regex anchors, and twin-plan contracts

- **ID**: ticket-010
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

Harden POA v1/v2 regular-file UTF-8 reads against relative ancestor symlinks and
`lstat`/`fstat` inode swaps, extend `validate_safe_uri_segments` to colon-delimited
references (`grant:`, `intent:`, `urn:`, actor references), anchor all compiled
regexes with `\A...\Z`, validate `DigitalTwinPlan` and `register_internal_process`
step DAGs and ticket inspectability fail-closed, and reconcile merged `ticket-009`
to `DONE` / `PUBLICATION`.

## Acceptance criteria

- [x] AC-01: Enforce `os.lstat` + `os.fstat` `(st_dev, st_ino)` identity and
      relative parent symlink rejection in `read_regular_utf8`, extend
      `validate_safe_uri_segments` to colon-delimited references, and anchor all
      regexes with `\A...\Z` across `standard/poa_primitives.py`,
      `standard/conformance.py`, and `standard/poa_plan_receipt.py`.
- [x] AC-02: Validate `DigitalTwinPlan` (`POA-TWIN-001`, `POA-DAG-001`,
      `POA-QUEUE-003`) and `register_internal_process` step DAGs fail-closed in
      `standard/ticket_queue_admission.py` and `standard/ticket_queue.py`, keeping
      every `standard/*.py` module `< 500` lines.
- [x] AC-03: Expand `standard/test_poa_hardening.py`, reconcile merged
      `project/ticket-009/README.md` to `DONE` / `PUBLICATION`, and pass `ruff`,
      `pytest`, `standard/conformance.py --all`, `governance-check.sh`, and
      `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
