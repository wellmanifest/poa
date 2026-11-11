# Ticket 011: Harden POA JSON overflow/surrogates, absolute symlink ancestors, key secret scanning, and URI segments

- **ID**: ticket-011
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

Harden `standard/poa_primitives.py` against `10**400` JSON integer overflow and
lone UTF-16 surrogates across `_check_json_tree`, `strict_loads`, `canonical`,
and `digest_text`, reject symlink ancestor directories on absolute paths in
`read_regular_utf8`, scan JSON object keys in `reject_secret_material`, reject
colon-delimited `.` / `..` / empty segments in `validate_safe_uri_segments`,
expand `standard/test_poa_hardening.py`, and reconcile merged `ticket-010` to
`DONE` / `PUBLICATION`.

## Acceptance criteria

- [x] AC-01: Reject `10**400` integers, lone UTF-16 surrogates, absolute-path
      symlink ancestors, secret-bearing JSON object keys, and colon-delimited
      `.` / `..` / empty URI segments in `standard/poa_primitives.py` (< 500 lines),
      and pass `ruff check --no-cache standard` and `python3 standard/conformance.py --all`.
- [x] AC-02: Pass `python3 standard/ticket_queue.py` and `pytest -q`.
- [x] AC-03: Reconcile merged `project/ticket-010/README.md` to `DONE` and pass
      `./project/governance-check.sh --base origin/main` and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
