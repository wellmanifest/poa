# Ticket 012: Modularize poa_io and harden relative symlink traversal, JSON digit/surrogate bounds, and process title controls

- **ID**: ticket-012
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

Extract bounded regular-file UTF-8 I/O, finite JSON parsing, and secret scanning
into `standard/poa_io.py` and move `validate_observation`, `validate_binding`,
and `validate_execution_envelope` into `standard/poa_primitives.py` (re-exported
via `__all__` in `standard/conformance.py`) so every module under `standard/`
remains well below 500 lines. Harden `_reject_ancestor_symlinks` against
relative `sym_dir/..` and `../sym_dir` symlink-parent traversal, bound JSON
integer digit length (`<= 309`) before `int()` conversion in `strict_loads`,
enforce UTF-8 surrogate checks in `reject_secret_material`, reject ASCII C0/DEL
control characters in `validate_process` `title`, expand
`standard/test_poa_hardening.py`, and reconcile merged
`project/ticket-011/README.md` to `DONE`.

## Acceptance criteria

- [x] AC-01: Extract `standard/poa_io.py` and keep all `standard/*.py` modules
      strictly `< 500` lines while preserving public re-exports.
- [x] AC-02: Reject relative `sym_dir/..` and `../sym_dir` symlink-parent
      traversal, 310+ digit JSON integers before `int()` conversion, lone UTF-16
      surrogates across programmatic validators, and ASCII C0/DEL control
      characters in `validate_process` `title`, passing `ruff`,
      `standard/conformance.py --all`, `standard/ticket_queue.py`, and `pytest`.
- [x] AC-03: Reconcile merged `project/ticket-011/README.md` to `DONE` and pass
      `./project/governance-check.sh --base origin/main` and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
