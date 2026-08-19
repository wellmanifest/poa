# Ticket Changelog (ticket-003)

## [0.2.0] - 2026-08-19

- Closed ticket-003 (`DONE / DONE`) from integrated `main` after
  `e30e0f3` (PR #4).
- Post-merge evidence: ticketed process-queue CQRS/ES pack is on the
  default branch. No implementation files in this closure.
- The ticket stayed `IN_PROGRESS` on `main` after the merge, which would
  make later pack tickets inherit it and fail workstream/conflict gates.

## [0.1.0] - 2026-08-15

- Added the closed ticketed process-queue CQRS/ES pack.
- Seeded the 2026-08-15 system-analysis P0/P1/P2 list with schedules, deps and quotas.
- Queue adapter rejects enqueue without a registered inspectable ticket_id.
