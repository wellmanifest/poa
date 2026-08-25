# TODO

- [x] Bootstrap governed CI checks in `project/ticket-002/`; state:
  `DONE / DONE`; classification: `BUG / P1 / requested`; workstream:
  `infrastructure`. `ifuri-validator-agent` approved and merged
  `e85978201a1738f18286fddfbd96003d8a30c3a9`.
- [x] Create the governed POA v1 architecture ticket: `project/ticket-001/`.
- [x] Define normative architecture and logic-flow documentation.
- [x] Publish closed JSON Schema and GBNF contracts.
- [x] Add positive and adversarial conformance checks.
- [x] Add typed registry binding, observation, execution and event contracts.
- [x] Add multi-dimensional effects, canonical hash profile, leases and full
  terminal-state semantics.
- [x] Validate the isolated Docker test environment and scoped governance files.
- [x] Publish the validated ticket branch and obtain trusted exact-head review
  through its pull request.
- [x] Ticketed process-queue CQRS/ES pack in `project/ticket-003/`; state:
  `DONE / DONE`; classification: `FEATURE / P1 / requested`; workstream:
  `integration`. Published through merged PR #5.
- [x] Revision-bound queue admission in `project/ticket-004/`; state:
  `DONE / DONE`; classification: `FEATURE / P1 / requested`;
  workstream: `integration`. Require ticket, current queue revision, exact plan
  hash, independent admission, same-ticket replan and higher authority for
  irreversible effects before an executor starts a URI Process. Published
  through independently validated and merged PR #8 (`5c7d290`).
