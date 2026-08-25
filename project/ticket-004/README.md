# Ticket 004: Gate ticket process queues with revision-bound admission

- **ID**: ticket-004
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-08-25

## Goal and scope

Extend the ticketed POA queue with a versioned, inspectable admission boundary.
Before an executor starts a planned URI Process, the runtime must bind one
existing ticket, the current queue revision and the exact canonical plan hash
to a decision made independently of both proposer and executor. A rejection
must keep the same ticket and replace the queued plan with a higher revision;
it must never execute the rejected bytes or create a shadow ticket.

Make rollback semantics explicit. A step with no rollback or compensating
process is irreversible and cannot be admitted without a higher-authority grant
bound to that exact plan. Wellmanifest owns the closed standard and reference
conformance; Subactor remains runtime owner and must adopt it in Control,
Planfile and orchestrators.

The user's request to enforce the POA queue like Wellmanifest CI and the later
request to push and continue are `SESSION_EXECUTION_AUTHORIZATION` for this
bounded standardization ticket. They authorize ticket-branch publication, not
direct-main push, self-approval, merge, runtime deployment or secret access.

## Acceptance criteria

- [x] AC-01: The user's execution and continuation requests authorize the
      bounded standard and its ticket-branch publication.
- [x] AC-02: Closed v2 queue plan and start documents bind ticket, queue
      revision, exact URI processes, rollback semantics and canonical plan hash.
- [x] AC-03: Admission is a separate closed decision and the reference adapter
      rejects stale revision/hash, proposer/admitter and admitter/executor
      identity collapse, and irreversible work without exact higher authority.
- [x] AC-04: Rejection preserves the ticket, prevents start and permits only a
      higher-revision replacement plan under that same ticket.
- [x] AC-05: A read-only view exposes the current plan, admission and queue
      state without creating authority or events.
- [x] AC-06: Architecture guidance explains URI Processes as delegated logical
      resources, analogous to resource/process identifiers in mobile operating
      systems, while making clear that URI resolution itself grants nothing.
- [x] AC-07: Positive and adversarial conformance, networkless Docker and
      repository governance pass before publication.

## Validation evidence

- `python3 standard/ticket_queue.py`: passed; 11 adversarial queue rejections,
  rejected revision 1 replaced by admitted/running revision 2 in the same
  `poa.tkt.ingress-caddy` ticket.
- `python3 standard/conformance.py --all`: passed; existing POA v1 checks remain
  green and the v2 admission projection reports the exact revision and hash.
- Draft 2020-12 validation accepted representative plan, admission and replan
  documents; adapter conformance separately rejected a replan whose embedded
  plan hash was not recomputed.
- `docker compose run --rm --build conformance`: rebuilt the exact source and
  passed in the isolated container.
- `./project/governance-check.sh --actor agent`: passed with zero errors and
  zero warnings.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)
