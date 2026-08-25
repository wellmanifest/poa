---
participant-id: agent:codex
participant: codex
role: agent
ticket: ticket-004
---
# Participant: codex (AI agent)

## Understanding

The existing POA process contract already separates plan hashes, grants and URI
bindings, but the ticket-queue v1 pack can start a queued step without proving
that the visible queue revision was independently admitted. That gap permits a
stale or rejected plan to reach an executor and makes replan behavior implicit.

## Execution plan

1. Add closed, additive v2 Schema and protobuf documents for queue plan,
   admission, same-ticket replan and read-only view.
2. Extend the reference adapter with exact hash/revision/identity/authority
   checks and positive plus adversarial conformance.
3. Explain the URI-resource and rollback boundary in normative architecture
   language, then run local, Docker and governance gates.

## Actual changes

- Initialized the bounded ticket and recorded SESSION_EXECUTION_AUTHORIZATION
  from the request to execute this work.

## Blockers

- None inside the recorded intent; proceed without a second confirmation.
- New authority remains required for destructive action, secret access, new
  external coordination, material objective expansion and trusted merge.
