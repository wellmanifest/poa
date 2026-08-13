# Ticket 002: Bootstrap governed CI checks

- **ID**: ticket-002
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-08-13

## Goal and scope

Add one target-owned, immutable-action GitHub workflow that publishes Linux
`test` and Windows `windows-governance` checks, runs the existing deterministic
governance entrypoints against exact revisions, executes POA conformance in a
networkless Docker container when the standard is present, and delegates
trusted-review resolution to the pinned reusable governance workflow.

The request to continue the completion audit records
`SESSION_EXECUTION_AUTHORIZATION` for this bounded infrastructure repair. It
does not authorize merge, release, secrets, branch-protection changes or
modification of ticket-001 implementation files.

## Acceptance criteria

- [x] AC-01: Scope is approved by the user's continuation request and recorded
  before implementation.
- [ ] AC-02: The workflow exposes deterministic `test` and
  `windows-governance` checks using immutable action references.
- [ ] AC-03: Linux validates the exact change boundary and runs POA
  conformance in Docker with networking disabled when the standard exists.
- [ ] AC-04: Windows validates the managed entrypoint for the exact revision.
- [ ] AC-05: Trusted-review resolution remains external and pinned to an
  immutable `wellmanifest/new-project` reusable workflow revision.
- [ ] AC-06: Workflow syntax, local governance and Docker availability checks
  pass before publication.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)
