# Ticket 001: Define POA v1 architecture standard

- **ID**: ticket-001
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-08-12

## Goal and scope

Create POA v1 as a reusable Process-Oriented Architecture standard derived
from verified Wellmanifest and Subactor implementations. The standard covers
typed process contracts, constrained LLM/MCP input, URI Process routing,
authority, execution, verification and receipts. It does not create a runtime
or grant production authority.

The user's request to create this repository and standard is recorded as
`SESSION_EXECUTION_AUTHORIZATION` for the paths in `intent.json`. It is not a
trusted merge approval. The later explicit request to push the changes
authorizes the initial local baseline, creation of the public repository,
committing this bounded diff, pushing its ticket branch and opening a pull
request. It does not authorize direct-main implementation push, merge, tag or
release creation.

## Acceptance criteria

- [x] AC-01: POA terminology, components and normative invariants are explicit.
- [x] AC-02: A closed Draft 2020-12 JSON Schema models process, request, plan and receipt documents.
- [x] AC-03: GBNF constrains LLM generation to the request AST accepted by the schema.
- [x] AC-04: Conformance checks accept canonical examples and reject unsafe or ambiguous input.
- [x] AC-05: Architecture and logic-flow documents contain Mermaid diagrams and implementation guidance.
- [x] AC-06: Docker validation passes without network access or runtime secrets.
- [x] AC-07: Lessons from the scoped MCP/CLI implementation are generalized without granting authority to DSL or URI resolution.

## Validation status

- Local contract and Docker conformance: passed.
- Scoped governance structure check: passed.
- Initial Git baseline created as `67729d63949a8dfb8422435f808316065484da47`;
  bounded delivery is bound to that exact SHA. Host and networkless Docker
  conformance, governance and diff hygiene passed; trusted exact-head review
  and merge remain pending after ticket-branch publication.

## Participants

- Human participant: unresolved:human; no user-* file was created by the agent.
- Agent participant: [ai-codex.md](ai-codex.md)
