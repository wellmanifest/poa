# Ticket 001: Define POA v1 architecture standard

- **ID**: ticket-001
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: VALIDATION
- **Created**: 2026-08-12

## Goal and scope

Create POA v1 as a reusable Process-Oriented Architecture standard derived
from verified Wellmanifest and Subactor implementations. The standard covers
typed process contracts, constrained LLM/MCP input, URI Process routing,
authority, execution, verification and receipts. It does not create a runtime
or grant production authority.

The user's request to create this repository and standard is recorded as
`SESSION_EXECUTION_AUTHORIZATION` for the paths in `intent.json`. It is not a
trusted merge approval and does not authorize commit, push or remote creation.

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
- Full publication gate: pending an initial reviewed Git baseline and bounded
  delivery contract bound to its real commit SHA. No placeholder SHA was used.

## Participants

- Human participant: unresolved:human; no user-* file was created by the agent.
- Agent participant: [ai-codex.md](ai-codex.md)
