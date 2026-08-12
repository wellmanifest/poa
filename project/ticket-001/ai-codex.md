---
participant-id: agent:codex
participant: codex
role: agent
ticket: ticket-001
---
# Participant: codex (AI agent)

## Understanding

The repository is a technology-neutral standard for constructing auditable,
process-oriented automation. Its primary consumer is a human or autonomous
agent designer who needs to turn natural-language intent into an exact,
bounded process without making the LLM, transport or Digital Twin an authority.

The normative core will distinguish process definition, invocation request,
secret-free plan and terminal receipt. JSON Schema constrains accepted data;
GBNF constrains model generation; a deterministic compiler verifies their
intersection and emits hashes. Runtime authority remains external through
policy, plan binding, grant and intent.

## Execution plan

1. Define POA components, invariants, trust boundaries and anti-patterns.
2. Document the complete authored-to-receipt flow with concrete MCP/CLI and
   multi-service process examples.
3. Publish one closed JSON Schema containing versioned process, request, plan
   and receipt document variants.
4. Publish matching GBNF for canonical request generation.
5. Implement a dependency-free conformance runner with positive and
   adversarial fixtures, then validate it in the isolated Docker service.
6. Review schema/grammar drift, unsafe data channels, secret exposure and
   governance evidence; record results in this ticket.

## Actual changes

- Initialized the bounded ticket and recorded SESSION_EXECUTION_AUTHORIZATION
  from the request to execute this work.
- Adopted the published `wellmanifest/new-project` governance package at its
  exact v0.14.1 revision.
- Bootstrapped a local Git repository and isolated Docker conformance service.
- Defined 27 stable POA requirements across authoring, registry, observation,
  planning, authority, execution, verification, receipts and MCP.
- Added a closed Draft 2020-12 schema for process, request, plan and receipt
  documents plus a matching inspect/plan GBNF.
- Added dependency-free compilation and conformance checks with canonical
  hashing, capability binding, DAG validation and 13 adversarial rejections.
- Added Mermaid architecture/sequence diagrams, implementation examples,
  failure semantics, maturity levels and an adoption checklist.

## Risks and controls

- JSON Schema and GBNF prevent structural injection but cannot prove semantic
  harmlessness; execution authority and runtime policy stay independent.
- A generic POA schema can become an accidental universal executor; therefore
  it contains capability identifiers and registry references, never arbitrary
  transport configuration or shell commands.
- Receipts can leak data; normative receipts contain hashes, sizes, state and
  references, while artifact access remains a separate capability.

## Blockers

- None inside the recorded intent; proceed without a second confirmation.
- New authority remains required for destructive action, secret access, new
  external coordination, material objective expansion and trusted merge.
- The repository has no initial Git commit because the user did not request a
  commit. Exact-base governance checks that require a HEAD remain a publication
  prerequisite rather than being fabricated.

## Acceptance evidence

- AC-01/05/07: `docs/ARCHITECTURE.md` and `docs/LOGIC_FLOW.md`.
- AC-02: Draft 2020-12 meta-schema and four positive variants passed.
- AC-03: grammar integrity and canonical intersection passed.
- AC-04: conformance report returned `ok: true` and 13 adversarial rejections.
- AC-06: isolated `docker compose run --rm conformance` returned `ok: true`.
