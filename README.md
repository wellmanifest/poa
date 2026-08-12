# POA — Process-Oriented Architecture

POA is a versioned standard for building systems in which work is represented
as typed, addressable and auditable processes rather than unbounded tool calls.

The first release standardizes lessons verified in Wellmanifest and Subactor:

- closed DSL input compiled into a typed AST;
- concrete URI Process selection from a registry;
- separation of planning, authority and execution;
- plan hashes, bounded grants, intents and one-shot execution;
- container and capability boundaries;
- effect verification through read-back and immutable receipts;
- fail-closed JSON Schema and GBNF validation for LLM/MCP inputs.

## Documents

- `docs/ARCHITECTURE.md` — normative components, boundaries and invariants.
- `docs/LOGIC_FLOW.md` — end-to-end lifecycle and implementation examples.
- `standard/poa-process.schema.v1.json` — machine-readable process contract.
- `standard/poa-process.v1.gbnf` — constrained generation grammar.
- `standard/conformance.py` — dependency-free positive and negative checks.

## Validation

```bash
docker compose run --rm conformance
```

This repository adopts immutable governance package `wellmanifest/new-project`
version `0.14.1`. Local implementation is not a trusted merge approval.
