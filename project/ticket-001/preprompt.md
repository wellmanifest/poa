# Ticket preprompt

- **Task ID**: ticket-001
- **Task title**: Define POA v1 architecture standard
- **Created**: 2026-08-12T12:05:01Z

Keep executable implementation outside this governance/evidence directory.
Read a human-owned user-*.md file only when one exists.
The request to execute this work creates SESSION_EXECUTION_AUTHORIZATION;
proceed within the recorded intent without a redundant confirmation prompt.
Require new authority for destructive action, secrets, external coordination,
material objective expansion and trusted merge approval.

## Technical directives

- Define POA as Process-Oriented Architecture: a controlled process composes
  service capabilities and proves an effect; POA does not replace SOA.
- Preserve the verified pipeline: authored DSL -> typed AST -> capability
  binding -> exact URI Process -> observation -> dry-run -> plan hash -> grant
  and intent -> apply -> read-back -> immutable receipt.
- A DSL, schema-valid document, resolvable URI or MCP tool never grants
  authority by itself.
- LLM output may select only declared operations/capabilities. It must not
  invent URI, transport, executable, shell argv, credential locator or grant.
- Use `additionalProperties: false`, bounded strings and arrays, exact enums,
  canonical serialization, JSON Schema and GBNF as an intersecting language.
- Keep raw prompts, secrets and full outputs out of plans and event logs; store
  hashes, sizes, references and bounded receipts.
- Treat semantic prompt filtering as defense in depth, not a proof that natural
  language is harmless.

## Internal evidence references

- `knowledge://subactor/architecture.strategy-dsl/v1`
- `knowledge://subactor/architecture.autonomy-execution-pipeline/v2`
- `knowledge://subactor/architecture.openwebui-mcp-control-boundary/v2`
- `repo://wellmanifest/wellm/docs/SOA_POA_CQRS_ES.md`
- `repo://subactor/llm-account-hub/llmhub/cli_dsl.py`
- `repo://subactor/llm-account-hub/llmhub/cli_execution.py`
