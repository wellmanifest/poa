# Ticket 015: Align declared version: pyproject.toml

- **ID**: ticket-015
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-11-19

## Goal and scope

The new-project 0.20.162 gate reports GOV-VERSION-001 in this repository, which blocks the fleet
standard adoption: pyproject 0.1.0.dev0 → VERSION 0.1.0. Align the single declaration; no other change.

## Acceptance criteria

- [ ] AC-01: `wellman-governance check` (0.20.162 runtime) reports no GOV-VERSION-001.
- [ ] AC-02: `project/governance-check.sh` passes.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
