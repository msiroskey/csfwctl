# Architecture

Technical findings accumulated during implementation. This document
captures decisions and discoveries that affect how the code is
structured.

## Layering

- `csfwctl.cli` is the only entrypoint operators touch.
- `csfwctl.falcon.*` is the only module that talks to CrowdStrike.
- `csfwctl.loader` and `csfwctl.schema.*` own the desired-state side.
- `csfwctl.differ` consumes both and produces a structured change set.
- `csfwctl.applier` is the only module that performs writes, gated by
  `csfwctl.safety`.

## Location API spike

To be completed in Phase 2. See `csfwctl-project-plan.md` section 9,
Phase 2 for the questions to answer. Findings land here.
