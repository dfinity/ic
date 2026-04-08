---
description: Rules for editing OpenSpec capability specs
globs: openspec/capabilities/**/*.md
---

# OpenSpec Capability Spec Rules

When editing files in `openspec/capabilities/`:

1. Every requirement MUST have a `REQ-<DOMAIN>-<NNN>` identifier
2. Every scenario MUST have a `SCENARIO-<DOMAIN>-<NNN>` identifier
3. Every scenario MUST use strict Given/When/Then format
4. Every spec file MUST end with a Traceability table
5. The REQ prefix MUST match the domain convention in `_bmad/architecture.md`
6. Never silently drop a requirement from the source narrative
7. After adding REQs, update `_bmad/traceability.md`
