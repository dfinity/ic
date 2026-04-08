---
description: Rules for editing BMAD strategic documents
globs: _bmad/**/*.md
---

# BMAD Document Rules

When editing files in `_bmad/`:

1. `traceability.md` is the single source of truth for REQ-* → test linkage status
2. Status values: `not-started`, `narrative`, `linked`, `verified`
3. Always update traceability.md when adding new REQs or linking tests
4. `architecture.md` defines the domain → REQ prefix mapping — keep it current
5. `prd.md` defines project goals — only modify when goals change
6. Never leave specs and code disagreeing silently — update spec to match reality with documented rationale, or fix code to match spec
