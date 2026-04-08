---
description: Rules for test files that have traceability headers
globs: rs/**/tests/**/*.rs, rs/**/tests.rs
---

# Test Traceability Rules

When editing test files:

1. If the file has a `//! # Traceability` header, preserve it
2. New test functions covering a REQ-* should be noted in the header
3. Every test file SHOULD reference at least one REQ-*/SCENARIO-* in its header
4. No orphan tests: tests without spec references are a code smell
5. Assertion quality matters: test assertions must match what the SCENARIO specifies, not just test surface-level behavior (e.g., don't test only status codes when the spec requires schema validation)
