---
description: Rules for editing execution environment Rust code
globs: rs/execution_environment/**/*.rs, rs/cycles_account_manager/**/*.rs, rs/embedders/**/*.rs, rs/canister_sandbox/**/*.rs
---

# Execution Environment Code Rules

When editing execution environment code:

1. All replicated execution MUST be fully deterministic across all replicas
2. DTS preserves determinism: execution results are identical regardless of slice boundaries
3. Every execution round has a bounded instruction budget — never remove these bounds
4. Cycles are neither created nor destroyed during normal execution (only CMC mints)
5. Canister sandbox execution runs in separate processes — never bypass isolation
6. After modifying Rust code, follow the CLAUDE.md build/lint/test workflow
