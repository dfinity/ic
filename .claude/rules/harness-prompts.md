---
description: Rules for editing agent task prompts
globs: .harness/prompts/**/*.md
---

# Agent Task Prompt Rules

When editing agent task prompts in `.harness/prompts/`:

1. NEVER use persona names (e.g., "You are Quinn", "You are Amelia")
2. Use task scoping: "Your task is X" not "You are the X agent"
3. Frame role boundaries as task constraints, not identity
4. Keep prompts factual and directive — no narrative framing
5. The orchestrator is NEVER an LLM — it's a deterministic script
6. Generator tasks must NOT include evaluation logic
7. Evaluator tasks must NEVER see the generator's context
