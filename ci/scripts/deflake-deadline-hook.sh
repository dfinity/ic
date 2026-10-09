#!/usr/bin/env bash
# PreToolUse hook of the Claude step of .github/workflows/fix-flaky-test.yml: Claude must return its result before
# the deadline, $1 in seconds since the epoch. Until then the timeout of each Bash command is cut to the time left,
# which stops the command at the deadline because the job sets CLAUDE_CODE_DISABLE_BACKGROUND_TASKS=1 (otherwise it
# would continue in the background). After it every tool call is denied, except StructuredOutput, which returns the
# result. Exit code 2 is the only one that denies: other failures let the call through.
# Reads the call as JSON from stdin, see https://code.claude.com/docs/en/hooks.

set -euo pipefail

left=$(($1 - $(date +%s)))
input="$(cat)"
if tool="$(jq -r .tool_name <<<"$input" 2>/dev/null)" && [ "$tool" == StructuredOutput ]; then
    exit 0
fi
if ((left <= 0)); then
    echo "The deadline has passed: call StructuredOutput with your result now." >&2
    exit 2
fi
if [ "$tool" == Bash ]; then
    # The whole input is returned with the new timeout. A missing timeout means the default, BASH_DEFAULT_TIMEOUT_MS
    # of the job.
    jq -c --argjson left_ms "$((left * 1000))" '{
        hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "allow",
            updatedInput: (.tool_input | .timeout = ([(.timeout // 7200000), $left_ms] | min))
        }
    }' <<<"$input"
fi
