#!/bin/bash
#
# ic-ask: Ask the local ollama LLM a question about this AI node's synced
# subnet state.
#
# Reads:  ic-ai-state-query (gathers structured JSON from the latest
#         locally synced checkpoint).
# Writes: ollama chat completion to stdout.
#
# Usage:
#     ic-ask "How many canisters are on this subnet?"
#     ic-ask "Which canister has the largest memory footprint?"
#     ic-ask --canister rrkah-fqaaa-aaaaa-aaaaq-cai "what does this canister look like?"
#
# Environment:
#     OLLAMA_HOST   default 127.0.0.1:11434 (host stunnel) or :11435 (loopback)
#     OLLAMA_MODEL  default gemma3:1b
#     IC_STATE_ROOT default /var/lib/ic/data/ic_state
#
# Exit status:
#     0   on success
#     1   on missing dependency
#     2   when there is no synced checkpoint yet
#     3   on ollama / network failure

set -euo pipefail

OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11435}"
OLLAMA_MODEL="${OLLAMA_MODEL:-gemma3:1b}"
IC_STATE_ROOT="${IC_STATE_ROOT:-/var/lib/ic/data/ic_state}"
QUERY_BIN="${IC_AI_STATE_QUERY_BIN:-/opt/ic/bin/ic-ai-state-query}"

err() { echo "ic-ask: $*" >&2; }

require() {
    if ! command -v "$1" >/dev/null 2>&1 && [ ! -x "$1" ]; then
        err "missing dependency: $1"
        exit 1
    fi
}

require "$QUERY_BIN"
require curl
require jq

CANISTER_ID=""
QUESTION=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --canister)
            CANISTER_ID="${2:-}"
            shift 2
            ;;
        --canister=*)
            CANISTER_ID="${1#*=}"
            shift
            ;;
        -h|--help)
            sed -n '/^# /,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            QUESTION="$*"
            break
            ;;
    esac
done

if [ -z "$QUESTION" ]; then
    err "no question provided"
    err "usage: ic-ask [--canister <id>] \"<question>\""
    exit 1
fi

# Gather context from the local checkpoint. We always include the subnet
# summary; if a canister was specified we also include its detail.
SUMMARY_JSON="$("$QUERY_BIN" --state-root "$IC_STATE_ROOT" summary 2>/dev/null || true)"
if [ -z "$SUMMARY_JSON" ] || echo "$SUMMARY_JSON" | jq -e '.error' >/dev/null 2>&1; then
    err "no synced subnet state available yet at $IC_STATE_ROOT"
    err "wait until at least one checkpoint has been state-synced and try again."
    [ -n "$SUMMARY_JSON" ] && err "underlying error: $(echo "$SUMMARY_JSON" | jq -r '.error // "unknown"')"
    exit 2
fi

CANISTER_JSON=""
if [ -n "$CANISTER_ID" ]; then
    CANISTER_JSON="$("$QUERY_BIN" --state-root "$IC_STATE_ROOT" canister "$CANISTER_ID" 2>/dev/null || true)"
fi

# Top canisters by memory (compact list).
TOP_BY_MEM_JSON="$("$QUERY_BIN" --state-root "$IC_STATE_ROOT" list-canisters --sort-by memory --limit 10 2>/dev/null || echo '{}')"

# Recent ingress (compact).
INGRESS_JSON="$("$QUERY_BIN" --state-root "$IC_STATE_ROOT" ingress --limit 25 2>/dev/null || echo '{}')"

read -r -d '' SYSTEM_PROMPT <<'EOF' || true
You are an assistant embedded in an Internet Computer (IC) "AI node". This
node is NOT a consensus member of any subnet, but it has synced the read-only
state of one specific subnet to local disk. The user asks you questions about
that subnet. You have access to the latest synced state via context blocks
below, in JSON form. Answer concisely and ground every claim in the JSON.

Each canister is a smart contract on the IC. Memory footprint is in bytes.
Cycles are an integer count; 1 trillion cycles is roughly $1.30. Status is
Running, Stopping, or Stopped. The "controllers" of a canister are the
principals authorized to upgrade it.

If the JSON does not contain enough information to answer the question, say
so explicitly instead of guessing. Numbers expressed as strings in JSON
(e.g. cycle balances) are exact u128 values.
EOF

# Build the user message with embedded JSON context.
USER_MSG="$(jq -n \
    --arg q "$QUESTION" \
    --argjson sum "$SUMMARY_JSON" \
    --argjson top "$TOP_BY_MEM_JSON" \
    --argjson ing "$INGRESS_JSON" \
    --arg canister "$CANISTER_JSON" \
    '
    {
        question: $q,
        subnet_summary: $sum,
        top_canisters_by_memory: $top,
        recent_ingress: $ing,
    } + (if $canister == "" then {} else {canister_detail: ($canister | fromjson)} end)
    ')"

PAYLOAD="$(jq -n \
    --arg model "$OLLAMA_MODEL" \
    --arg sys "$SYSTEM_PROMPT" \
    --arg user "$USER_MSG" \
    '{
        model: $model,
        stream: false,
        messages: [
            {role: "system", content: $sys},
            {role: "user", content: $user}
        ]
    }')"

RESPONSE="$(curl --silent --show-error --fail \
    --max-time 120 \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    "http://${OLLAMA_HOST}/api/chat" 2>&1)" || {
    err "ollama request failed: $RESPONSE"
    exit 3
}

echo "$RESPONSE" | jq -r '.message.content // .error // .'
