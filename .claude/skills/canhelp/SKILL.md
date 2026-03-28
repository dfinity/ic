---
name: canhelp
description: Display a human-readable summary of a canister's interface given its mainnet canister ID or name. Like --help but for canisters.
allowed-tools: Bash(./scripts/resolve-canister-id.sh *), Bash(./scripts/fetch-candid.sh *), Read, Grep, Glob
argument-hint: <canister-id-or-name>
---

Given a canister ID or name in `$ARGUMENTS`, fetch and summarize its Candid interface.

## Steps

1. Resolve the canister ID by running the resolve script from the skill's base directory:
   ```
   ./scripts/resolve-canister-id.sh $ARGUMENTS
   ```
   If `$ARGUMENTS` is already a valid principal, the script echoes it back.
   Otherwise, it queries the IC Dashboard API and outputs matches as `<canister-id>  <name>` (one per line).
   - If there is a single result, use it directly.
   - If there are multiple results, present the list to the user and ask them to pick one before continuing.

2. Fetch the Candid interface using the resolved canister ID:
   ```
   ./scripts/fetch-candid.sh <resolved-canister-id>
   ```
   The script outputs the path to the downloaded `.did` file.

3. Read the file using the `Read` tool.

4. Present the output as a readable summary with the following structure:

   **Canister `<canister-id>`**

   **Query methods:**
   - `method_name(arg1: type1, arg2: type2) → return_type` — one-line description if inferable from the name

   **Update methods:**
   - `method_name(arg1: type1) → return_type`

   **Types:**
   - List any custom record/variant types defined in the interface, with their fields

## Guidelines

- Group methods by query vs update
- Sort methods alphabetically within each group
- For complex nested types, show the top-level structure and note nesting
- If the candid is very large (>100 methods), show a summary count and list only the most important-looking methods, offering to show the full list on request
- If the fetch fails, suggest the user verify the canister ID and that `icp` is installed