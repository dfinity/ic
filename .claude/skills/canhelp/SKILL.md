---
name: canhelp
description: Display a human-readable summary of a canister's interface given its mainnet canister ID. Like --help but for canisters.
allowed-tools: Bash(icp canister metadata:*), Read, Grep, Glob
argument-hint: <canister-id>
---

Given the canister ID in `$ARGUMENTS`, fetch and summarize its Candid interface.

## Steps

1. Fetch the Candid interface from mainnet using `icp`:
   ```
   icp canister metadata $ARGUMENTS candid:service --network ic
   ```

2. Present the output as a readable summary with the following structure:

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
