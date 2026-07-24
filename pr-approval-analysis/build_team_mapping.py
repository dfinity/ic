#!/usr/bin/env python3
"""
Derive a stable fine-grained-team -> umbrella-team mapping for dfinity/ic.

Team ownership in .github/CODEOWNERS changed a lot over the analysis window: many
fine-grained teams (consensus, execution, ic-message-routing-owners, crypto-team,
team-dsm, finint, cross-chain-team, ...) were consolidated into ~10 umbrella teams
(core-protocol, defi, node, idx, dre, governance-team, sdk, infrasec,
product-security, ic-owners-owners).

To classify PRs consistently across time we map every team name that ever appears
in a review request to a stable umbrella. We derive the mapping empirically: for
each path pattern owned by a fine team in the OLD CODEOWNERS (~12 months ago), we
resolve that same path through the CURRENT CODEOWNERS to see which umbrella owns it
now. The umbrella a fine team's paths most often map to becomes its umbrella.

Writes team_mapping.json: {fine_team: umbrella_team}.
"""

import json
import re
from collections import Counter, defaultdict

# The 10 umbrella teams used by the current CODEOWNERS.
UMBRELLAS = {
    "core-protocol",
    "defi",
    "node",
    "idx",
    "dre",
    "governance-team",
    "sdk",
    "infrasec",
    "product-security",
    "ic-owners-owners",
}


def parse(path):
    rules = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            pat = parts[0]
            teams = [p[len("@dfinity/") :] for p in parts[1:] if p.startswith("@dfinity/")]
            if teams:
                rules.append((pat, teams))
    return rules


def pattern_to_regex(pat):
    """Approximate gitignore/CODEOWNERS pattern semantics as a regex over a path."""
    anchored = pat.startswith("/")
    p = pat[1:] if anchored else pat
    dir_only = p.endswith("/")
    p = p.rstrip("/")

    # Build regex piece by piece, handling ** and * specially.
    out = []
    i = 0
    while i < len(p):
        c = p[i]
        if c == "*":
            if i + 1 < len(p) and p[i + 1] == "*":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c in ".+()[]{}^$|\\":
            out.append("\\" + c)
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(c)
        i += 1
    body = "".join(out)

    if anchored:
        prefix = "^"
    else:
        # unanchored: match at start of any path segment
        prefix = "^(?:.*/)?"
    if dir_only:
        suffix = "(?:/.*)?$"
    else:
        suffix = "(?:/.*)?$"
    return re.compile(prefix + body + suffix)


def compile_rules(rules):
    return [(pattern_to_regex(pat), teams, pat) for pat, teams in rules]


def resolve(path, compiled):
    """Last matching rule wins (CODEOWNERS semantics)."""
    found = None
    for rx, teams, pat in compiled:
        if rx.match(path):
            found = teams
    return found


def representative_path(pat):
    """A concrete-ish path that the pattern should match."""
    anchored = pat.startswith("/")
    p = pat[1:] if anchored else pat
    p = p.rstrip("/")
    p = p.replace("**", "x").replace("*", "x")
    if not p:
        p = "x"
    # ensure it looks like a file under the dir
    return p


def main():
    old = parse("codeowners_old.txt")
    new = compile_rules(parse("codeowners_new.txt"))

    mapping_counts = defaultdict(Counter)
    for pat, teams in old:
        rep = representative_path(pat)
        umb = resolve(rep, new)
        if not umb:
            continue
        for t in teams:
            for u in umb:
                mapping_counts[t][u] += 1

    # Resolve each fine team to a single umbrella.
    mapping = {}
    for t, counts in mapping_counts.items():
        # prefer a non-catch-all umbrella
        non_catch = Counter({k: v for k, v in counts.items() if k != "ic-owners-owners"})
        use = non_catch or counts
        mapping[t] = use.most_common(1)[0][0]

    # Umbrellas map to themselves.
    for u in UMBRELLAS:
        mapping[u] = u

    # A few teams may not appear in old file paths but show up in PR review
    # requests (e.g. renamed teams). Add safe explicit fallbacks, then let the
    # data-derived values override where present.
    explicit = {
        "defi-team": "defi",
        "ledger": "defi",
        "ledger-suite": "defi",
        "bitcoin": "defi",
        "ic-message-routing-owners": "core-protocol",
        "ic-interface-owners": "core-protocol",
        "crypto-team": "core-protocol",
        "consensus": "core-protocol",
        "execution": "core-protocol",
        "runtime": "core-protocol",
        "team-dsm": "core-protocol",
        "pocket-ic": "core-protocol",
        "formal-models": "core-protocol",
        "research": "core-protocol",
        "p2p-systems-research-team": "core-protocol",
        "networking": "core-protocol",
        "boundary-node": "node",
        "canister-os": "node",
        "platform-operations": "dre",
        "governance": "governance-team",
        "finint": "defi",
        "cross-chain-team": "defi",
        "languages": "sdk",
        "motoko": "sdk",
        "utopia": "sdk",
        "security": "product-security",
        "ic-support": "ic-owners-owners",
    }
    for t, u in explicit.items():
        mapping.setdefault(t, u)

    with open("team_mapping.json", "w") as f:
        json.dump(mapping, f, indent=2, sort_keys=True)

    print("=== derived fine -> umbrella mapping ===")
    for t in sorted(mapping):
        derived = dict(mapping_counts.get(t, {}))
        flag = "" if t in UMBRELLAS else ("  <-derived " + str(derived) if derived else "  <-explicit")
        print(f"{t:30} -> {mapping[t]:18}{flag}")


if __name__ == "__main__":
    main()
