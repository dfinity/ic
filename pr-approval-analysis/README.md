# PR approval waiting-time analysis (`dfinity/ic`)

Quantifies how long pull requests wait for **code-review approval**, to assess
whether review is a productivity bottleneck — broken down by PRs that only need
approval from the author's own team ("same-team") vs. PRs that also need other
teams ("cross-team").

See **[REPORT.md](REPORT.md)** for the findings, methodology, and limitations.

## TL;DR

- For the *median* PR, approval is fast (first approval ~1.5 h, full approval
  ~4.5 h over the last 12 months) — review is not a severe bottleneck at the
  center of the distribution.
- The cost is in the **tail** (overall full-approval p90 ≈ 5 days) and in
  **cross-team PRs** (full-approval median 8.3 h vs 3.4 h same-team, with a
  heavier tail). Coordinating approvals across teams is the main drag.

## Files

| File | Purpose |
|---|---|
| `REPORT.md` | The generated report (12- and 6-month windows). |
| `fetch_teams.py` | Fetch current membership of the CODEOWNERS umbrella teams → `teams.json`. |
| `fetch_prs.py` | Fetch all PRs in the last 365 days (reviews + review-request timeline) → `prs.jsonl`. Resumable (cursor checkpoint + dedupe). |
| `build_team_mapping.py` | Derive a stable fine-grained-team → umbrella-team mapping from CODEOWNERS git history → `team_mapping.json`. |
| `analyze.py` | Compute approval waiting-time stats + classification → `REPORT.md`. |
| `team_mapping.json` | The derived team mapping (checked in for reference). |

## Reproduce

Requires `gh` authenticated with `read:org` + `repo` scopes (or a PAT — see note
below) and Python 3.

```sh
cd pr-approval-analysis

# 1. Team memberships (current snapshot)
python3 fetch_teams.py

# 2. All PRs in the last 12 months (writes prs.jsonl; resumable)
python3 fetch_prs.py

# 3. Build the historical fine->umbrella team mapping
#    (uses git history of .github/CODEOWNERS)
git -C .. show "$(git -C .. rev-list -1 --before=2025-06-18 master):.github/CODEOWNERS" > codeowners_old.txt
cp ../.github/CODEOWNERS codeowners_new.txt
python3 build_team_mapping.py

# 4. Analyze + regenerate REPORT.md
python3 analyze.py
```

> **Note on tokens:** if the same GitHub account runs `gh auth login` on another
> machine it will revoke this machine's token mid-run. `fetch_prs.py` is
> resumable and can read an independent token from `~/.gh_pat` (a classic PAT
> with `repo` + `read:org`, SSO-authorized for `dfinity`) or `GH_TOKEN`.

## Caveats

Approval elapsed time overlaps with the author iterating and is an upper bound on
"lost" time, not pure idle time. Team membership history is not available from the
API, so home teams are derived from a year of review-request data. See the
*Limitations & caveats* section of `REPORT.md` for the full list.
