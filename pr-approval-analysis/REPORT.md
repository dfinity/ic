# dfinity/ic — PR approval waiting-time analysis

_Generated 2026-06-18 13:12 UTC._

This report quantifies how long pull requests in `dfinity/ic` wait for code-review **approval**, to assess whether review is a productivity bottleneck. Results are split by whether a PR only needs approval from the author's **own team** or also from **other teams**.

## Executive summary

Over the last 12 months, **3,953** human-authored PRs passed the filters. Of those that received review, the **typical (median) PR waited 1.5 h for a first approval and 4.5 h for full approval** (all required teams). So for the median PR, approval is reasonably fast — review is *not* a severe bottleneck at the center of the distribution.

**The cost is in the tail and in cross-team PRs.** Key findings:

- **Cross-team PRs are the bottleneck.** They reach *full* approval in a median of **8.3 h** vs **3.4 h** for same-team PRs, and their tail is far heavier (p90 **6.1 d** vs **4.5 d**). Each extra team that must approve adds serial waiting.
- **Cross-team PRs get a *first* look fastest** (median 38 min vs 2.2 h for same-team) — more requested reviewers means someone responds quickly — but converting that into *all* required approvals is what drags.
- **A heavy tail affects every category.** Overall, full approval takes p90 **5.2 d** and p95 **8.1 d**. Roughly 10–20% of PRs wait multiple days for approval; this is where engineer time is actually lost.
- **Weekends inflate the wait.** Counting only Mon–Fri shaves the tail materially (overall full-approval p90 drops from 5.2 d wall-clock to 3.4 d business-time).
- **Most PRs are single-team.** 3,032 of 3,953 human PRs need only one team; 540 need two and 285 need three or more.
- **Recent trend is slightly better.** The last 6 months are modestly faster than the full year (see below), so review latency is not worsening.

**Bottom line:** code review is responsive for the median change, but **cross-team approval coordination and a heavy multi-day tail** are the real drags on throughput. If frontier models make writing code cheaper, the relative cost of these approval waits — especially for PRs spanning multiple teams — will dominate cycle time.

## Methodology

- **Source:** all PRs created in the last 12 months (2025-06-18 → 2026-06-18), pulled from the GitHub GraphQL API (reviews + review-request timeline events). 4,885 PRs fetched before filtering.
- **Filters applied:** draft PRs are excluded; open PRs not updated in the last 30 days are excluded (treated as abandoned). Bot-authored PRs are reported separately and excluded from timing stats.
- **Ready time** = when the PR first became reviewable (creation time, or the ready-for-review event if it was opened as a draft).
- **Approval** = a human `APPROVED` review (bot/automation reviews ignored).
- **Time to first approval** = ready → first approval. **Time to full approval** = ready → last approval at/before merge (proxy for 'all required approvals obtained'). PRs that never received a human approval are excluded from these two metrics (so very fast trivial merges by owners are not counted).
- **Mon–Fri** rows count only weekday time, removing weekends from the wait (approximate 'business time', UTC; ignores public holidays and time-of-day).
- **Team gating:** GitHub requests review from the CODEOWNERS teams that own the changed files. A PR is **same-team** if every requested team maps to the author's own umbrella area, otherwise **cross-team**.
- **Team consolidation handled.** CODEOWNERS was reorganized during the window (61 changes); most notably (#10114, 2026-05-07) the fine-grained teams `consensus`, `execution`, `team-dsm`, `ic-message-routing-owners`, `ic-interface-owners`, `crypto-team`, `pocket-ic` were consolidated into the `core-protocol` umbrella, and `defi-team`→`defi`, `boundary-node`→`node`, etc. To measure same/cross-team **consistently over time**, every team name ever requested is mapped to a stable umbrella (`core-protocol`, `defi`, `node`, `idx`, `dre`, `governance-team`, `sdk`, `infrasec`, `product-security`, `ic-owners-owners`). The mapping is derived by resolving each historical CODEOWNERS path through the current file.
- **Author home team** is derived empirically from the umbrella most often requested on that author's single-team PRs. This reflects where an author actually contributes (agreeing with org-team membership for 18/25 code-owners; the rest are people who mostly contribute outside their nominal team or have very few PRs).

## Last 12 months

PRs created since **2025-06-18** that pass the filters: **4263** total — 3953 human-authored, 310 bot-authored.

Human PR state: 3768 merged, 27 open, 158 closed.

Classification (human): **2488 same-team**, **1369 cross-team**, 96 no-team-request, 0 unknown-home.

Reviewing teams per PR: 3032 need 1 team, 540 need 2, 285 need 3+ (96 had no team request).

### Same-team vs cross-team at a glance

| Metric | Same-team | Cross-team |
|---|---:|---:|
| PRs with an approval | 2346 | 1287 |
| First approval — median | 2.2 h | 38 min |
| Full approval — median | 3.4 h | 8.3 h |
| Full approval — p90 | 4.5 d | 6.1 d |
| Full approval — p95 | 7.2 d | 9.1 d |

### Overall

**All human PRs with an approval** (n with an approval = 3726)

| Metric | n | Median | Mean | p25 | p75 | p90 | p95 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Time to first approval (wall-clock) | 3726 | 1.5 h | 32.7 h | 11 min | 17.9 h | 3.3 d | 5.8 d |
| Time to first approval (Mon–Fri) | 3726 | 1.4 h | 23.0 h | 11 min | 16.2 h | 46.7 h | 3.9 d |
| Time to full approval (wall-clock) | 3726 | 4.5 h | 2.1 d | 28 min | 37.7 h | 5.2 d | 8.1 d |
| Time to full approval (Mon–Fri) | 3726 | 4.3 h | 36.4 h | 27 min | 25.2 h | 3.4 d | 6.0 d |
| Time to merge (wall-clock) | 3671 | 17.3 h | 3.0 d | 1.8 h | 2.8 d | 6.9 d | 12.3 d |

| First-approval (wall-clock) reached within | ≤1h | ≤4h | ≤8h | ≤1d | ≤2d | ≤3d | ≤1w |
|---|---:|---:|---:|---:|---:|---:|---:|
| share | 45% | 61% | 67% | 80% | 85% | 89% | 96% |

### Same-team PRs

**Same-team PRs** (n with an approval = 2346)

| Metric | n | Median | Mean | p25 | p75 | p90 | p95 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Time to first approval (wall-clock) | 2346 | 2.2 h | 38.3 h | 19 min | 20.9 h | 3.7 d | 6.1 d |
| Time to first approval (Mon–Fri) | 2346 | 2.2 h | 26.7 h | 18 min | 18.4 h | 2.1 d | 4.1 d |
| Time to full approval (wall-clock) | 2346 | 3.4 h | 2.1 d | 26 min | 27.4 h | 4.5 d | 7.2 d |
| Time to full approval (Mon–Fri) | 2346 | 3.3 h | 34.8 h | 26 min | 22.1 h | 2.9 d | 5.2 d |
| Time to merge (wall-clock) | 2324 | 16.5 h | 3.1 d | 1.9 h | 2.8 d | 6.2 d | 12.1 d |

| First-approval (wall-clock) reached within | ≤1h | ≤4h | ≤8h | ≤1d | ≤2d | ≤3d | ≤1w |
|---|---:|---:|---:|---:|---:|---:|---:|
| share | 39% | 56% | 63% | 78% | 83% | 88% | 96% |

### Cross-team PRs

**Cross-team PRs** (n with an approval = 1287)

| Metric | n | Median | Mean | p25 | p75 | p90 | p95 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Time to first approval (wall-clock) | 1287 | 38 min | 20.5 h | 5 min | 8.7 h | 2.1 d | 4.0 d |
| Time to first approval (Mon–Fri) | 1287 | 36 min | 14.6 h | 5 min | 7.7 h | 36.1 h | 2.8 d |
| Time to full approval (wall-clock) | 1287 | 8.3 h | 2.2 d | 33 min | 2.0 d | 6.1 d | 9.1 d |
| Time to full approval (Mon–Fri) | 1287 | 7.7 h | 38.4 h | 32 min | 34.7 h | 4.1 d | 6.5 d |
| Time to merge (wall-clock) | 1256 | 18.1 h | 2.9 d | 1.5 h | 3.0 d | 7.0 d | 12.1 d |

| Full-approval (wall-clock) reached within | ≤1h | ≤4h | ≤8h | ≤1d | ≤2d | ≤3d | ≤1w |
|---|---:|---:|---:|---:|---:|---:|---:|
| share | 32% | 45% | 50% | 67% | 75% | 81% | 92% |

## Last 6 months

PRs created since **2025-12-18** that pass the filters: **2039** total — 1876 human-authored, 163 bot-authored.

Human PR state: 1778 merged, 27 open, 71 closed.

Classification (human): **1170 same-team**, **684 cross-team**, 22 no-team-request, 0 unknown-home.

Reviewing teams per PR: 1489 need 1 team, 225 need 2, 140 need 3+ (22 had no team request).

### Same-team vs cross-team at a glance

| Metric | Same-team | Cross-team |
|---|---:|---:|
| PRs with an approval | 1102 | 632 |
| First approval — median | 2.0 h | 40 min |
| Full approval — median | 2.6 h | 7.7 h |
| Full approval — p90 | 4.1 d | 5.8 d |
| Full approval — p95 | 7.0 d | 8.1 d |

### Overall

**All human PRs with an approval** (n with an approval = 1755)

| Metric | n | Median | Mean | p25 | p75 | p90 | p95 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Time to first approval (wall-clock) | 1755 | 1.4 h | 31.6 h | 10 min | 17.4 h | 3.1 d | 5.6 d |
| Time to first approval (Mon–Fri) | 1755 | 1.3 h | 22.1 h | 10 min | 15.2 h | 45.9 h | 3.6 d |
| Time to full approval (wall-clock) | 1755 | 3.7 h | 47.5 h | 24 min | 29.7 h | 4.9 d | 7.6 d |
| Time to full approval (Mon–Fri) | 1755 | 3.6 h | 33.5 h | 22 min | 22.6 h | 3.1 d | 5.6 d |
| Time to merge (wall-clock) | 1726 | 14.6 h | 2.7 d | 1.7 h | 2.5 d | 6.1 d | 11.0 d |

| First-approval (wall-clock) reached within | ≤1h | ≤4h | ≤8h | ≤1d | ≤2d | ≤3d | ≤1w |
|---|---:|---:|---:|---:|---:|---:|---:|
| share | 46% | 61% | 66% | 81% | 85% | 90% | 97% |

### Same-team PRs

**Same-team PRs** (n with an approval = 1102)

| Metric | n | Median | Mean | p25 | p75 | p90 | p95 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Time to first approval (wall-clock) | 1102 | 2.0 h | 35.7 h | 18 min | 18.5 h | 3.6 d | 5.7 d |
| Time to first approval (Mon–Fri) | 1102 | 1.9 h | 25.0 h | 17 min | 17.5 h | 2.1 d | 3.8 d |
| Time to full approval (wall-clock) | 1102 | 2.6 h | 45.7 h | 22 min | 22.1 h | 4.1 d | 7.0 d |
| Time to full approval (Mon–Fri) | 1102 | 2.5 h | 32.0 h | 22 min | 19.9 h | 2.6 d | 5.0 d |
| Time to merge (wall-clock) | 1089 | 13.4 h | 2.7 d | 1.8 h | 2.0 d | 5.8 d | 10.8 d |

| First-approval (wall-clock) reached within | ≤1h | ≤4h | ≤8h | ≤1d | ≤2d | ≤3d | ≤1w |
|---|---:|---:|---:|---:|---:|---:|---:|
| share | 41% | 57% | 63% | 79% | 84% | 89% | 96% |

### Cross-team PRs

**Cross-team PRs** (n with an approval = 632)

| Metric | n | Median | Mean | p25 | p75 | p90 | p95 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Time to first approval (wall-clock) | 632 | 40 min | 23.1 h | 5 min | 11.7 h | 2.6 d | 4.8 d |
| Time to first approval (Mon–Fri) | 632 | 36 min | 16.2 h | 4 min | 8.9 h | 39.6 h | 3.0 d |
| Time to full approval (wall-clock) | 632 | 7.7 h | 2.1 d | 31 min | 47.4 h | 5.8 d | 8.1 d |
| Time to full approval (Mon–Fri) | 632 | 7.3 h | 35.6 h | 29 min | 36.0 h | 3.9 d | 6.0 d |
| Time to merge (wall-clock) | 617 | 16.7 h | 2.7 d | 1.5 h | 2.9 d | 6.9 d | 10.9 d |

| Full-approval (wall-clock) reached within | ≤1h | ≤4h | ≤8h | ≤1d | ≤2d | ≤3d | ≤1w |
|---|---:|---:|---:|---:|---:|---:|---:|
| share | 32% | 46% | 50% | 67% | 75% | 81% | 93% |

## Limitations & caveats

- **Approval ≠ active waiting.** Elapsed time to approval overlaps with the author iterating, addressing comments, or working on other PRs. It is an upper bound on 'lost' time, not pure idle time.
- **Full-approval proxy.** 'Time to full approval' uses the last approval at or before merge. If a PR was mergeable after fewer approvals, this slightly overstates the required wait; if approvals were dismissed by new commits and re-requested, it can understate it.
- **Home-team is current, data-derived.** It is inferred from a whole year of review requests; an author who switched teams mid-year is assigned their dominant area. Team membership history is not available from the API.
- **Team mapping is best-effort.** A few low-volume historical teams (`utopia`, `languages`, `platform-operations`, ~0.3% of requests) are mapped heuristically; this does not materially affect the aggregates.
- **Review-request timeline truncation.** A small number of PRs (≈6%) have >50 timeline events; the first ready/review-request events used here occur early, so truncation has negligible effect on classification.
- **Bots excluded.** Automation-authored PRs (release bots, dependabot, etc.) are reported as counts but excluded from timing to avoid skew.

## Appendix: home-team assignment (top 25 authors by PR count)

| Author | PRs (12mo) | Home umbrella |
|---|---:|---|
| basvandijk | 518 | idx |
| mraszyk | 396 | core-protocol |
| nmattia | 322 | idx |
| eichhorl | 209 | core-protocol |
| cgundy | 203 | idx |
| jasonz-dfinity | 199 | governance-team |
| andrewbattat | 186 | node |
| frankdavid | 161 | node |
| daniel-wong-dfinity-org | 146 | governance-team |
| alin-at-dfinity | 144 | core-protocol |
| Bownairo | 140 | node |
| pierugo-dfinity | 137 | core-protocol |
| mbjorkqvist | 135 | defi |
| pietrodimarco-dfinity | 134 | governance-team |
| gregorydemay | 116 | defi |
| kpop-dfinity | 101 | core-protocol |
| randombit | 91 | core-protocol |
| fspreiss | 84 | core-protocol |
| NikolaMilosa | 80 | governance-team |
| maksymar | 79 | core-protocol |
| michael-weigelt | 78 | core-protocol |
| dsarlis | 62 | core-protocol |
| schneiderstefan | 56 | core-protocol |
| ninegua | 53 | defi |
| r-birkner | 52 | node |
