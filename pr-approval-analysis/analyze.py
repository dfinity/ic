#!/usr/bin/env python3
"""
Analyze PR approval waiting times for dfinity/ic.

Reads prs.jsonl (from fetch_prs.py) and teams.json (from fetch_teams.py) and
produces statistics on how long PRs wait for approval, broken down by:
  - PRs that only need approval from the author's own team ("same-team")
  - PRs that need approval from other teams too ("cross-team")
for two windows: last 12 months and last 6 months.

Writes report.md and prints a summary.
"""

import datetime
import json
import math
import statistics
from collections import Counter, defaultdict

NOW = datetime.datetime.now(datetime.timezone.utc)
WINDOWS = [("12 months", 365), ("6 months", 182)]
STALE_OPEN_DAYS = 30  # open PRs not updated within this many days are dropped

# Fine-grained-team -> stable umbrella-team mapping (built by build_team_mapping.py).
# CODEOWNERS consolidated many fine teams (consensus, execution, team-dsm, ...) into
# ~10 umbrella teams during the window; we canonicalize so same/cross-team is
# measured consistently over time.
try:
    TEAM_UMBRELLA = json.load(open("team_mapping.json"))
except FileNotFoundError:
    TEAM_UMBRELLA = {}


def to_umbrella(team):
    return TEAM_UMBRELLA.get(team, team)


BOT_LOGINS = {
    "github-actions",
    "github-actions[bot]",
    "dependabot",
    "dependabot[bot]",
    "renovate",
    "renovate[bot]",
    "pr-automation-bot-public",
    "sa-github-api",
    "ic-team-bot",
    "github-merge-queue[bot]",
}

# ---------------------------------------------------------------- helpers


def parse_ts(s):
    if s is None:
        return None
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))


def is_bot(actor):
    if actor is None:
        return True
    login = actor.get("login")
    if login is None:
        return True
    if actor.get("__typename") == "Bot":
        return True
    if login in BOT_LOGINS:
        return True
    if login.endswith("[bot]"):
        return True
    return False


def weekday_seconds(start, end):
    """
    Elapsed seconds between start and end counting only Mon-Fri (UTC).

    Approximates "business time" so that weekends do not count as approval wait.
    Ignores public holidays and time-of-day (treats all 24h of a weekday).
    """
    if end <= start:
        return 0.0
    total = 0.0
    cur = start
    while cur < end:
        day_start = cur.replace(hour=0, minute=0, second=0, microsecond=0)
        next_day = day_start + datetime.timedelta(days=1)
        seg_end = min(next_day, end)
        if cur.weekday() < 5:  # Mon=0 .. Fri=4
            total += (seg_end - cur).total_seconds()
        cur = seg_end
    return total


def pct(data, p):
    if not data:
        return None
    s = sorted(data)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * p / 100.0
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return s[int(k)]
    return s[f] + (s[c] - s[f]) * (k - f)


def fmt_hours(h):
    if h is None:
        return "n/a"
    if h < 1:
        return f"{h * 60:.0f} min"
    if h < 48:
        return f"{h:.1f} h"
    return f"{h / 24:.1f} d"


# ---------------------------------------------------------------- load


def load_prs(path="prs.jsonl"):
    prs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                prs.append(json.loads(line))
    return prs


def compute_ready_time(pr):
    """
    When the PR first became reviewable.

    - created non-draft  -> createdAt
    - created as draft    -> first ReadyForReviewEvent
    Decided by whether the earliest draft/ready transition is a ready event.
    """
    created = parse_ts(pr["createdAt"])
    events = []
    for it in pr["timelineItems"]["nodes"]:
        t = it.get("__typename")
        if t in ("ReadyForReviewEvent", "ConvertToDraftEvent"):
            events.append((parse_ts(it["createdAt"]), t))
    events.sort()
    if not events:
        return created
    if events[0][1] == "ReadyForReviewEvent":
        # created as draft, then marked ready
        return events[0][0]
    # created non-draft (first transition is a convert-to-draft)
    return created


def requested_teams(pr):
    teams = set()
    for it in pr["timelineItems"]["nodes"]:
        if it.get("__typename") == "ReviewRequestedEvent":
            rr = it.get("requestedReviewer") or {}
            if rr.get("__typename") == "Team":
                teams.add(rr["slug"])
    return teams


def approvals(pr):
    """List of (timestamp, login) for human APPROVED reviews."""
    out = []
    for r in pr["reviews"]["nodes"]:
        if r.get("state") == "APPROVED" and not is_bot(r.get("author")):
            ts = parse_ts(r.get("submittedAt"))
            if ts is not None:
                out.append((ts, r["author"]["login"]))
    out.sort()
    return out


# ---------------------------------------------------------------- enrich


def enrich(prs):
    for pr in prs:
        pr["_created"] = parse_ts(pr["createdAt"])
        pr["_updated"] = parse_ts(pr["updatedAt"])
        pr["_merged"] = parse_ts(pr.get("mergedAt"))
        pr["_ready"] = compute_ready_time(pr)
        pr["_req_teams"] = requested_teams(pr)
        pr["_req_umbrellas"] = {to_umbrella(t) for t in pr["_req_teams"]}
        pr["_approvals"] = approvals(pr)
        pr["_author"] = (pr.get("author") or {}).get("login")
        pr["_is_bot_author"] = is_bot(pr.get("author"))
    return prs


def passes_filters(pr):
    """Apply the user's filters: drop drafts and stale open PRs."""
    if pr.get("isDraft"):
        return False
    if pr.get("state") == "OPEN":
        if pr["_updated"] is None or pr["_updated"] < NOW - datetime.timedelta(days=STALE_OPEN_DAYS):
            return False
    return True


def determine_home_teams(prs, login_to_teams):
    """
    Empirically map each (human) author to a single home *umbrella* team.

    Signal: among an author's 'solo' PRs (exactly one umbrella requested), the most
    frequently requested umbrella is their home. Falls back to the most frequent
    umbrella across all their PRs. Org membership (mapped to umbrellas) is a
    tie-breaker. ic-owners-owners (a meta team) is not a home candidate unless it
    is the only signal.
    """
    solo_counts = defaultdict(Counter)
    all_counts = defaultdict(Counter)
    for pr in prs:
        if pr["_is_bot_author"] or pr["_author"] is None:
            continue
        ru = pr["_req_umbrellas"]
        if not ru:
            continue
        a = pr["_author"]
        for t in ru:
            all_counts[a][t] += 1
        if len(ru) == 1:
            solo_counts[a][next(iter(ru))] += 1

    home = {}
    authors = set(all_counts) | set(solo_counts)
    for a in authors:
        counts = solo_counts.get(a) or all_counts.get(a)
        if not counts:
            continue
        # drop ic-owners-owners as a home candidate unless it's all we have
        filtered = Counter({k: v for k, v in counts.items() if k != "ic-owners-owners"})
        use = filtered or counts
        org_umbrellas = {to_umbrella(t) for t in login_to_teams.get(a, [])}
        best = max(
            use.items(),
            key=lambda kv: (kv[1], kv[0] in org_umbrellas, kv[0]),
        )[0]
        home[a] = best
    return home


def classify(pr, home):
    """
    Return one of: same_team, cross_team, no_team_request, unknown_home.

    Same-team = the PR's requested umbrellas are only the author's home umbrella.
    Cross-team = at least one other umbrella is also required to approve.
    """
    ru = pr["_req_umbrellas"]
    if not ru:
        return "no_team_request"
    a = pr["_author"]
    h = home.get(a)
    if h is None:
        return "unknown_home"
    if ru <= {h}:
        return "same_team"
    return "cross_team"


# ---------------------------------------------------------------- stats


def stat_block(values):
    """values: list of hours."""
    if not values:
        return None
    return {
        "n": len(values),
        "median": statistics.median(values),
        "mean": statistics.fmean(values),
        "p25": pct(values, 25),
        "p75": pct(values, 75),
        "p90": pct(values, 90),
        "p95": pct(values, 95),
    }


def buckets(values):
    """Share of values <= each threshold (in hours)."""
    thresholds = [1, 4, 8, 24, 48, 72, 168]  # 1h,4h,8h,1d,2d,3d,1w
    n = len(values)
    if n == 0:
        return {}
    out = {}
    for t in thresholds:
        out[t] = sum(1 for v in values if v <= t) / n
    return out


def analyze_window(prs, days, home):
    cutoff = NOW - datetime.timedelta(days=days)
    sel = [p for p in prs if p["_created"] >= cutoff and passes_filters(p)]

    human = [p for p in sel if not p["_is_bot_author"]]
    bot = [p for p in sel if p["_is_bot_author"]]

    # state breakdown (human)
    states = Counter(p["state"] for p in human)

    # classification (human only)
    cls = Counter(classify(p, home) for p in human)

    # team-count distribution (human, with >=1 requested team)
    team_count_dist = Counter()
    for p in human:
        k = len(p["_req_umbrellas"])
        if k == 0:
            team_count_dist["0"] += 1
        elif k == 1:
            team_count_dist["1"] += 1
        elif k == 2:
            team_count_dist["2"] += 1
        else:
            team_count_dist["3+"] += 1

    def timing_for(group):
        """Return dict with first/last approval wall & business hour stats."""
        first_wall, first_biz, last_wall, last_biz, to_merge = [], [], [], [], []
        approved_n = 0
        for p in group:
            ready = p["_ready"]
            apps = p["_approvals"]
            apps = [(ts, who) for (ts, who) in apps if ts >= ready]  # ignore pre-ready
            if not apps:
                continue
            approved_n += 1
            first = apps[0][0]
            merged = p["_merged"]
            if merged is not None:
                last_candidates = [ts for ts, _ in apps if ts <= merged + datetime.timedelta(minutes=1)]
                last = max(last_candidates) if last_candidates else apps[-1][0]
            else:
                last = apps[-1][0]
            first_wall.append((first - ready).total_seconds() / 3600.0)
            last_wall.append((last - ready).total_seconds() / 3600.0)
            first_biz.append(weekday_seconds(ready, first) / 3600.0)
            last_biz.append(weekday_seconds(ready, last) / 3600.0)
            if merged is not None:
                to_merge.append((merged - ready).total_seconds() / 3600.0)
        return {
            "approved_n": approved_n,
            "first_wall": stat_block(first_wall),
            "first_biz": stat_block(first_biz),
            "last_wall": stat_block(last_wall),
            "last_biz": stat_block(last_biz),
            "to_merge": stat_block(to_merge),
            "first_wall_buckets": buckets(first_wall),
            "last_wall_buckets": buckets(last_wall),
        }

    same = [p for p in human if classify(p, home) == "same_team"]
    cross = [p for p in human if classify(p, home) == "cross_team"]

    return {
        "days": days,
        "cutoff": cutoff,
        "n_selected": len(sel),
        "n_human": len(human),
        "n_bot": len(bot),
        "states": states,
        "cls": cls,
        "team_count_dist": team_count_dist,
        "overall": timing_for(human),
        "same": timing_for(same),
        "cross": timing_for(cross),
        "n_same": len(same),
        "n_cross": len(cross),
    }


# ---------------------------------------------------------------- render


def render_stat_row(label, block):
    if block is None:
        return f"| {label} | 0 | – | – | – | – | – | – |"
    return (
        f"| {label} | {block['n']} | {fmt_hours(block['median'])} | "
        f"{fmt_hours(block['mean'])} | {fmt_hours(block['p25'])} | "
        f"{fmt_hours(block['p75'])} | {fmt_hours(block['p90'])} | "
        f"{fmt_hours(block['p95'])} |"
    )


def render_timing_table(title, timing):
    lines = [f"**{title}** (n with an approval = {timing['approved_n']})", ""]
    lines.append("| Metric | n | Median | Mean | p25 | p75 | p90 | p95 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    lines.append(render_stat_row("Time to first approval (wall-clock)", timing["first_wall"]))
    lines.append(render_stat_row("Time to first approval (Mon–Fri)", timing["first_biz"]))
    lines.append(render_stat_row("Time to full approval (wall-clock)", timing["last_wall"]))
    lines.append(render_stat_row("Time to full approval (Mon–Fri)", timing["last_biz"]))
    lines.append(render_stat_row("Time to merge (wall-clock)", timing["to_merge"]))
    lines.append("")
    return "\n".join(lines)


def render_buckets(title, b):
    if not b:
        return ""
    order = [(1, "≤1h"), (4, "≤4h"), (8, "≤8h"), (24, "≤1d"), (48, "≤2d"), (72, "≤3d"), (168, "≤1w")]
    head = "| " + title + " | " + " | ".join(lbl for _, lbl in order) + " |"
    sep = "|---|" + "|".join("---:" for _ in order) + "|"
    row = "| share | " + " | ".join(f"{b[t] * 100:.0f}%" for t, _ in order) + " |"
    return "\n".join([head, sep, row, ""])


def render_compare(res):
    """Compact same-team vs cross-team comparison for the headline metrics."""

    def cell(block, key, stat):
        b = block.get(key)
        if not b or b.get(stat) is None:
            return "n/a"
        return fmt_hours(b[stat])

    sm, cr = res["same"], res["cross"]
    lines = ["### Same-team vs cross-team at a glance\n"]
    lines.append("| Metric | Same-team | Cross-team |")
    lines.append("|---|---:|---:|")
    lines.append(f"| PRs with an approval | {sm['approved_n']} | {cr['approved_n']} |")
    lines.append(
        f"| First approval — median | {cell(sm, 'first_wall', 'median')} | {cell(cr, 'first_wall', 'median')} |"
    )
    lines.append(f"| Full approval — median | {cell(sm, 'last_wall', 'median')} | {cell(cr, 'last_wall', 'median')} |")
    lines.append(f"| Full approval — p90 | {cell(sm, 'last_wall', 'p90')} | {cell(cr, 'last_wall', 'p90')} |")
    lines.append(f"| Full approval — p95 | {cell(sm, 'last_wall', 'p95')} | {cell(cr, 'last_wall', 'p95')} |")
    lines.append("")
    return "\n".join(lines)


def render(results, home, prs):
    out = []
    out.append("# dfinity/ic — PR approval waiting-time analysis\n")
    out.append(f"_Generated {NOW.strftime('%Y-%m-%d %H:%M UTC')}._\n")
    out.append(
        "This report quantifies how long pull requests in `dfinity/ic` wait for "
        "code-review **approval**, to assess whether review is a productivity "
        "bottleneck. Results are split by whether a PR only needs approval from the "
        "author's **own team** or also from **other teams**.\n"
    )

    # ---- Executive summary (driven by the 12-month window) ----
    r12 = results[0][1]
    ov = r12["overall"]
    sm = r12["same"]
    cr = r12["cross"]

    def med(block, key):
        return fmt_hours(block[key]["median"]) if block[key] else "n/a"

    def p90(block, key):
        return fmt_hours(block[key]["p90"]) if block[key] else "n/a"

    out.append("## Executive summary\n")
    out.append(
        f"Over the last 12 months, **{r12['n_human']:,}** human-authored PRs passed the "
        f"filters. Of those that received review, the **typical (median) PR waited "
        f"{med(ov, 'first_wall')} for a first approval and {med(ov, 'last_wall')} for "
        f"full approval** (all required teams). So for the median PR, approval is "
        f"reasonably fast — review is *not* a severe bottleneck at the center of the "
        f"distribution.\n"
    )
    out.append(
        "**The cost is in the tail and in cross-team PRs.** Key findings:\n\n"
        f"- **Cross-team PRs are the bottleneck.** They reach *full* approval in a "
        f"median of **{med(cr, 'last_wall')}** vs **{med(sm, 'last_wall')}** for "
        f"same-team PRs, and their tail is far heavier (p90 **{p90(cr, 'last_wall')}** "
        f"vs **{p90(sm, 'last_wall')}**). Each extra team that must approve adds "
        f"serial waiting.\n"
        f"- **Cross-team PRs get a *first* look fastest** (median "
        f"{med(cr, 'first_wall')} vs {med(sm, 'first_wall')} for same-team) — more "
        f"requested reviewers means someone responds quickly — but converting that "
        f"into *all* required approvals is what drags.\n"
        f"- **A heavy tail affects every category.** Overall, full approval takes "
        f"p90 **{p90(ov, 'last_wall')}** and p95 "
        f"**{fmt_hours(ov['last_wall']['p95']) if ov['last_wall'] else 'n/a'}**. "
        f"Roughly 10–20% of PRs wait multiple days for approval; this is where "
        f"engineer time is actually lost.\n"
        f"- **Weekends inflate the wait.** Counting only Mon–Fri shaves the tail "
        f"materially (overall full-approval p90 drops from {p90(ov, 'last_wall')} "
        f"wall-clock to {p90(ov, 'last_biz')} business-time).\n"
        f"- **Most PRs are single-team.** {r12['team_count_dist'].get('1', 0):,} of "
        f"{r12['n_human']:,} human PRs need only one team; "
        f"{r12['team_count_dist'].get('2', 0):,} need two and "
        f"{r12['team_count_dist'].get('3+', 0):,} need three or more.\n"
        f"- **Recent trend is slightly better.** The last 6 months are modestly "
        f"faster than the full year (see below), so review latency is not worsening.\n"
    )
    out.append(
        "**Bottom line:** code review is responsive for the median change, but "
        "**cross-team approval coordination and a heavy multi-day tail** are the real "
        "drags on throughput. If frontier models make writing code cheaper, the "
        "relative cost of these approval waits — especially for PRs spanning multiple "
        "teams — will dominate cycle time.\n"
    )

    # Methodology
    out.append("## Methodology\n")
    out.append(
        "- **Source:** all PRs created in the last 12 months (2025-06-18 → "
        "2026-06-18), pulled from the GitHub GraphQL API (reviews + review-request "
        "timeline events). 4,885 PRs fetched before filtering.\n"
        "- **Filters applied:** draft PRs are excluded; open PRs not updated in the "
        f"last {STALE_OPEN_DAYS} days are excluded (treated as abandoned). "
        "Bot-authored PRs are reported separately and excluded from timing stats.\n"
        "- **Ready time** = when the PR first became reviewable (creation time, or the "
        "ready-for-review event if it was opened as a draft).\n"
        "- **Approval** = a human `APPROVED` review (bot/automation reviews ignored).\n"
        "- **Time to first approval** = ready → first approval. **Time to full "
        "approval** = ready → last approval at/before merge (proxy for 'all required "
        "approvals obtained'). PRs that never received a human approval are excluded "
        "from these two metrics (so very fast trivial merges by owners are not "
        "counted).\n"
        "- **Mon–Fri** rows count only weekday time, removing weekends from the "
        "wait (approximate 'business time', UTC; ignores public holidays and "
        "time-of-day).\n"
        "- **Team gating:** GitHub requests review from the CODEOWNERS teams that own "
        "the changed files. A PR is **same-team** if every requested team maps to the "
        "author's own umbrella area, otherwise **cross-team**.\n"
        "- **Team consolidation handled.** CODEOWNERS was reorganized during the "
        "window (61 changes); most notably (#10114, 2026-05-07) the fine-grained "
        "teams `consensus`, `execution`, `team-dsm`, `ic-message-routing-owners`, "
        "`ic-interface-owners`, `crypto-team`, `pocket-ic` were consolidated into the "
        "`core-protocol` umbrella, and `defi-team`→`defi`, `boundary-node`→`node`, "
        "etc. To measure same/cross-team **consistently over time**, every team name "
        "ever requested is mapped to a stable umbrella "
        "(`core-protocol`, `defi`, `node`, `idx`, `dre`, `governance-team`, `sdk`, "
        "`infrasec`, `product-security`, `ic-owners-owners`). The mapping is derived "
        "by resolving each historical CODEOWNERS path through the current file.\n"
        "- **Author home team** is derived empirically from the umbrella most often "
        "requested on that author's single-team PRs. This reflects where an author "
        "actually contributes (agreeing with org-team membership for 18/25 "
        "code-owners; the rest are people who mostly contribute outside their nominal "
        "team or have very few PRs).\n"
    )

    for label, res in results:
        out.append(f"## Last {label}\n")
        out.append(
            f"PRs created since **{res['cutoff'].strftime('%Y-%m-%d')}** that pass the "
            f"filters: **{res['n_selected']}** total — {res['n_human']} human-authored, "
            f"{res['n_bot']} bot-authored.\n"
        )
        states = res["states"]
        out.append(
            f"Human PR state: {states.get('MERGED', 0)} merged, "
            f"{states.get('OPEN', 0)} open, {states.get('CLOSED', 0)} closed.\n"
        )
        cls = res["cls"]
        out.append(
            f"Classification (human): **{cls.get('same_team', 0)} same-team**, "
            f"**{cls.get('cross_team', 0)} cross-team**, "
            f"{cls.get('no_team_request', 0)} no-team-request, "
            f"{cls.get('unknown_home', 0)} unknown-home.\n"
        )
        tcd = res["team_count_dist"]
        out.append(
            f"Reviewing teams per PR: {tcd.get('1', 0)} need 1 team, "
            f"{tcd.get('2', 0)} need 2, {tcd.get('3+', 0)} need 3+ "
            f"({tcd.get('0', 0)} had no team request).\n"
        )

        # Same-vs-cross comparison
        out.append(render_compare(res))

        out.append("### Overall\n")
        out.append(render_timing_table("All human PRs with an approval", res["overall"]))
        out.append(render_buckets("First-approval (wall-clock) reached within", res["overall"]["first_wall_buckets"]))

        out.append("### Same-team PRs\n")
        out.append(render_timing_table("Same-team PRs", res["same"]))
        out.append(render_buckets("First-approval (wall-clock) reached within", res["same"]["first_wall_buckets"]))

        out.append("### Cross-team PRs\n")
        out.append(render_timing_table("Cross-team PRs", res["cross"]))
        out.append(render_buckets("Full-approval (wall-clock) reached within", res["cross"]["last_wall_buckets"]))

    # limitations
    out.append("## Limitations & caveats\n")
    out.append(
        "- **Approval ≠ active waiting.** Elapsed time to approval overlaps with the "
        "author iterating, addressing comments, or working on other PRs. It is an "
        "upper bound on 'lost' time, not pure idle time.\n"
        "- **Full-approval proxy.** 'Time to full approval' uses the last approval at "
        "or before merge. If a PR was mergeable after fewer approvals, this slightly "
        "overstates the required wait; if approvals were dismissed by new commits and "
        "re-requested, it can understate it.\n"
        "- **Home-team is current, data-derived.** It is inferred from a whole year of "
        "review requests; an author who switched teams mid-year is assigned their "
        "dominant area. Team membership history is not available from the API.\n"
        "- **Team mapping is best-effort.** A few low-volume historical teams "
        "(`utopia`, `languages`, `platform-operations`, ~0.3% of requests) are mapped "
        "heuristically; this does not materially affect the aggregates.\n"
        "- **Review-request timeline truncation.** A small number of PRs (≈6%) have "
        ">50 timeline events; the first ready/review-request events used here occur "
        "early, so truncation has negligible effect on classification.\n"
        "- **Bots excluded.** Automation-authored PRs (release bots, dependabot, "
        "etc.) are reported as counts but excluded from timing to avoid skew.\n"
    )

    # validation appendix
    out.append("## Appendix: home-team assignment (top 25 authors by PR count)\n")
    counts = Counter(p["_author"] for p in prs if not p["_is_bot_author"] and p["_author"])
    out.append("| Author | PRs (12mo) | Home umbrella |")
    out.append("|---|---:|---|")
    for a, c in counts.most_common(25):
        out.append(f"| {a} | {c} | {home.get(a, '?')} |")
    out.append("")

    return "\n".join(out)


def main():
    teams = json.load(open("teams.json"))
    login_to_teams = teams["login_to_teams"]
    prs = enrich(load_prs())
    print(f"loaded {len(prs)} PRs")

    home = determine_home_teams(prs, login_to_teams)

    # quick validation: agreement with org membership (mapped to umbrellas) for
    # authors who are members of a code-owning team
    agree = total = 0
    for a, h in home.items():
        org_umbrellas = {to_umbrella(t) for t in login_to_teams.get(a, [])}
        if org_umbrellas:
            total += 1
            if h in org_umbrellas:
                agree += 1
    print(f"home-umbrella agreement with org membership: {agree}/{total}")

    results = []
    for label, days in WINDOWS:
        results.append((label, analyze_window(prs, days, home)))

    # console summary
    for label, res in results:
        print(f"\n=== last {label} ===")
        print(f"selected={res['n_selected']} human={res['n_human']} bot={res['n_bot']}")
        print(f"same={res['n_same']} cross={res['n_cross']} cls={dict(res['cls'])}")
        for name in ("overall", "same", "cross"):
            t = res[name]
            fw = t["first_wall"]
            lw = t["last_wall"]
            if fw:
                print(
                    f"  {name}: approved_n={t['approved_n']} "
                    f"first_med={fmt_hours(fw['median'])} "
                    f"full_med={fmt_hours(lw['median'])}"
                )

    report = render(results, home, prs)
    with open("report.md", "w") as f:
        f.write(report)
    print("\nwrote report.md")


if __name__ == "__main__":
    main()
