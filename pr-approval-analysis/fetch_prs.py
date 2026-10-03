#!/usr/bin/env python3
"""
Fetch all PRs from dfinity/ic created within the last N days via the GraphQL API.

For each PR we capture creation/ready/merge/close timestamps, draft status, state,
size, the review decisions/approvals (with timestamps + authors), and the timeline
events that tell us which *teams* were requested for review (CODEOWNERS) plus
ready-for-review / convert-to-draft transitions.

Writes prs.jsonl (one JSON object per line).
"""

import datetime
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

DAYS = 365
PAGE_SIZE = 25


def get_token():
    # Prefer an independent token that the other machine's `gh auth login`
    # cannot revoke: a PAT in a file, or GH_TOKEN/GITHUB_TOKEN env. Fall back
    # to the shared gh OAuth token only if nothing else is provided.
    token_file = os.environ.get("PR_FETCH_TOKEN_FILE", os.path.expanduser("~/.gh_pat"))
    if os.path.exists(token_file):
        t = open(token_file).read().strip()
        if t:
            return t
    t = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if t:
        return t.strip()
    return subprocess.check_output(["gh", "auth", "token"], text=True).strip()


NOW = datetime.datetime.now(datetime.timezone.utc)
CUTOFF = NOW - datetime.timedelta(days=DAYS)

QUERY = (
    """
query($cursor: String) {
  repository(owner: "dfinity", name: "ic") {
    pullRequests(first: %d, after: $cursor, orderBy: {field: CREATED_AT, direction: DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number
        author { login __typename }
        createdAt
        updatedAt
        isDraft
        state
        mergedAt
        closedAt
        additions
        deletions
        changedFiles
        reviewDecision
        reviews(first: 50) {
          totalCount
          nodes { state submittedAt author { login __typename } }
        }
        timelineItems(first: 50, itemTypes: [READY_FOR_REVIEW_EVENT, CONVERT_TO_DRAFT_EVENT, REVIEW_REQUESTED_EVENT]) {
          totalCount
          nodes {
            __typename
            ... on ReadyForReviewEvent { createdAt }
            ... on ConvertToDraftEvent { createdAt }
            ... on ReviewRequestedEvent {
              createdAt
              requestedReviewer {
                __typename
                ... on Team { slug }
                ... on User { login }
              }
            }
          }
        }
      }
    }
  }
}
"""
    % PAGE_SIZE
)


class AuthExpired(Exception):
    """Raised when the GitHub token is no longer valid and a manual re-auth is needed."""


def post(query, variables):
    body = json.dumps({"query": query, "variables": variables}).encode()
    last_err = None
    auth_fails = 0
    for attempt in range(8):
        token = get_token()  # gh returns the current token (no background rotation)
        req = urllib.request.Request(
            "https://api.github.com/graphql",
            data=body,
            headers={"Authorization": f"bearer {token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req) as r:
                data = json.loads(r.read())
            if "errors" in data:
                # RATE_LIMITED or transient — back off and retry
                last_err = data["errors"]
                print("GraphQL errors:", data["errors"], file=sys.stderr)
                time.sleep(3 * (attempt + 1))
                continue
            return data
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 401:
                # Token expired. gh does NOT refresh non-interactively, so do not
                # call `gh auth refresh` (it blocks on the device flow). Retry a
                # couple times to rule out a spurious 401, then bail out so the
                # caller can checkpoint and exit for a manual re-auth + resume.
                auth_fails += 1
                print(f"401 Unauthorized (auth_fails={auth_fails})", file=sys.stderr)
                if auth_fails >= 3:
                    raise AuthExpired(str(e))
                time.sleep(2)
                continue
            print("HTTP error:", e, file=sys.stderr)
            time.sleep(3 * (attempt + 1))
        except Exception as e:  # noqa: BLE001
            last_err = e
            print("error:", e, file=sys.stderr)
            time.sleep(3 * (attempt + 1))
    raise RuntimeError(f"failed after retries: {last_err}")


def parse_ts(s):
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))


def main():
    # Resume support: load already-fetched PR numbers and the saved cursor.
    seen = set()
    if os.path.exists("prs.jsonl"):
        with open("prs.jsonl") as fr:
            for line in fr:
                line = line.strip()
                if not line:
                    continue
                try:
                    seen.add(json.loads(line)["number"])
                except Exception:  # noqa: BLE001
                    pass
    cursor = os.environ.get("RESUME_CURSOR") or None
    if cursor is None and os.path.exists("cursor.txt"):
        cursor = open("cursor.txt").read().strip() or None
    print(f"resume: have={len(seen)} start_cursor={cursor}", file=sys.stderr)

    new = 0
    stop = False
    f = open("prs.jsonl", "a")
    try:
        while True:
            try:
                data = post(QUERY, {"cursor": cursor})
            except (AuthExpired, RuntimeError) as e:
                # Checkpoint the cursor for the page we failed on, then exit so the
                # caller can re-authenticate and rerun (which resumes from here).
                with open("cursor.txt", "w") as cf:
                    cf.write(cursor or "")
                f.flush()
                os.fsync(f.fileno())
                print(f"INTERRUPTED cursor={cursor} err={e}", file=sys.stderr)
                print(f"RESUME_NEEDED have={len(seen)} new_this_run={new}")
                sys.exit(2)
            conn = data["data"]["repository"]["pullRequests"]
            for pr in conn["nodes"]:
                if parse_ts(pr["createdAt"]) < CUTOFF:
                    stop = True
                    break  # ordered DESC, everything after is older
                if pr["number"] in seen:
                    continue  # dedupe across resumes / overlapping pages
                seen.add(pr["number"])
                f.write(json.dumps(pr) + "\n")
                new += 1
            f.flush()
            os.fsync(f.fileno())
            next_cursor = conn["pageInfo"]["endCursor"]
            print(f"have={len(seen)} new={new} stop={stop} next={next_cursor}", file=sys.stderr)
            if stop or not conn["pageInfo"]["hasNextPage"]:
                break
            cursor = next_cursor
            with open("cursor.txt", "w") as cf:
                cf.write(cursor)
    finally:
        f.close()
    # Completed the full window: clear the checkpoint.
    if os.path.exists("cursor.txt"):
        os.remove("cursor.txt")
    print(f"DONE total_unique={len(seen)} new_this_run={new}")
    print(f"cutoff={CUTOFF.isoformat()} now={NOW.isoformat()}")


if __name__ == "__main__":
    main()
