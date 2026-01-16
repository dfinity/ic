Statistics on GitHub Actions
===

A PostgreSQL database is maintained that stores information on all GitHub Action workflow runs of the dfinity/ic repository. It stores workflow runs, jobs and steps. Additionally it stores bazel invocations per workflow run and their associated bazel tests.

The DB can be accessed in a read-only matter via the browser using Apache Superset at:

* https://superset.idx.dfinity.network/
  All DFINITY engineers can sign in using Okta. Ask #help-it in case that doesn't work.

* Or via the CLI with `psql` if you're on the VPN using:
```
psql -h githubstats.idx.dfinity.network -U githubstats_read -d github
```

Useful queries
---
