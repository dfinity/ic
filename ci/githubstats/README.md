Statistics on GitHub Actions
===

A PostgreSQL database is maintained that stores information on all GitHub Action workflow runs of the dfinity/ic repository. It stores workflow runs, jobs and steps. Additionally it stores bazel invocations per workflow run and their associated bazel tests.

The DB can be accessed in a read-only matter via the browser using Apache Superset at:

* https://superset.idx.dfinity.network/
  All DFINITY engineers can sign in using Okta. Ask #help-it in case that doesn't work.

* Or via the CLI with `psql` if you're on the VPN using:
```
psql postgresql://githubstats_read@githubstats.idx.dfinity.network/github
```

Frequently Asked Queries
---

The following Python script can be used to run some frequently asked queries
(use `--verbose` to log the queries):

```
$ bazel run //ci/githubstats:query -- --help
usage: bazel run //ci/githubstats:query -- [-h] {top,last} ...

positional arguments:
  {top,last}
    top       Get the top N non-successful / flaky / failed / timed-out tests in the last period
    last      Get the last runs of the specified test in the given period

options:
  -h, --help  show this help message and exit
```