# Contributing to the Internet Computer Protocol

## Guidelines

Thank you for your interest in contributing to the Internet Computer Protocol. If you'd like to contribute a feature or bug fix, please **reach out to us first** so that we can discuss feasibility and implementation strategies. You can reach out to us on the [forum](https://forum.dfinity.org/).

Make sure to read the [LICENSE](LICENSE) first.

Ohter guidelines?

## Running CI on your code changes

For security reasons, we do not run CI on PRs submitted by external contributors automatically. We review PRs first, then kick them off manually. Please use the following instructions:

1. To avoid long feedback loops run tests locally first. You can follow the instructions in the [HACKING.md](HACKING.md) document.
1. For security reasons, you cannot make any changes to the [following files](.github/repo_policies/EXTERNAL_CONTRIB_BLACKLIST). If you do, your PR will be closed automatically.
1. Once your PR is ready for review, submit the PR and click `Ready for Review` and someone will review your PR and kick off CI.
1. You will be notified that CI has been kicked off with a link to the CI run in a comment. Once CI is complete, it will report the status back to your PR.
1. Running CI manually will need to be repeated for any new commits you push.
