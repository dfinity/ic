# Development Guide

## Release Preparation

There are 3 packages published to crates.io: `canbench`, `canbench-rs`, and `canbench-rs-macros`.  
Before publishing them, you should create a PR to bump the versions of the packages, and then cut a new release on GitHub after the PR with the new versions is merged. Let's say it's version `vX.X.X`.

Here's an example PR bumping the versions: https://github.com/dfinity/canbench/pull/71.

## Steps to Cut a Release

1. Identify the commit for the release, e.g. `aff3eef`.
2. Draft a new pre-release:
    - Click on **Draft a new release** at the [releases page](https://github.com/dfinity/canbench/releases), and make sure the correct commit is selected.
    - Create a new tag named `vX.X.X`.
    - Set the title to `vX.X.X`.
    - Choose the previous tag as the last release.
    - Add release notes. GitHub can generate them by clicking **Generate release notes**, modify as needed.
3. Click **Publish release** when ready.

## Steps to Publish the Packages to crates.io

1. On the repository main page, navigate to the `Actions` tab.
2. Click on the workflow to publish to crates.io
3. Click on `run workflow` and select the version tag created above for the workflow to run on.
