<p>
  <a href="https://github.com/dfinity/canbench/blob/main/LICENSE">
    <img alt="Apache-2.0" src="https://img.shields.io/github/license/dfinity/bench"/>
  </a>
  <a href="https://forum.dfinity.org/">
    <img alt="Chat on the Forum" src="https://img.shields.io/badge/help-post%20on%20forum.dfinity.org-blue">
  </a>
</p>

# `canbench`

`canbench` is a tool for benchmarking canisters on the Internet Computer.

## Background

Canister smart contracts on the Internet Computer consume compute and memory resources.  
Since resources are finite, execution of a message (transaction) must remain within specific bounds:

1. **Instructions**: A monotonically increasing counter correlated with compute and memory usage.
2. **Dirty Pages**: The number of memory pages written to.

If a message exceeds these limits, it is aborted.
`canbench` gives developers insights into how their code consumes instructions and memory. 
Support for reporting dirty pages will be added once the IC exposes that information.

## Use Cases

- Analyze instruction, heap, and stable memory usage of canisters
- Detect performance regressions in local or CI environments
- Identify potential performance bottlenecks

## Features

- **Relevant metrics**

  Traditional benchmarking tools rely on repeated runs and averaging time.  
  On the deterministic Internet Computer, this is neither necessary nor insightful.  
  `canbench` reports instruction count and memory changes directly.

- **Regression detection**

  Persist benchmark results in your repo.  
  `canbench` compares results over time to highlight performance regressions.

- **High instruction limits**

  While regular messages are capped at a few billion instructions, `canbench` supports up to 10 trillion, allowing deep benchmarking.

- **Language-agnostic**

  While currently Rust-focused, `canbench` is designed to support canisters written in any language.

## Installation

```bash
cargo install canbench
```

## Quickstart (Rust)

See the [crate's documentation](https://docs.rs/canbench-rs).

## GitHub CI Support

You can integrate `canbench` into your GitHub CI pipeline to catch regressions automatically.

You’ll need:

1. Benchmark scripts (see `scripts/` directory)

2. A workflow that posts benchmarking results as PR comments (`canbench-post-comment.yml`)

3. A job to upload the PR number (see `upload-pr-number` in `ci.yml`)

4. The benchmark job itself (e.g. `benchmark-fibonacci-example` in `ci.yml`)

Once configured, the job will fail on regressions and pass otherwise.
It will also leave a PR comment with detailed results.
See [this PR](https://github.com/dfinity/bench/pull/18) example.