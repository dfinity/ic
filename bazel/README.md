# Scope

This document helps developers understand how to start with Bazel and port
Cargo development workflows over to Bazel. While this guide focuses on Rust
development, Bazel is a polygot build system: See the “Language Specific
Guides” section below.

If you know C++ or Java, the best introductory reading material might be the
official guides for those languages (linked at the bottom of
[this](https://bazel.build/about/intro) page). Unfortunately, there is no Rust
analog, but the main concepts are language-independent, so it might be a good
idea to start with the C++ or Java guides.

# Setup

We recommend a Linux machine although MacOS works for Rust development but may
require some package installation.

**Do NOT use nix-shell.**

**Do NOT use direnv.**

**DO NOT use apt-get.**

To install Bazel follow the instructions on
[https://github.com/bazelbuild/bazelisk](https://github.com/bazelbuild/bazelisk).
IDX recommends and only supports `bazelisk` - do not install the `bazel`
package with native package managers such as apt get, homebrew, etc..

To build Rust and IC-OS code will require a minimal set of packages. On a Linux
host the
`[Dockerfile](https://github.com/dfinity/ic/blob/master/gitlab-ci/container/Dockerfile)`
serves as a reference for the minimal apt installation set. Developers may
develop inside the build and development container with
`./gitlab-ci/container/container-run.sh`.

```bash
bazel test //rs/crypto/sha2:all
```

Most targets should build on the host machine. However, the IC-OS image only
builds inside the canonical container (`ic-build-bazel:$TAG`). To enter this
docker container run `./gitlab-ci/container/conatiner-run.sh`. This container
is only available in x86-64 environments.

# Building Blocks

## Bazel Commands

The three most common commands for developers are `build`, `test` and `run`.

### Bazel Build

`bazel build //path:target_name`

Just builds the target binary, library or test; but doesn’t do anything with it.
Outputs it to the `bazel-bin` directory at the root of the workspace.

*Examples (see*
[https://docs.bazel.build/versions/main/guide.html#specifying-targets-to-build](https://docs.bazel.build/versions/main/guide.html#specifying-targets-to-build))

`bazel build //rs/crypto/sha:sha`

`cd rs/crypto; bazel build :sha`

`bazel build //rs/crypto/sha:all`

`bazel build //rs/crypto/...`: build all rule targets in all packages beneath
the directory `crypto`.

### Bazel Test

`*bazel test //path:target_name*`

Builds an executable test binary [or binaries] and runs them, outputting and
caching the results. Cached results will not be rerun. Bazel only caches passed
test results. The flag  `--cache_test_results=no` will make Bazel rerun cached
tests.

To see log output from failed tests add `--test_output=errors`. To see all log
output add `--test_output=all`. To see output of non-failing Rust tests,
additionally add `--test_arg=--nocapture`.

To run only a specific test add `--test_arg=$TEST_NAME`

*Examples*

`bazel test //rs/log_analyzer:tests`

`cd rs/log_analyzer; bazel test :tests`

`bazel test //rs/log_analyzer:all`

`bazel test //rs/log_analyzer/...`

### Bazel Run

`*bazel run //path:target_name*`

Builds executable binary and then executes it on the host machine.

*Examples*

`bazel run //rs/log_analyzer:log_analyzer_bench`
`cd rs/log_analyzer; bazel run :log_analyzer_bench -- --bench`

All tests are also binaries that can be run:

`bazel run //rs/registry/canister:registry_canister_canister_test -- --help`

## BUILD.bazel Files

BUILD.bazel files define targets and their dependencies. You can see a complete
list of Rust build rules [here](https://bazelbuild.github.io/rules_rust/flatten.html). For Rust, the
most common targets are:

### `rust_library`

Builds a rust library crate. You can build this with `bazel build` command
described above.

### `rust_binary`

Builds a rust executable. You can build this with `bazel build` and run it on
your host machine with `bazel run`

### `rust_test`

Builds a Rust crate tests. You can build this with `bazel build` and execute the
test suite with `bazel test`

### `rust_doc_test`

Builds a Rust doc tests tests. You can build this with `bazel build` and execute
the test suite with `bazel test`

## WORKSPACE.bazel and external_crates.bzl

[WORKSPACE.bazel](https://github.com/dfinity/ic/blob/master/WORKSPACE.bazel)

The workspace file defines the root of the Bazel workspace and defines which
external dependencies to pull into the build.

[bazel/external_crates.bzl](https://github.com/dfinity/ic/blob/master/bazel/external_crates.bzl)

The workspace file pulls Rust crate dependencies from
`bazel/external_crates.bzl` . The crate dependencies live in a separate file to
facilitate integration with automation.

Changes to the crate_repository require regeneration of `Cargo.Bazel.*.lock`
with `./bin/bazel-pin.sh`

Below is an example of adding a new third-party crate.

1.  The main thing is adding an entry to bazel/external_crates.bzl . In this
example, I used/added the egg-mode crate in `bazel/external_crates.bzl`

```git
+ "egg-mode": crate.spec(
+   version = "^0.16.0",
+ ),
```

2.  `./bin/bazel-pin.sh`

3.  Don't worry about the changes to the two Cargo.Bazel.* files (in the root of the repo). Those are all generated by the repin command

## Example BUILD.Bazel File

[rs/crypto/sha/BUILD.bazel](https://github.com/dfinity/ic/blob/master/rs/crypto/sha/BUILD.bazel)

```bash
load("@rules_rust//rust:defs.bzl", "rust_doc_test", "rust_library", "rust_test")

package(default_visibility = ["//visibility:public"])

rust_library(
    name = "sha",
    srcs = glob(["src/**"]),
    crate_name = "ic_crypto_sha",
    version = "0.9.0",
    deps = ["//rs/crypto/internal/crypto_lib/sha2"],
)

rust_doc_test(
    name = "sha_doc_test",
    crate = ":sha",
)

rust_test(
    name = "sha224_test",
    srcs = ["tests/sha224.rs"],
    deps = [
        ":sha",
        "@crate_index//:openssl",
    ],
)

rust_test(
    name = "sha256_test",
    srcs = ["tests/sha256.rs"],
    deps = [
        ":sha",
        "@crate_index//:openssl",
    ],
)
```

## Python tests
Python bazel targets are built very similarly and also include `py_test`, `py_library`, `py_binary`. Note that `py_library` is a python module which tests can import and test against. Test deps can either be a `py_library` or a `requirement`, see example below:

```
load("@python_deps//:requirements.bzl", "requirement")

py_library(
    name = "my_module",
    srcs = ["my_module.py"],
    deps = requirement("numpy"),
)

py_test(
    name = "test_my_module",
    srcs = ["tests/test_my_module.py"],
    deps = [":my_module", requirement("pytest")],
)
```

Note that if a module is defined with a package dependency, then the test does not need to specify this dependency again, but can import the entire module. Similarly if packages depend on other packages, only the top-level package needs to be imported.

Some good examples for writing bazel tests can be found in `scalability/BUILD.bazel`.

To add python packages to the build container for use in a build or test target in bazel, follow [these instructions](https://github.com/dfinity/ic/blob/master/ci/srcowTo-Developer.adoc).


## Target Labels

In Bazel, target labels specify the absolute paths from the root of the
workspace to the BUILD.bazel file, or the target name from the current working
directory. Relative paths are not possible. Examples:

Example absolute path `bazel build //rs/crypto/sha:sha`

Example current working dir: `cd rs/crypto/sha; bazel build :sha`

Targets external to the workspace [e.g. third party crates] need to include the
repository name. For exam-ple `bazel build @crate_index//:openssl`

See
[https://docs.bazel.build/versions/main/build-ref.html#labels](https://docs.bazel.build/versions/main/build-ref.html#labels)
for Bazel’s nomenclature and more details.

### Wildcards

Bazel
[reference](https://docs.bazel.build/versions/main/guide.html#specifying-targets-to-build)

The `:all` target name specifies all targets in the path. For example `bazel
build //rs/log_analyzer:all` builds all libraries, executable binaries and
tests.

The `...` name specifies all targets in the workspace and recurses starting from
the current working directory. Note, there’s no colon. When used with `bazel
test`, also build all targets including those not referenced by any test.

*Examples*

`cd rs; bazel build ...` builds all Rust libraries, executable binaries and tests.

`cd rs; bazel test ...` runs all Rust tests and builds all Rust libraries and executables.

# Example Cargo to Bazel Conversion MRs

Take a look at the following example migration. It is instructive to compare and
contrast the  the  `Cargo.toml` file with its associated `BAZEL.build` file.

- [Criterion Times](https://github.com/dfinity/ic/commit/83bafb9c102eb91b0afde7c5d2260532bc6874d5)
- [Log Analyzer](https://github.com/dfinity/ic/commit/63b176839c61ebe028cf93ed058f81d5b552efc8)

# Visualize and Share

Developers may inspect and share detailed build results, timings, logs and
artifacts with the buildfarm URL. Note the buildfarm URL emitted at the start and
end of the build.



# Flaky Tests

Bazel provides several tools to **mitigate** and **resolve** flaky tests.

## Mitigation

Mark the test as **flaky** to make Bazel will retry the test up to three times.

```bash
rust_test(
	name = "foo_test",
  # lines omitted
	flaky = True",
)
```

Instruct rust to only run one test in parallel - this can help when multiple
concurrent test cases collide but may greatly increase the runtime of the tests.

```bash
rust_test(
	name = "foo_test",
  # lines omitted
  args = [
       "--test-threads",
      "1",
  ],
)
```

## Resolution

The test owners are responsible for eliminating flakiness in their tests.

Bazel provides a facility to reproduce flaky tests, `--runs_per_test <num>`
makes Bazel re-run a test multiple times and aggregate the result.

```bash
bazel test //rs/rust_canisters/memory_test:memory_test_integration_test
--runs_per_test 100
```

# Best Practices

[Minimize
visibility](https://docs-staging.bazel.build/2338/versions/main/visibility.html#best-practices).
Just like members of a class should generally be private, you should restrict
visibility (this is why private is the default visibility). The reason is that
it minimizes the amount of code that can depend on you. This is a Good Thing™️,
because if you later want to make an incompatible change (e.g. add a parameter
to a pub fn), there will be less affected downstream code that you’ll have to
update. The more people who can use an API, the harder it is to change. You will
find many BUILD.bazel files that do the “wrong thing”, in that [they contain the following line](https://sourcegraph.com/search?q=context:global+repo:%5Egithub%5C.com/dfinity/ic%24+package%28default_visibility+%3D+%5B%22//visibility:public%22%5D%29&patternType=standard&case=yes&sm=0):

```python
package(default_visibility = ["//visibility:public"])
```

We have many of these (despite this best practice), because we migrated from
Cargo. We didn’t hand-craft these BUILD.bazel files. Do not follow these
examples in new BUILD.bazel files. If you are feeling ambitious, it would be
nice if you updated this line in your BUILD.bazel files.

# FAQ

### How do I lint (i.e. run rustfmt, and clippy)?

Add `--config=lint` to your bazel command.

By default, clippy violations are just warnings, but formatting issues do not
generate warnings (just like what you’re probably used to from cargo).

Alternatively, if you only want one or the other, do `--config=fmt` or
`--config=clippy` instead (the latter maybe isn’t so useful, since you get
warnings by default anyway).

E.g.

```jsx
bazel build --config=lint //rs/sns/swap:all
```

### Crate contains data files

```jsx
crate/
├─ Cargo.toml
├─ BUILD.bazel
├─ data/
│  ├─ test.csv
├─ src/
│  ├─ lib.rsrs
```

With cargo, tests reference data file relative to the crate root directory.
However, Bazel runs all tests from the workspace root.

The following example adds a data file to the `BUILD.bazel` file under
`rust_test`.

```jsx
data = ["data/test.csv"],
env = {
	"CARGO_MANIFEST_DIR": "rs/bitcoin/validation",
},
```

Change how you access the file. This way we don’t break the cargo pipeline.

```rust
let rdr = Reader::from_path(
		PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
			.join("tests/data/headers.csv"));
```

[Example MR](https://github.com/dfinity/ic/commit/592c25ea302be55f2ef745dc61700e8767909b6c)

### How to recalculate `Cargo.Bazel.*.lock` file?

Run `./bin/bazel-pin.sh` from the root of the repo to recalculate
`Cargo.Bazel.*.lock` files (should take about a minute or three)

You may run it inside of `./gitlab-ci/container/container-run.sh` if you don’t
have `bazel` commands installed locally.

### rustfmt

`bazel run //:rustfmt`

### Clear Local Bazel Cache

`bazel/bazel_clean.sh`

You might also want to consider adding `--expunge`.

### How do I make debug vs. release builds?

Append `--config=dev` to your bazel command.

```bash
bazel build --config=dev :target
bazel test --config=dev :target
```

See `.bazelrc` at the root of the repo for details on other config options.

### How to run a unit test in just a single file?

Use the flag `--test_arg` to pass the test as an argument over to the Rust test runner. e.g.

```bash
bazel test //rs/registry/canister:registry_canister_test
--test_arg="registry::tests::test_apply_mutations_delta_too_large"
```

### How to run a group of unit tests and see their output?

Use `--test_output=all --test_arg=--nocapture` flags, and also
`--test_arg=heartbeat_` to match a group of tests.

```bash
bazel test --flaky_test_attempts=1 --test_output=all --test_arg=--nocapture
//rs/execution_environment:execution_environment_test --test_arg=heartbeat_
```

### How to find out where builds spend the most time?

Find the dashboard link. Bazel should output this immediate before and
after the Bazel command line invocation. Navigate to the “TIMING” section and
inspect the “Critical Path”

### How to measure the test coverage?

Bazel can collect test coverage information with the
[coverage](https://bazel.build/configure/coverage) command.

```bash
bazel coverage --combined_report=lcov //rs/my/test:target
```

You need to have `genhtml` tool installed to see the report. The tool comes with
the `lcov` package. You need to run `genhtml` in the repository root directory.

```bash
genhtml --ignore-errors source --output genhtml "$(bazel info output_path)/_coverage/_coverage_report.dat"
```

Open the `genhtml/index.html` file in a browser and navigate to the file of
interest to see the coverage.

### “Too many open files in system” error on MacOS

Add this line to `/etc/launchd.conf`:

`limit maxfiles 1000000 1000000`

### How do I auto-format my `.bazel` files?

Run `bazel run //:buildifier`

### Is there something equivalent to `cargo check` but for bazel?

TL;DR
Run `bazel build --config=check //rs/some/target`

The above command will try to only build metadata files for all the rust
libraries, which is almost exactly what `cargo check` does. As with cargo check,
this is not always possible, e.g. when a library depends on a macro.

This feature is still experimental, so please report any issues you encounter
with it, especially if they look something like `error[E0460]: found possibly
newer version of crate ...`.

### Is is possible to deploy a static testnet bazel?

Yes! Follow this procedure:
[testnet/tools/README.md](https://github.com/dfinity/ic/blob/master/testnet/tools/README.md)

### What is the official Bazel slack channel?

You can also find additional help in the Google Bazel documentation and in the
Google Bazel Slack organisation [[Invite link here](https://join.slack.com/t/bazelbuild/shared_invite/zt-18mwk19k1-cxoouSeqqGgkmiweHK35ag)].

# Language Specific Guides
## Go
### Overview

DFINITY uses Rust for systems programming. Rust offers strong safety guarantees
that benefit reliable systems programming; however the tradeoffs include slower
development cycles and a steeper learning curve. Therefore, for other domains
such as CLI tools, infrastructure automation, and scripting other languages
offer merits over Rust

- Faster development cycles
- Faster learning curve
- Mature community API client library support [e.g. GitLab API client libraries]

Historically, DFINITY used Python as an infrastructure or scripting languages.
The IDX team has written automation scripts and daemons in Python, and the Node
team has maintained Python scripts to build the IC-OS disk image. While Python
is ubiquitous and offers a fast learning curve, it notoriously “converts your
compile time errors into run-time errors” which can increase software
development times and cause unexpected breakages. Furthermore, while better than
shell scripts, Python codebases eventually become more difficult to read,
maintain and extend.

Therefore, IDX strongly recommends **Golang** over Python for CLIs,
infrastructure tools and  scripting tasks. The Bazel build infrastructure
provides seamless Golang integration into the CI and build system - automation
tools handles the heavy lifting to generate BUILD files and manage external
dependencies.

### Getting Started

This tutorial will guide you through two programs that will acquaint you with Go
development in the IC repo.

- “Hello World Basic” will only use the Go standard library
- “Hello World Advanced” will bring in an external dependency.

Both programs will use [gazelle](https://github.com/bazelbuild/bazel-gazelle) -
a tool which generates build files and manages external dependencies.

### Hello World Basic

From a recent checkout of the IC repo:

```bash
**mkdir go-demo-basic
cd go-demo-basic**
**touch main.go**

# contents of main.go
package main

import "fmt"

func main() {
  fmt.Println("hello world")
}
# end contents of main.go
```

```bash
**bazel run //:gazelle**

**tree
.**
├── BUILD.bazel
└── main.go

**bazel run //go-demo-basic:go-demo-basic 2>/dev/null**

hello world
```

The command `bazel run //:gazelle` will generates the correct `BUILD.bazel`
file. You can then build and execute the Go binary with `bazel run //demo:demo`
. The CI system is batteries included. IDX’s infrastructure automatically
picks-up and builds these new targets on the CI merge requests pipelines.

### Hello World Advanced

```bash
**mkdir go-demo-advanced
cd go-demo-advanced
touch main.go**

# contents of main.go
package main

import("github.com/common-nighthawk/go-figure")

func main() {
  myFigure := figure.NewFigure("Hello World", "", true)
  myFigure.Print()
}
# end contents of main.go
```

```bash
**bazel run //:gazelle**

**tree**
.
├── BUILD.bazel
└── main.go
```

The new BUILD.bazel file will reference the external dependency [take a look at
the contents of the build file]. However, before Bazel can build and run the new
binary, Bazel needs to know how to fetch and provide that dependency and all its
transitive dependencies.

```bash
**bazel run //:gobin -- get github.com/common-nighthawk/go-figure**
**bazel run //:gazelle-update-repos

git status
# the above commands modified the following files: go.mod, go.sum, go_deps.bzl**
```

****And now Bazel can build and run the advanced hello world binary.

```bash
**bazel run //go-demo-advanced:go-demo-advanced 2>/dev/null

  _   _          _   _            __        __                 _       _
 | | | |   ___  | | | |   ___     \ \      / /   ___    _ __  | |   __| |
 | |_| |  / _ \ | | | |  / _ \     \ \ /\ / /   / _ \  | '__| | |  / _` |
 |  _  | |  __/ | | | | | (_) |     \ V  V /   | (_) | | |    | | | (_| |
 |_| |_|  \___| |_| |_|  \___/       \_/\_/     \___/  |_|    |_|  \__,_|**
```

### Real World Code Example

See [bazel/exporter](https://github.com/dfinity/ic/tree/master/bazel/exporter)
for a more advanced real world tool which requires several external dependencies
and Go protobuf definitions. The Bazel exporter runs at the end of every Bazel
CI job; reads Bazel build events protobufs; and exports telemetry to Honeycomb
to populate data.
