# Testing Infrastructure: `rs/tests`

Note: For an overview over the testing terminology, please visit [this
notion-page](https://www.notion.so/Testing-Terminology-8cc0735dfcd945959f8d47caedf058b5).

## System tests

System Tests (declared in `rs/tests/bin/prod_test_driver.rs`) drive all
components in combination in the form of a functioning IC. The test API is
implemented in Rust.

In System Tests, every node is instantiated as a virtual machine running the
[ic-os](https://sourcegraph.com/github.com/dfinity/ic/-/tree/ic-os/guestos). The
test driver allocates virtual machines using a backend service called
[Farm](https://github.com/dfinity-lab/infra/tree/master/farm/). Resources
allocated with farm are collected after a maximum time-to-live.

System Tests are organized in a hierarchy: every test belongs to a _pot_. A pot
declares the test system (Internet Computer under test). Multiple tests can run
using the same test instance (of a pot) either in parallel or in sequence. Pots
in turn are grouped into _test suites_.

### How can I run system tests?

Make sure you're in the nix-shell.
When running system tests, the base ic-os version has to be set manually.
Currently, only images built by CI can be used. Thus, you first need to find out
the `IC_VERSION_ID` that belongs to the image that you want to use. Note that
alongside the image itself, also all other build artifacts that belong to that
version are downloaded from CI/CD (NNS canisters, auxiliary binaries, etc.).
When run locally, only the test driver (including tests) is re-compiled and
includes local changes.

You have two options to find the desired `IC_VERSION_ID`:

1. To obtain a GuestOS image version for your commit, please push your branch
to origin and create an MR. See http://go/guestos-image-version
1. To obtain the latest GuestOS image version for `origin/master` (e.g., if your
changes are withing `ic/rs/tests`), use the following command (Note: this
command is not guaranteed to be deterministic):

```bash
ic/gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh origin/master
```

For example, running all tests in a test suite `hourly` can be achieved as
follows:

```bash
IC_VERSION_ID=<version> ./run-system-tests.py --suite hourly
```

The command line options `include-pattern` and `exclude-pattern` allow the
inclusion and exclusion of tests based on regular expressions. See also the
`--help` message for more information.

For example, running the basic health test can be achieved using the following
command:

```bash
IC_VERSION_ID=<version> ./run-system-tests.py --suite hourly --include-pattern basic_health_test
```

If you have further questions, please contact the testing team on #eng-testing.

## Legacy System Tests

The `rs/tests`-crate is also host to so-called legacy system tests declared in
`rs/tests/src/main.rs`. The tests use largely the same API, however, the nodes
are instantiated as processes that are launched on the same operating system as
the test driver.

**Note**: Legacy system tests are **not** supported on Darwin!
### My test is failing/flaky, what do I do?

Please, check the [FAQ](doc/FAQ.md) or [TROUBLESHOOTING](doc/TROUBLESHOOTING.md) before submitting
a bug report

### Running the tests
To run the tests locally, run the `setup-and-cargo-test.sh` script. Go to the end of the page for info on the CLI arguments.
If you are running the script within nix-shell on Linux and run out of disk space, `export TMPDIR=` might solve this issue for you.
On Ubuntu 20.04, nix-shell sets the initially unset TMPDIR to /run/user/1000, which might be too small for the tests. Unsetting this variable enables the tests to use /tmp instead.

### High Level Overview

The `rs/tests` crate builds our `system-tests` binary, whose sole responsibility is to run our system tests 
Underneath `system-tests` we have two auxiliary libraries: `ic_fondue` and `fondue`.

1. `fondue` is a general-purpose abstraction for running distributed system
	 tests. It enables us to specify a initial configuration describing the
	 initial state of the system, an active test that interacts with the
	 configured system and a passive pipeline that monitors the signals from the
	 different system components. Fondue is paramount to our tests by abstracting
	 away the meta environment setup: which thread processes what? Where do the
	 log messages go? How do we access the passive pipeline from within a test?
	 How do we pass a PRNG through ensuring they are reproducible? etc...
	 Moreover, having a general purpose library ensures we can test that these
	 features are all working properly with toy systems, increasing the
	 confidence in `fondue`'s reliability.
1. `ic_fondue` is an instantiation of `fondue` for the IC: the initial
	 configuration corresponds with a topology, each `fondue` process is a
	 `orchestrator` and we look at the logs produced by each replica as the source
	 of passive information. This minimizes the chance of a test writer wiring
	 everything in the wrong way.

### So You Want to Write a Test?

You've got the urge to write a test? Need a little guidance? you can start
looking at `src/basic_health_test`. It is a small, documented and rich example.
Please, ask your questions away on #eng-testing! We're happy to answer them.

When writing your test, please keep in mind a few important things:

1. Make sure to add a ASCIIDOC description to the beginning of your file, just
	 like `basic_health_test`.
1. Don't forget to make use of the `ekg` module, which provides combinators to
	 passively monitor the behavior of the replicas that are running. Most of the
	 times you'll want `ekg::basic_monitoring`, just like `basic_health_test`.
1. Make sure to mark your test as "stating", this means it wont be blocking PRs
	 until you're confident it is stable enough to block PRs.
1. Keep reproducibility at mind. All the tests receive a PRNG to be used to do
	 any sort of random operation, please use it as much as reasonably possible.
1. Refrain from `println!` and use the logging primitives and `ctx.logger`
	 instead.
1. Do not make too many environment assumptions: `fondue` enables us to easily
	 re-use a setup, providing a simple way to decrease runtime of our tests. In
	 fact, `fondue` divides tests in two categories: (A) isolated tests and (B)
	 composable tests. Isolated tests have full freedom to change their
	 environment by starting, stopping and restarting nodes.  Composable tests,
	 on the other hand, can only _read_ from their environment. Hence, if you
	 write your test as a composable test, chances are we can group it with some
	 other composable tests and share the same IC instance to run them.
1. Go ahead and write a test that we can run!


### A note on the CLI

The System Tests are defined in `rs/tests/bin/prod-test-driver.rs`. The API of the tests themselves remains unchanged.

For example, to run all the `pre-master` System Tests use:

```bash
./run-system-tests.py --suite pre_master --log-base-dir $(date +"%Y%m%d") 2>&1 | tee farm.log
```

Note: This requires the commit to be built by CI/CD, i.e. it must be pushed to the remote and an MR has to be created. If the script can't find artifacts for the current commit, it will fail.

Below is the usage of the "legacy" System Tests.

To run all tests, but still log debug-level messages to `my-log` we run:

```
$ ./setup-and-cargo-test.sh -- -v --log-to-file my-log
```

The `--` separates the arguments to `setup-and-cargo-test.sh` from the arguments
consumed by `rs/tests/src/main.rs`. In general,

```
$ ./setup-and-cargo-test.sh [SCRIPT-OPTIONS] [-- SYSTEM-TEST-OPTIONS]
```

If you wish to see more info on which options are supported, run:

```
$ ./setup-and-cargo-test.sh -- --help
```

### Pots and Tests

In `fondue`, tests are organized in _pots_ of two different kinds:

- *Composable* pots consist of multiple individual tests that run against the
	same environment configuration. This means we pay the price of setting up a
	bunch of nodes only once. The disadvantage is that these tests receive a
	read-only `IcHandle` object, which does not enable the test author to change
	its environment (i.e., start new replicas, stop replicas, etc). Note that
	altering the state of the nodes is allowed — think of installing a canister,
	for instance.  You can think of an `IcHandle` as a vector of HTTP endpoints.

- *Isolated* pots consists in a _single_ test that runs against a given
	environment. This single test, however, receives a `IcManager` instead of a
	`IcManager::handle()`; hence, it is allowed to perform arbitrary changes in
	its environment.

### Filtering

Often, we might want to run just one specific test, or we might
want to skip certain tests. We can do so by passing a filter
as the last argument to `system-tests` or as an argument to `--skip`.

To run all tests that contain the string "basic" in their name we run:

```
$ ./setup-and-cargo-test.sh -- basic
```

This will run `basic_health_test` and `canister_lifecycle_basic_test`.
Now, say that we do not want to run the steps that have `delete` in their
names:

```
$ ./setup-and-cargo-test.sh -- --skip delete basic
```

### Known Issues

#### Darwin Support is 'Best Effort'

It might happen that tests break on Darwin because, on CI, they are not tested
on Darwin.

This is a compromise. As many developers use Darwin, we can save overhead by
running the tests directly on Darwin for local testing. Hence, they _should_
run on Darwin. On the other hand, supporting both Linux _and_ Darwin on CI is
costly.

#### NNS Canister Installation Timeouts when testing locally

Using the `NNSInstaller`-trait, it is possible to install all NNS-canisters on
the root subnet using functionality by the `nns/test_utils`-crate. The NNS
canisters are compiled before installation. If your local cargo cache is
outdated ( e.g., after an explicit cache invalidation or pulling updates),
canister compilation can take on the order of 10 minutes. As a result, a test
might hit a global timeout configured in the test runner
(`rs/tests/src/main.rs`). *It is suggested to adjust such timeouts to mitigate
this issue.*

On CI, the issue is mitigated as the canisters are built in a separate stage. 
