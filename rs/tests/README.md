# My test is failing/flaky, what do I do?

Please, check the [FAQ](doc/FAQ.md) or [TROUBLESHOOTING](doc/TROUBLESHOOTING.md) before submitting
a bug report

# Testing Infrastructure: `rs/tests`

## Running the tests
To run the tests locally, run the `setup-and-cargo-test.sh` script. Go to the end of the page for info on the CLI arguments.
If you are running the script within nix-shell on Linux and run out of disk space, `export TMPDIR=` might solve this issue for you.
On Ubuntu 20.04, nix-shell sets the initially unset TMPDIR to /run/user/1000, which might be too small for the tests. Unsetting this variable enables the tests to use /tmp instead.

## High Level Overview

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

## So You Want to Write a Test?

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


## A note on the CLI

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

## Pots and Tests

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

## Filtering

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

## Known Issues

### Darwin Support is 'Best Effort'

It might happen that tests break on Darwin because, on CI, they are not tested
on Darwin.

This is a compromise. As many developers use Darwin, we can save overhead by
running the tests directly on Darwin for local testing. Hence, they _should_
run on Darwin. On the other hand, supporting both Linux _and_ Darwin on CI is
costly.

### NNS Canister Installation Timeouts when testing locally

Using the `NNSInstaller`-trait, it is possible to install all NNS-canisters on
the root subnet using functionality by the `nns/test_utils`-crate. The NNS
canisters are compiled before installation. If your local cargo cache is
outdated ( e.g., after an explicit cache invalidation or pulling updates),
canister compilation can take on the order of 10 minutes. As a result, a test
might hit a global timeout configured in the test runner
(`rs/tests/src/main.rs`). *It is suggested to adjust such timeouts to mitigate
this issue.*

On CI, the issue is mitigated as the canisters are built in a separate stage. 
