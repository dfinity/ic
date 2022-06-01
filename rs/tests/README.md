# Testing Infrastructure: `rs/tests`

Note: For an overview over the testing terminology, please visit [this
notion-page](https://www.notion.so/Testing-Terminology-8cc0735dfcd945959f8d47caedf058b5).

## System tests

System Tests (declared in `rs/tests/bin/prod_test_driver.rs`) can involve all
components in combination in the form of a functioning IC. The test API is
implemented in Rust.

In System Tests, the smallest unit under test is a virtual machine. In
particular, when deploying an Internet Computer instance, every node is
instantiated as a virtual machine running the
[ic-os](https://sourcegraph.com/github.com/dfinity/ic/-/tree/ic-os/guestos). The
test driver allocates virtual machines using a backend service called
[Farm](https://github.com/dfinity-lab/infra/tree/master/farm/). Farm actively
manages all allocated resources. In particular, all virtual machines allocated
by the test driver are collected after a maximum time-to-live.

System Tests are organized in a hierarchy: every test belongs to a _pot_. A pot
declares the test system (Internet Computer under test). Multiple tests can run
using the same test instance (of a pot) either in parallel or in sequence. Pots
in turn are grouped into _test suites_.

```
Suite0
 |
 | -- Pot0
 |     |
 |     | -- Test0
 |     | -- Test1
 |
 | -- Pot1
 |     | -- Test0
 ...
```

### How can I run system tests?

First, make sure you're in the `nix-shell` started from `ic/rs`.

When running system tests, the base ic-os version has to be set manually.
Currently, only disk images built by CI/CD can be used. Thus, you first need to
find out the `IC_VERSION_ID` that belongs to the image that you want to use.
Note that alongside the image itself, also all other build artifacts that belong
to that version are downloaded from CI/CD (NNS canisters, auxiliary binaries,
etc.). When run locally, only the test driver (including tests) is re-compiled
and includes local changes.

When running tests locally, it is possible, however, to provide all the test
artifacts and build dependencies (with the exception of disk images) in a folder
by specifying a corresponding directory in the `ARTIFACT_DIR` environment
variable.

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

# How to write a System Test

Before progressing, it is worth understanding how system tests work
conceptually and what makes them different from unit tests.

System tests are a form of end-to-end tests. Currently, they integrate all
layers of the Internet Computer software stack with the exception of the Host
OS. E.g., it is not possible at the moment to test host os upgrades.

Technically, the testing infrastructure can be used to deploy any kind of
virtual machine (e.g. auxiliary services like rosetta node), provided the images
are available in the correct format. However, typically, a setup procedure of a
pot instantiates one Internet Computer instance and possibly some auxiliary
virtual machines.

When instantiating an IC, the IC is «bootstrapped». For all intends and
purposes, this is the same procedure as was used when mainnet was launched:
`ic-prep` is used to generate the initial registry reflecting the initial
topology of the network.

## Test Environment

A *test environment* is essentially a directory structure that contains
information about the environment in which the test is executed. For example, it
contains infrastructure configuration, such as the URL of Farm is located. Or,
when a Internet Computer is deployed in the setup of a pot, the corresponding
topology data is stored in the test env—which can then be picked up by the
tests.

From the point of view of the test driver, both a test and a setup function are
just procedures that operate on the test environment. They both have the
same signature:

```rust
fn setup(test_env: TestEnv) { /* ... */ }
fn test(test_env: TestEnv) { /* ... */ }
```

For example, when an Internet Computer is instantiated, information about the
internet computer is stored in the test environment which can then be picked up
in the test:

```rust
fn setup(test_env: TestEnv) {
	InternetComputer::new()
	    .with_subnet(/* ... */)
		.setup_and_start(&test_env); // (1)
}

fn test(test_env: TestEnv) {
	use crate::test_env_api::*;
	let root_subnet = test_env
		.topology_snapshot()         // (2)
		.root_subnet();              // (3)
}
```

The module
[`test_env_api`](https://sourcegraph.com/github.com/dfinity/ic/-/blob/rs/tests/src/driver/test_env_api.rs)
contains traits and functions to access the information contained in the test
environment in a structured way. For example,
the above call (1), initializes the IC and stores the initial registry (and
further config data) under `<test_env>/ic_prep`. 

The call in (2), in turn, reads this information to construct a data structure
that reflects the initial topology. So, e.g., the call (3) returns a data
structure that represents to root_subnet.

For more information about the test environment API, check out the module
`test_env_api.rs` and its module documentation!

## Working Directory

As stated in the previous section, any test works within a test environment.
Before a test starts, the test driver «forks» the test environment of the
corresponding pot setup; that just means, the directory is copied as is. Thus,
every test *inherits* the environment of the pot's setup, but no two tests share
the same test environment.

All tests environment are placed in the working directory of the test driver
(see CLI options for more information). The working directory's structure
follows the hierarchical structure of the tests. For example:

```
── working_dir
   └── 20220428_224049         <<== timestamp of test run
       ├── api_test            <<== POT name
       │   ├── setup           <<== data related to the setup of this pot
       │   │   ├── ic_prep
       │   │   │   ├── blessed_replica_versions.pb
       │   │   │   <... etc. etc. ...>
       │   │   └── test.log    <<== logs produced during the setup
       │   └── tests
       │       ├── ics_have_correct_subnet_count  <<== test name
       │       │   <... more files ...>
       │       │   ├── test.log                   <<== test (driver) log
       │       |   ├── test_execution_result.json <<== test result
	   <... etc. ...>
       ├── system_env           <<== global system env that all pots inherit
       │   ├──suite_execution_contract.json
<... etc. ...>
```


## Example Test

The `basic_health_test` is an example test that should act as guidance on how to
use the test API.

## Guiding principles when writing tests

When writing your test, please keep in mind a few important things:

* Make sure to add a ASCIIDOC description to the beginning of your file, just
like `basic_health_test`.
* Keep reproducibility in mind. For example, if you use a RNG in the test, make sure the seed is fixed (or at least logged).
* Refrain from `println!` and use the logging primitives of the test environment instead.
* In general, do not make too many environment assumptions. For example, never access the file system directory or only through information available through the test environment.
* Put your test in a suitable folder in the src directory or create a new
sub-directory. Don't forget to modify CODEOWNERS accordingly.

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


## Legacy System Tests

The `rs/tests` crate also hosts the so-called _legacy system tests_ declared in
`rs/tests/src/main.rs`. The tests use largely the same API, however, the nodes
for legacy system tests are instantiated as _processes_ (rather than virtual machines).
These processes all share the resources of a single OS that launched the legacy system tests.
Conversely, we encourage you to use the new system tests framework based on the Farm service that offers on-demand resource allocation and load balancing across a pool of remote servers.

**Note**: Legacy system tests are **not** supported on Darwin!
### My test is failing/flaky, what do I do?

Please, check the [FAQ](doc/FAQ.md) or [TROUBLESHOOTING](doc/TROUBLESHOOTING.md) before submitting
a bug report.

### Running the tests
Legacy system tests can be launched via the `setup-and-cargo-test.sh` script. Go to the end of the page for info on the CLI arguments.
If you are running the script within nix-shell on Linux and run out of disk space, `export TMPDIR=` might solve this issue for you.
In particular, the `nix-shell` command run in Ubuntu 20.04 sets the `TMPDIR` variable to `/run/user/1000`, which might correspond to a disk partition that is be too small for storing all the artifacts produced by the tests. To mitigate the problem, one could run, e.g., `export TMPDIR=/tmp`.


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
