# Testing Infrastructure: `rs/tests`

Note: For an overview over the testing terminology, please visit [this
notion-page](https://www.notion.so/Testing-Terminology-8cc0735dfcd945959f8d47caedf058b5).

**Note**: If you want to add a system test, please jump right to the section
about [bazelified system tests](How-can-I-run-system-tests-in-Bazel?).

## System tests

System tests can involve all components in combination in the form of a
functioning IC. The test API is implemented in Rust.

The system test driver allows for the execution of arbitrary setup and test
functions written in Rust. However, the accompanying APIs are geared towards
instantiating and managing virtual machines on a backend service called
[Farm](https://github.com/dfinity-lab/infra/tree/master/farm/). Farm actively
manages all allocated resources; e.g., all virtual machines allocated
by the test driver are collected after the test driver finishes. When deploying
an Internet Computer instance, every node is instantiated as a virtual machine
running the
[ic-os](https://sourcegraph.com/github.com/dfinity/ic/-/tree/ic-os/guestos).

### How can I write system tests in Bazel?
T&V team is working actively on the
[bazelification](https://docs.google.com/document/d/1RGyvOkRluFsqroDmyM9hfr37VG-nCrTOrutQnStJsco/edit#heading=h.fcajjuvgc2dn)
of all system tests. When you want to write a new test or when you own system
tests declared in `rs/tests/bin/prod_test_driver.rs`, take a look at the linked
document.

### How can I run system tests in Bazel?
In order to run system tests, enter the build docker container:
```
/ic$ ./gitlab-ci/container/container-run.sh
```
To launch a test target (`my_test_target` in this case) within the docker run:
```
devenv-container$ bazel test --config=systest //rs/tests:my_test_target
```

In the docker container, you can also use `ict` to start tests.

```
ict test //rs/tests:my_test_target
```

At some point in the future, ict should be the only thing a user needs to know.
I.e., she can explore all options by interacting with ict and there is no need
for a README here no more. ;-)

# How to write a system test

Before progressing, it is worth understanding how system tests work
conceptually and what makes them different from unit tests.

System tests are a form of end-to-end tests. Currently, they integrate all
layers of the Internet Computer software stack with the exception of the Host
OS. E.g., it is not possible at the moment to test host os upgrades.

Technically, the testing infrastructure can be used to deploy any kind of
virtual machine (e.g. auxiliary services like rosetta node), provided the images
are available in the correct format. Typically, however, a setup function of a
pot is used to instantiate one Internet Computer instance and possibly some
auxiliary virtual machines.

When instantiating an IC, the IC is «bootstrapped». For all intends and
purposes, this is the same procedure as was used when mainnet was launched:
`ic-prep` is used to generate the initial registry reflecting the initial
topology of the network.

## Test Environment

A *test environment* is essentially a directory structure that contains
information about the environment in which the test is executed. For example, it
contains infrastructure configuration, such as the URL where Farm is located.
Or, when a Internet Computer is deployed in the setup of a pot, the
corresponding topology data is stored in the test env—which can then be picked
up by the tests.

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
corresponding pot setup; that is, the directory is copied as is. Thus, every
test *inherits* the environment of the pot's setup, but no two tests share the
same test environment.

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
use the test API. **Note**: As every test environment is a copy of another test
environment with the exception of the system environment, a test environment
includes all the logs of the parent environment. As a consequence, a test
environment contains all the logs of the system environment, up to the point
where the test environment was created.

## Guiding principles when writing tests

When writing your test, please keep in mind a few important things:

* Make sure to add a ASCIIDOC description to the beginning of your file, just
like `basic_health_test`.
* Keep reproducibility in mind. For example, if you use a RNG in the test, make
  sure the seed is fixed (or at least logged).
* Refrain from `println!` and use the logging primitives of the test environment instead.
* In general, do not make too many environment assumptions. For example, never access
  the file system directory or only through information available through the test environment.
* Put your test in a suitable folder in the src directory or create a new
  sub-directory. Don't forget to modify CODEOWNERS accordingly.

### A note on the CLI

The system tests are defined in `rs/tests/bin/prod-test-driver.rs`. The API of the tests themselves remains unchanged.

For example, to run all the `pre-master` system tests use:

```bash
./run-system-tests.py --suite pre_master 2>&1 | tee system-test-logs.log
```

Note: This requires the commit to be built by CI/CD, i.e. it must be pushed to the remote and an MR has to be created. If the script can't find artifacts for the current commit, it will fail.


### My test is failing/flaky, what do I do?

Please, check the [FAQ](doc/FAQ.md) or [TROUBLESHOOTING](doc/TROUBLESHOOTING.md) before submitting
a bug report.

### Running the tests
Go to the end of the page for info on the CLI arguments.
If you are running the script within nix-shell on Linux and run out of disk space, `export TMPDIR=` might solve this issue for you.
In particular, the `nix-shell` command run in Ubuntu 20.04 sets the `TMPDIR` variable to `/run/user/1000`, which might correspond to a disk partition that is be too small for storing all the artifacts produced by the tests. To mitigate the problem, one could run, e.g., `export TMPDIR=/tmp`.

### Running Docker Containers in system-tests

Docker containers can be run in Universal VMs. Search for calls of "UniversalVm::new" to see examples on how to set that up.

Note that Universal VMs are created afresh for each pot. This means that if it runs a docker container the container's image needs to be fetched from the registry each time.

### Known Issues
