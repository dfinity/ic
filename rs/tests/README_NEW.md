## Content
- [What is a system test of the Internet Computer](#what-is-a-system-test-of-the-internet-computer)
- [How can I run a system Test manually](#how-can-i-run-a-system-test-manually)
  - [Running a bazelified flavour of a system test](#running-a-bazelified-flavour-of-a-system-test)
    - [Via native Bazel commands](#via-native-bazel-commands)
    - [Via `ict` command line tool](#via-ict-command-line-tool)
  - [Running a cargo-based (legacy) flavour of a system test](#running-a-cargo-based-legacy-flavour-of-a-system-test)
- [Where do I get test logs and logs of the IC nodes?](#where-do-i-get-test-logs-and-logs-of-the-ic-nodes)
  - [For manual test executions](#for-manual-test-executions)
  - [For CI/CD test executions](#for-cicd-test-executions)

# What is a system test of the Internet Computer
A system test is a test, which is conducted on a complete instance of the [Internet Computer](https://internetcomputer.org/how-it-works) (IC). IC under test may be comprised of multiple System- and/or Application-subnets. The subnet is formed by a collection of nodes, which replicate each others state and realize a four-layered architecture of the [Internet Computer Protocol](https://internetcomputer.org/how-it-works) (ICP). System-subnet is primarily aimed at hosting [NNS canisters](https://wiki.internetcomputer.org/wiki/NNS_Canisters), but can also host any other canisters, such as [Bitcoin](https://github.com/dfinity/bitcoin-canister) canister or [Internet Identity](https://github.com/dfinity/internet-identity) canister. The objective of the Application-subnets is to host users canisters, which can range from simple [counter](https://github.com/dfinity/examples/tree/master/wasm/counter) canisters to arbitrary complex ones. 

An IC system test might include other components, such as unassigned nodes, boundary nodes, or nodes with some customized behavior. Customized nodes can, e.g., implement [workloads](https://github.com/dfinity/ic/blob/master/rs/tests/src/workload.rs), which dispatch query/update calls to canisters at desired rates.

System tests are primarily aimed at realizing *functional testing* of the system requirements. These functional requirements (behaviors) are expressed in the forms of assertions in the test function. Non-functional testing, for example, performance testing can also be realized as a system test. This, however, should be done with a great deal of caution, as such tests are especially prone to flakiness in the distributed systems.

**[TODO]: add a picture with the main components: test driver, system test, Farm**
# How can I run a system Test manually
In the current (transitional) period, system tests can co-exist in two flavours: *bazelified* and *cargo-based*. Eventually, only *bazelified* flavour will remain. A system test is considered to be *bazelified*, if there is a Bazel [rule](https://bazel.build/extending/rules) for the Rust source code of the test. This rule should be defined in the [BUILD.bazel](https://github.com/dfinity/ic/blob/master/rs/tests/BUILD.bazel). Alternatively, a system test is considered to be *cargo-based*, if it is defined in one of the test suites of the [prod_test_driver.rs](https://github.com/dfinity/ic/blob/master/rs/tests/bin/prod_test_driver.rs) file. As mentioned above, presently a system test can co-exist in both flavours simultaneously. Provided that test timeout is not hit, execution result of both flavours should of course be identical. However, test invocation procedure is rather different.
## Running a bazelified flavour of a system test
[basic_health_test.rs](https://github.com/dfinity/ic/blob/master/rs/tests/bin/basic_health_test.rs) can serve as an example of a bazelified system test. Bazel [rule](https://bazel.build/extending/rules) needed for building the test target binary from the underlying Rust source code is defined in the [BUILD.bazel](https://github.com/dfinity/ic/blob/master/rs/tests/BUILD.bazel) file. In order to run this test with [Bazel](https://bazel.build/), first enter the docker container:
```
/ic$ ./ci/container/container-run.sh
```
this container provides all the necessary environment setup for building and running Bazel targets.
### Via native Bazel commands
Within the docker execute:
```
devenv-container$ bazel test --config=systest //rs/tests/testing_verification:basic_health_test
```
You can provide additional [flags](https://bazel.build/reference/command-line-reference#test) to the Bazel [test](https://bazel.build/reference/command-line-reference#test) command. For example, *--test_tmpdir* would be useful, if you want to keep test artifacts (logs, ssh keys, etc.) after the test execution has finished.
### Via `ict` command line tool
Within the same docker container there is also an [ict](https://github.com/dfinity/ic/tree/master/rs/tests/ict) CLI at your disposal. This tool simplifies your interaction with bazelified system tests and abstracts away the underlying Bazel machinery. In order to run the same `basic_health_test` with the `ict` execute:
```
devenv-container$ ict test //rs/tests/testing_verification:basic_health_test
```
Upon this invocation `ict` launches the test and also displays the raw Bazel command, which is called under the hood:
```
Raw Bazel command to be invoked: 
$ bazel test //rs/tests/testing_verification:basic_health_test --config=systest --cache_test_results=no
```
You can explore the functionality of the continuously developed `ict` tool by:
```
devenv-container$ ict -h
```
For example, you can list all existing system test targets via:
```
devenv-container$ ict test list
The following 60 system_test targets were found:
//rs/tests/consensus:backup_manager_test
//rs/tests/testing_verification:basic_health_test
...
```
Had you misspelled the test target name, `ict` will help you with a fuzzy match proposal:
```
devenv-container$ ict test almost_basic_test
There was an error while executing CLI: 'No test target `almost_basic_test` was found: 
Did you mean any of:
//rs/tests/testing_verification:basic_health_test
//rs/tests/financial_integrations/ckbtc:ckbtc_minter_basics_test
...
```
## Running a cargo-based (legacy) flavour of a system test
*Cargo-based* system tests are defined in the test suites of the [prod_test_driver.rs](https://github.com/dfinity/ic/blob/master/rs/tests/bin/prod_test_driver.rs).
In order to launch `basic_health_test`, firstly enter the `nix-shell` environment:
```
~/ic/rs$ nix-shell
```
Secondly, specify GuestOS image (replica) version. For example, take the latest available one:
```
[nix-shell:~/ic]$ export IC_VERSION_ID=$(./ci/src/artifacts/newest_sha_with_disk_image.sh master)
```
Finally, execute `basic_health_test` (which resides in the `hourly` suite) via python [run-system-tests.py](https://github.com/dfinity/ic/blob/master/rs/tests/run-system-tests.py) script:
```
[nix-shell:~/ic]$ ./rs/tests/run-system-tests.py --suite=hourly --include-pattern=basic_health_test
```
If you omit *--include-pattern*, the whole `hourly` test suite will be executed.

**Important**: GuestOs image specified by the IC_VERSION_ID should be available in http://download.proxy-global.dfinity.network:8080/ic/IC_VERSION_ID/guest-os/disk-img-dev/disk-img.tar.zst. Otherwise, Farm will fail to setup the IC nodes and the test will fail in the setup phase.
# Where do I get test logs and logs of the IC nodes?
During/after test execution one may naturally be interested in looking at the test logs and logs produced by the IC nodes.
## For manual test executions
Console displays only test logs, i.e., everything that is sent to the stdout/stderr from the Rust source code of the test itself. Logs of the IC nodes are pushed to the Elastic Search and can be retrieved by following the Kibana link, which is printed in the console output in the form:
```
See replica logs in Kibana: https://kibana.testnet.dfinity.network/...
```
During test execution one can also login to VMs directly via browser links. Test stdout prints these console links in the form:
```
Timestamp INFO[...] Console: https://farm.dfinity.systems/group/group_name/vm/vm_id/console/
```
By clicking the links and logging via:
```
nixos login: root
password: root
```
one can execute any terminal command, e.g., `journalctl -flu ic-replica` to read the replica logs.

Logs of the test itself are displayed in the stdout in the mixed form of the unstructured and semi-structured logs. Log messages originating from the test are decorated with a timestamp and file path with a line number. For example, when [running](#via-ict-command-line-tool) a `basic_health_test` one can see this message:
```
Jan 27 16:33:01.539 INFO[rs/tests/src/basic_health_test.rs:149:0] Assert that message has been stored ...
```
In addition to the test logs, one can also observe logs produced by the [test driver](https://github.com/dfinity/ic/tree/master/rs/tests/src/driver):

```
Jan 27 16:33:02.538 INFO[rs/tests/src/driver/new/subprocess_task.rs:88:17] Task 'test' finished with exit code: Ok(ExitStatus(unix_wait_status(0)))
...
Jan 29 19:43:20.056 INFO[rs/tests/src/driver/new/group.rs:840:0] Executing sub-process-specific code ...
...
Jan 29 19:44:29.384 DEBG[rs/tests/src/driver/new/group.rs:787:29] All events completed. Sending the report ...
```
Test execution is summarized in the stdout with a message:
```
========= Summary ==========
Test setup  PASSED in  55.97s
Test test  PASSED in  69.34s
... All 2 tests passed! ....
============================
```
One can also access all the test logs by following the Bazel dashboard link, which is printed at the end of the output:
```
INFO: Streaming build results to: https://dash.hostname.dfinity.network/invocation/id
```
## For CI/CD test executions
CI jobs, which execute Bazel system tests should print links to the Bazel dashboard in the form:
```
INFO: Streaming build results to: https://dash.hostname.dfinity.network/invocation/id
```
By following this link one can find logs of the individual system tests of interest.
See the previous [section](#for-manual-test-executions) on how to interpret these logs.
