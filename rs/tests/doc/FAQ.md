
<!--
This doc uses collapsible sections. This is a very delicate piece of markdown
and full of nuances. Make sure that you always have an empty line after
the closing of "summary" and "details".
-->

# System Tests Frequently Asked Questions

<details>
  <summary><strong>Some test is failing on my (seemingly) unrelated PR!</strong></summary>

  Due to the side-effectful nature of most of our components, sometimes a PR might seem unrelated but
  it actually is related. Most of the times, this will be because (A) you changed a log message or (B) you
  refactored a log message.

  - (A) If you changed log messages, try reverting them back and see if the test starts passing again.
  - (B) If you refactored some code and this code used to emit `DEBG`-level log messages, make sure
  that if the module where the log messages were emmitted before your change was listed in
	`/rs/ic_fondue/src/ic_manager/inner.rs`,
  then the module where you refactored the messages to should also be listed there.

  The testing framework (`ic_fondue`) relies on the generated rust protobuf/serde instances for
  parsing `LogEntry`-y+ies. This means that the situation (A) above is less likely to happen,
  but its worth noting anyway.

  When system-tests are run on CI, we compile the replica in `release` mode. This means that
  `DEBG`-level (and below!) log messages are erased unless they come from a module specified 
  in the `debug_overrides` field (`/rs/ic_fondue/src/ic_manager/inner.rs#L435`)
  from the `LoggerConfig`. Hence, refactoring a function from a module that is listed
  in the `debug_override` will cause the log messages to not be displayed and hence, can cause
  the tests that expect a certain log message to fail.
</details>

<details>
  <summary><strong>Can the testing framework do X?</strong></summary>

  The testing framework is a capable piece of software. There's a chance it can already do X. Please make sure to check
  the `--help` screen. If you're running from `./setup-and-cargo-test.sh`, use `./setup-and-cargo-test.sh -- --help`,
  otherwise you'll see the help screen for the setup script itself.

  If the feature you need is still not there, send the testing team a feature request! We'll be happy
  to implement it or discuss with you what/how to implement. We gladly accept PRs on all of our libraries
  and it helps a great bunch! :)
</details>

<details>
  <summary><strong>Do I really need <tt>./setup-and-cargo-test.sh</tt>?</strong></summary>

  No, but its highly advisable you use it. Running the system tests requires that the necessary binaries
  can be found on `$PATH`.
</details>

<details>
  <summary><strong>How does CI run these tests?</strong></summary>

  TL;DR: CI runs the `system-tests` binary directly, it does the necessary configuration explicitely.

  The CI aspect of system testing is owned by IDX. Still, if you want to see the gory details, check the relevant config files.
  As of Mar 22, 2021, [these are the relevant config files](../../../gitlab-ci/config/40--cargo-test--child-pipeline.yml), but
  they might be moved in the future.
</details>

<details>
  <summary><strong>The <tt>[insert_test_name_here]</tt> test is failing, what do I do?</strong></summary>

  Check the [TROUBLESHOOTING](TROUBLESHOOTING.md) document for a list of steps and self-checks
  you can perform yourself. If you still can't get the test to work or can't figure out why it is failing,
  please ask for help on slack (#eng-testing).
</details>

<details>
  <summary><strong>Where do I start if I want to write a test?</strong></summary>

  Check the [README](../README.md) and/or the [basic_health_test](../src/basic_health_test.rs).
</details>

<details>
  <summary><strong>I see <tt>Assessment: FAIL</tt> but it the tool reports <tt>0 failed</tt> What's wrong?</strong></summary>

  The system tests success condition is a little more involved than "the test produced the right result", in fact,
  it is: "the test produced the right result AND the health of the network was not compromised in the meanwhile".
  Hence, you should also not see the string `(there were soft failures)`, this means that some health check failed.
  The best way to find which health check failed is to search for "Failure" on the output.
</details>

