# I found a bug!

Amazing! Thank you!

When reporting the bug, please make sure you go through a quick checklist and use the template below to help
us debug it with you. The test framework itself is relatively well-tested and there is a higher probability
that the bug you found results from some not well-known replica config interaction than the test framework per se.
Therefore, please trust the failure to be a real failure at first and collect the necessary information for
us to look into it.

# Before Submitting a Report

## I'm running the test locally

1. Are you on the latest `master`?
1. Are you running through `./setup-and-cargo-test.sh`? In particular, are you sure the latest replica is being used?

## The test failed on CI

1. It can be that the `--ready-timeout` was reached. Search in the logs for "Manager did not successfully start".
If you find the mentioned string, try restarting the job. Unfortunately,
the non-deterministic nature of these tests and the amount of resources available on CI means that some degree of
flakiness is bound to happen. If it fails repeatedly on that message, let us know!
1. Did you look for soft failures? Just search the log for "Failure" to easily do so.
1. Can you reproduce the failure locally?

# When Submitting a Report

Please use the following template:

```
    <Small description of the failure/test/relevant info>

    What I'm seeing: <seen result>

    What I expected: <expected result>

    Which command I ran: <exact command you used>

    I'm at commit: <the commit you ran the command at>
```
