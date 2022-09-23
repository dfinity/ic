#!/usr/bin/env python3
#
# We build the sets of tests ~ tuples (package_name, test_name)
# from sanitized input files:
# * "cargo tests" from cargo-nextests.out
# * "cargo doc tests" from cargo-doc-tests.out
# * "bazel tests" from bazel.tests
# * "bazel doc tests" from bazel.doc-tests
#
# By that, we are able to see which tests are present in both "realms"
# and which ones are not.
#
# We also take into account if we have duplicate pairs,
# which means we have same test name in various targets of the same package.
# That needs to match (unless it's ignored) in cargo and bazel "realm".
# We don't do that for doc tests due to very low probability of having
# two doc tests with same name in the same line in two separate files
# with the same name.
__all__ = [
    "load_ignored_test_set",
    "load_cargo_test_set",
    "load_bazel_test_set",
    "get_unpair_tests",
    "get_unpair_doctests",
]

import sys

import toml

# ignore duplicate count in the following packages:
# * ic-sns-cli: some tests are executed in binary as well as in library
DUPLICATE_IGNORE_SET = set(["ic-sns-cli"])


def load_ignored_test_set(toleration_tests_file):
    ignored_tests = set()

    with open(toleration_tests_file, "r") as f:
        package_name, test_name = None, None
        for line in f:
            # ^ic-crypto, should_correctly_parse_der_encoded_iccsa_pubkey
            data = line.split(",")
            package_name, test_name = data[0].strip(), data[1].strip()
            ignored_tests.add((package_name, test_name))

    return ignored_tests


def load_cargo_test_set(cargo_tests_file, doctests=False):
    tests = set()
    dup_tests = dict()

    with open(cargo_tests_file) as f:
        package_name, test_name = None, None
        for line in f:
            if doctests:
                # # Note: dfn_core is a target name.
                # # Most of the time that equals to package name.
                # ^   Doc-tests dfn_core
                # ^src/endpoint.rs - endpoint::over (line 10)
                # ...
                if "Doc-tests" in line:
                    package_name = line[13:].strip()
                elif " (line " in line:
                    doc_test = line.strip()
                    tests.add((package_name, doc_test))
            else:
                # ^ic-crypto::canister_signatures:
                # ^    should_correctly_parse_der_encoded_iccsa_pubkey
                # ...
                if not line.startswith(" "):
                    idx_end = line.find(":")
                    package_name = line[:idx_end]
                else:
                    test_name = line.strip()
                    test = (package_name, test_name)
                    if test in tests:
                        dup_tests[test] = dup_tests.get(test, 1) + 1
                    tests.add(test)

    return tests, dup_tests


def load_bazel_test_set(bazel_tests_file, doctests=False):
    tests = set()
    dup_tests = dict()

    with open(bazel_tests_file) as f:
        package_name, test_name = None, None
        for line in f:
            if line.startswith("="):
                # ^==================== Test output for //rs/rust_canisters/ecdsa:ecdsa_test
                idx_start, idx_end = line.find("rs"), line.find(":")
                dirname = line[idx_start:idx_end]
                toml_dict = toml.load(f"../{dirname}/Cargo.toml")
                package_name = toml_dict["package"]["name"]
            elif not doctests or (doctests and " (line " in line):
                # #Test:
                # ^should_correctly_parse_der_encoded_iccsa_pubkey
                # #Doctest:
                # ^src/endpoint.rs - endpoint::over (line 10)
                test_name = line.strip()
                test = (package_name, test_name)
                if test in tests:
                    dup_tests[test] = dup_tests.get(test, 1) + 1
                tests.add(test)

    return tests, dup_tests


def get_unpair_tests(cargo_tests, cargo_dup_tests, bazel_tests, bazel_dup_tests):
    only_cargo_tests = cargo_tests - bazel_tests
    only_bazel_tests = bazel_tests - cargo_tests
    cargo_test_match = dict()
    bazel_test_match = dict()

    print("\nFiltering out tests that seem to match")
    for cargo_test in only_cargo_tests:
        c_package_name, c_test_name = cargo_test
        for bazel_test in only_bazel_tests:
            b_package_name, b_test_name = bazel_test
            # Cargo: ('ic-sns-integration-tests', 'proposals::test_vote_on_non_existent_proposal')
            # Bazel: ('ic-sns-integration-tests', 'test_vote_on_non_existent_proposal')
            if c_package_name == b_package_name:
                if c_test_name in b_test_name or b_test_name in c_test_name:
                    print("-" * 130)
                    print(f"* Cargo: {cargo_test}")
                    print(f"* Bazel: {bazel_test}")
                    cargo_test_match[cargo_test] = bazel_test
                    bazel_test_match[bazel_test] = cargo_test

    only_cargo_tests.difference_update(set(cargo_test_match.keys()))
    only_bazel_tests.difference_update(set(bazel_test_match.keys()))

    # check that duplicate number match
    test_parity = cargo_tests - only_cargo_tests
    for cargo_test in test_parity:
        package_name, _ = cargo_test
        if package_name in DUPLICATE_IGNORE_SET:
            continue
        if cargo_test in cargo_dup_tests:
            bazel_test = cargo_test if cargo_test in bazel_tests else cargo_test_match[cargo_test]
            if cargo_dup_tests[cargo_test] != bazel_dup_tests.get(bazel_test, -1):
                print(f"Test duplicate count mismatch for {cargo_test}")
                print("    ", cargo_dup_tests[cargo_test], bazel_dup_tests.get(bazel_test, -1))
                only_cargo_tests.add(cargo_test)

    return only_cargo_tests, only_bazel_tests


def get_unpair_doctests(cargo_doctests, bazel_doctests):
    cargo_catch_set = set()
    bazel_catch_set = set()

    print("\nFiltering out doc tests that seem to match")
    for cargo_test in cargo_doctests:
        c_package_name, c_doctest = cargo_test
        for bazel_test in bazel_doctests:
            b_package_name, b_doctest = bazel_test
            if c_package_name == b_package_name:
                # Bazel test contains full path
                # Cargo: "src/bitmask.rs - bitmask::BitMask (line 12)"
                # Bazel: "rs/phantom_newtype/src/bitmask.rs - bitmask::BitMask (line 12)"
                if c_doctest in b_doctest:
                    print("-" * 130)
                    print(f"* Cargo: {cargo_test}")
                    print(f"* Bazel: {bazel_test}")
                    cargo_catch_set.add(cargo_test)
                    bazel_catch_set.add(bazel_test)
            elif c_doctest in b_doctest:
                # `cargo test --doc -- --list` gives us (target, test) while `bazel test` gives us (package, test)
                # Most of the times this equals but we need to handle the case where it doesn't:
                # ! Cargo: ('ic_image_upgrader', 'src/image_upgrader.rs - ImageUpgrader (line 30)')
                # ! Bazel: ('ic-image-upgrader', 'rs/orchestrator/image_upgrader/src/image_upgrader.rs - ImageUpgrader (line 30)')
                print("-" * 130)
                print(f"! Cargo: {cargo_test}")
                print(f"! Bazel: {bazel_test}")
                cargo_catch_set.add(cargo_test)
                bazel_catch_set.add(bazel_test)

    only_cargo_doctests = cargo_doctests - cargo_catch_set
    only_bazel_doctests = bazel_doctests - bazel_catch_set

    return only_cargo_doctests, only_bazel_doctests


def write_tests_to_file(lst, filename):
    with open(filename, "w") as f:
        for package, test in lst:
            f.write(f"{package}, {test}\n")


def print_tests(title, test_set):
    print(f"\n\033[1;34m::: {title} :::\033[0m\n")
    for e in test_set:
        print(f"\033[1;34m  {e}\033[0m")
    if not test_set:
        print("\033[1;34m  {}\033[0m")
    print("\n")


def print_red(message):
    print(f"\n\033[0;31m{message}\033[0m\n")


def print_green(message):
    print(f"\n\033[0;32m{message}\033[0m\n")


CARGO_TESTS_FILE = "cargo-nextest.out"
BAZEL_TESTS_FILE = "bazel.tests"
CARGO_TESTSDOCS_FILE = "cargo-doc-tests.out"
BAZEL_TESTSDOCS_FILE = "bazel.doc-tests"


if __name__ == "__main__":

    # load all the tests ~ sets of tuples (package_name, test_name)
    cargo_tests, cargo_dup_tests = load_cargo_test_set(CARGO_TESTS_FILE, doctests=False)
    bazel_tests, bazel_dup_tests = load_bazel_test_set(BAZEL_TESTS_FILE, doctests=False)
    cargo_doctests, _ = load_cargo_test_set(CARGO_TESTSDOCS_FILE, doctests=True)
    bazel_doctests, _ = load_bazel_test_set(BAZEL_TESTSDOCS_FILE, doctests=True)

    # load the ignored tests
    args = sys.argv[1:]
    ignored_tests = load_ignored_test_set(args[0]) if len(args) > 0 else set()
    ignored_doctests = load_ignored_test_set(args[1]) if len(args) > 1 else set()

    # get unpaired tests
    only_cargo_tests, only_bazel_tests = get_unpair_tests(cargo_tests, cargo_dup_tests, bazel_tests, bazel_dup_tests)
    only_cargo_doctests, only_bazel_doctests = get_unpair_doctests(cargo_doctests, bazel_doctests)

    # make sorted test lists
    tests_parity_list = sorted(cargo_tests - only_cargo_tests)
    doctests_parity_list = sorted(cargo_doctests - only_cargo_doctests)
    tests_onlycargo_list = sorted(only_cargo_tests)
    tests_onlybazel_list = sorted(only_bazel_tests)
    doctests_onlycargo_list = sorted(only_cargo_doctests)
    doctests_onlybazel_list = sorted(only_bazel_doctests)

    # print test lists
    print_tests("Test Parity List", tests_parity_list)
    print_tests("Doc Test Parity List", doctests_parity_list)

    print_tests("Tolerated Missing Tests", sorted(ignored_tests))
    print_tests("Tolerated Missing Doc Tests", sorted(ignored_doctests))

    print_tests("Cargo Only Tests", tests_onlycargo_list)
    print_tests("Bazel Only Tests", tests_onlybazel_list)
    print_tests("Cargo Only Doc Tests", doctests_onlycargo_list)
    print_tests("Bazel Only Doc Tests", doctests_onlybazel_list)

    # save sorted test lists
    write_tests_to_file(tests_parity_list, "paired.tests")
    write_tests_to_file(doctests_parity_list, "paired.doc-tests")
    write_tests_to_file(tests_onlycargo_list, "missing.tests")
    write_tests_to_file(doctests_onlycargo_list, "missing.doc-tests")

    write_tests_to_file(sorted(cargo_tests), "all-tests.cargo")
    write_tests_to_file(sorted(bazel_tests), "all-tests.bazel")

    exit_code = 0
    if not only_cargo_tests <= ignored_tests:
        print_tests("Unignored Missing Tests", sorted(only_cargo_tests - ignored_tests))
        print_red("Provide the missing tests above within Bazel!")
        exit_code -= 1
    elif only_cargo_tests < ignored_tests:
        print_tests("Unnecessary Ignored Tests", sorted(ignored_tests - only_cargo_tests))

    if not only_cargo_doctests <= ignored_doctests:
        print_tests("Unignored Missing Doc Tests", sorted(only_cargo_doctests - ignored_doctests))
        print_red("Provide the missing tests above within Bazel!")
        exit_code -= 2
    elif only_cargo_doctests > ignored_doctests:
        print_tests("Unnecessary Ignored Doc Tests", sorted(ignored_doctests - only_cargo_doctests))

    if exit_code == 0:
        print_green("Cargo - Bazel Test Parity Check Successful")

    sys.exit(exit_code)
