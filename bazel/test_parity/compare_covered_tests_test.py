from test_parity import compare_covered_tests as c


def test_no_unpaired_empty_sets():
    assert c.get_unpair_tests(set(), set(), set(), set()) == (set(), set())


def test_no_unpaired_simple():
    cargo_tests = {("package1", "test1"), ("package1", "test2")}
    bazel_tests = {("package1", "test1"), ("package1", "test2")}

    only_cargo, only_bazel = c.get_unpair_tests(cargo_tests, set(), bazel_tests, set())

    assert only_cargo == set()
    assert only_bazel == set()


def test_unpaired_simple():
    cargo_tests = {("package1", "test1"), ("package1", "test2")}
    bazel_tests = {("package1", "test1")}

    only_cargo, only_bazel = c.get_unpair_tests(cargo_tests, set(), bazel_tests, set())

    assert only_cargo, only_bazel == ({("package1", "test2")}, set())


def test_unpaired_duplicate():
    cargo_tests = {("package1", "test1"), ("package1", "test2")}
    bazel_tests = {("package1", "test1"), ("package1", "test2")}
    cargo_dup_tests = {("package1", "test1"): 2}
    bazel_dup_tests = {}

    only_cargo, only_bazel = c.get_unpair_tests(cargo_tests, cargo_dup_tests, bazel_tests, bazel_dup_tests)

    assert only_cargo == {("package1", "test1")}
    assert only_bazel == set()


def test_unpaired_duplicates():
    cargo_tests = {("package1", "test1"), ("package1", "test2")}
    bazel_tests = {("package1", "test1"), ("package1", "test2")}
    cargo_dup_tests = {("package1", "test1"): 3}
    bazel_dup_tests = {("package1", "test1"): 2}

    only_cargo, only_bazel = c.get_unpair_tests(cargo_tests, cargo_dup_tests, bazel_tests, bazel_dup_tests)

    assert only_cargo == {("package1", "test1")}
    assert only_bazel == set()


def test_paired_duplicate():
    cargo_tests = {("package1", "test1"), ("package1", "test2")}
    bazel_tests = {("package1", "test1"), ("package1", "test2")}
    cargo_dup_tests = {("package1", "test1"): 2}
    bazel_dup_tests = {("package1", "test1"): 2}

    only_cargo, only_bazel = c.get_unpair_tests(cargo_tests, cargo_dup_tests, bazel_tests, bazel_dup_tests)

    assert only_cargo == set()
    assert only_bazel == set()
