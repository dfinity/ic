import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from data_io import CANISTERS_INSTALLED, canister_id_to_number, load_subnet_data, number_to_canister_id
from split_finder import (
    DEFAULT_EPSILON_LOAD_DEFAULT,
    LOAD_TYPES,
    assign_canisters_to_ranges,
    compute_max_allowed_load_per_subnet,
    find_split,
    parse_args,
)

TEST_DATA_DIR = Path(__file__).resolve().parents[1] / "test_data"
FAKE_LOAD_SAMPLE_CSV_PATH = str(TEST_DATA_DIR / "fake_load_sample.csv")
FAKE_LOAD_BASELINE_SAMPLE_CSV_PATH = str(TEST_DATA_DIR / "fake_load_baseline_sample.csv")
FAKE_COMMUNICATION_SAMPLE_CSV_PATH = str(TEST_DATA_DIR / "fake_communication_sample.csv")
FAKE_COMMUNICATION_BASELINE_SAMPLE_CSV_PATH = str(TEST_DATA_DIR / "fake_communication_baseline_sample.csv")
# The canisters in "fake_load_sample.csv" are the canisters 0 to 19.
FAKE_SUBNET_CANISTER_ID_RANGES = [(0, 19)]

# The canisters in "fake_communication_sample.csv" form a cycling graph. Subtracting
# "fake_communication_baseline_sample.csv" from it leaves one message per edge, except:
# - canister 1 sent no new message to canister 0 (diff is 0), so that edge is dropped;
# - the counter of canister 2 to canister 1 was reset, so the fresh count (1) is used;
# - the counts of canisters 10 and 19 are higher in both samples but their diff is still 1;
# - the baseline-only rows (canister 0 -> canister 1 and canister 20 -> canister 0) are ignored.
FAKE_COMMUNICATION_EDGES = {(i, (i - 1) % 20): 1 for i in range(20) if i != 1}
FAKE_SAMPLE_PATHS = (
    FAKE_LOAD_SAMPLE_CSV_PATH,
    FAKE_LOAD_BASELINE_SAMPLE_CSV_PATH,
    FAKE_COMMUNICATION_SAMPLE_CSV_PATH,
    FAKE_COMMUNICATION_BASELINE_SAMPLE_CSV_PATH,
)
# All the command line arguments of the split finder which are required apart from `--load-type`.
REQUIRED_ARGS = [
    "--load-path",
    FAKE_LOAD_SAMPLE_CSV_PATH,
    "--load-baseline-path",
    FAKE_LOAD_BASELINE_SAMPLE_CSV_PATH,
    "--communication-data-path",
    FAKE_COMMUNICATION_SAMPLE_CSV_PATH,
    "--communication-baseline-data-path",
    FAKE_COMMUNICATION_BASELINE_SAMPLE_CSV_PATH,
    "--subnet-canister-id-ranges",
    "rwlgt-iiaaa-aaaaa-aaaaa-cai:sp3hj-caaaa-aaaaa-aaajq-cai",
    "--output-path",
    "output.txt",
]


def max_load_ratio(canister_ranges, load_type):
    """
    Returns the load of the more loaded post-split subnet relative to the maximum allowed load per
    subnet, so a split balances `load_type` within `epsilon` if the ratio is at most `1 + epsilon`.
    """
    load_path, load_baseline_path, communication_path, communication_baseline_path = FAKE_SAMPLE_PATHS
    data = load_subnet_data(load_path, load_baseline_path, [load_type], communication_path, communication_baseline_path)
    load = data["loads"][load_type]
    canister_id_to_index = {canister_id: index for index, canister_id in data["index_to_canister_id"].items()}
    load_in_ranges = sum(
        sum(load[canister_id_to_index[first] : canister_id_to_index[last] + 1]) for first, last in canister_ranges
    )
    load_outside_ranges = sum(load) - load_in_ranges
    return max(load_in_ranges, load_outside_ranges) / compute_max_allowed_load_per_subnet(load)


class TestCsvLoading(unittest.TestCase):
    def test_valid_csv_files_load(self):
        result = load_subnet_data(
            FAKE_LOAD_SAMPLE_CSV_PATH,
            FAKE_LOAD_BASELINE_SAMPLE_CSV_PATH,
            ["ingress_messages_executed"],
            FAKE_COMMUNICATION_SAMPLE_CSV_PATH,
            FAKE_COMMUNICATION_BASELINE_SAMPLE_CSV_PATH,
        )
        # this corresponds to the "ingress_messages_executed" column of "fake_load_sample.csv" minus that of
        # "fake_load_baseline_sample.csv"
        self.assertEqual(
            result["loads"]["ingress_messages_executed"],
            [1, 0, 1, 0, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1],
            msg=f"`load_subnet_data` returned {result}",
        )
        self.assertEqual(result["edges"], FAKE_COMMUNICATION_EDGES)
        self.assertEqual(len(result["index_to_canister_id"]), len(result["loads"]["ingress_messages_executed"]))

    def test_multiple_load_types_load(self):
        result = load_subnet_data(
            FAKE_LOAD_SAMPLE_CSV_PATH,
            FAKE_LOAD_BASELINE_SAMPLE_CSV_PATH,
            ["ingress_messages_executed", "heartbeats_and_global_timers_executed"],
            FAKE_COMMUNICATION_SAMPLE_CSV_PATH,
            FAKE_COMMUNICATION_BASELINE_SAMPLE_CSV_PATH,
        )
        # these correspond to the respective columns of "fake_load_sample.csv" minus those of
        # "fake_load_baseline_sample.csv"
        expected_ingress_load = [1, 0, 1, 0, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1]
        expected_heartbeats_load = [120, 0, 64, 0, 102, 0, 89, 0, 76, 0, 63, 0, 50, 0, 37, 0, 24, 0, 11, 0]
        self.assertEqual(
            result["loads"],
            {
                "ingress_messages_executed": expected_ingress_load,
                "heartbeats_and_global_timers_executed": expected_heartbeats_load,
            },
            msg=f"`load_subnet_data` returned {result}",
        )
        self.assertEqual(result["edges"], FAKE_COMMUNICATION_EDGES)

    def test_canisters_installed_load(self):
        result = load_subnet_data(
            FAKE_LOAD_SAMPLE_CSV_PATH,
            FAKE_LOAD_BASELINE_SAMPLE_CSV_PATH,
            [CANISTERS_INSTALLED],
            FAKE_COMMUNICATION_SAMPLE_CSV_PATH,
            FAKE_COMMUNICATION_BASELINE_SAMPLE_CSV_PATH,
        )
        # Every canister in "fake_load_sample.csv" counts once, including those in the baseline.
        self.assertEqual(result["loads"], {CANISTERS_INSTALLED: [1] * 20}, msg=f"`load_subnet_data` returned {result}")
        self.assertEqual(result["edges"], FAKE_COMMUNICATION_EDGES)

    def test_communication_with_unknown_canisters_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            communication_path = Path(tmp_dir) / "communication.csv"
            # Canisters which are not in the load data (e.g. deleted or migrated away) are ignored.
            communication_path.write_text(
                Path(FAKE_COMMUNICATION_SAMPLE_CSV_PATH).read_text().rstrip("\n")
                + "\nunknown-sender,rwlgt-iiaaa-aaaaa-aaaaa-cai,1"
                + "\nrwlgt-iiaaa-aaaaa-aaaaa-cai,unknown-receiver,1\n"
            )
            result = load_subnet_data(
                FAKE_LOAD_SAMPLE_CSV_PATH,
                FAKE_LOAD_BASELINE_SAMPLE_CSV_PATH,
                ["ingress_messages_executed"],
                communication_path,
                FAKE_COMMUNICATION_BASELINE_SAMPLE_CSV_PATH,
            )
        self.assertEqual(result["edges"], FAKE_COMMUNICATION_EDGES)

    def test_self_communication_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            communication_path = Path(tmp_dir) / "communication.csv"
            # A canister calling itself stays co-located under any split, so self-edges are ignored.
            communication_path.write_text(
                Path(FAKE_COMMUNICATION_SAMPLE_CSV_PATH).read_text().rstrip("\n")
                + "\nrwlgt-iiaaa-aaaaa-aaaaa-cai,rwlgt-iiaaa-aaaaa-aaaaa-cai,5\n"
            )
            result = load_subnet_data(
                FAKE_LOAD_SAMPLE_CSV_PATH,
                FAKE_LOAD_BASELINE_SAMPLE_CSV_PATH,
                ["ingress_messages_executed"],
                communication_path,
                FAKE_COMMUNICATION_BASELINE_SAMPLE_CSV_PATH,
            )
        self.assertEqual(result["edges"], FAKE_COMMUNICATION_EDGES)

    def test_communication_counter_reset_uses_fresh_count(self):
        header = "sender_canister_id,receiver_canister_id,count\n"
        sender = "rrkah-fqaaa-aaaaa-aaaaq-cai"
        receiver = "rwlgt-iiaaa-aaaaa-aaaaa-cai"
        with tempfile.TemporaryDirectory() as tmp_dir:
            communication_path = Path(tmp_dir) / "communication.csv"
            communication_path.write_text(header + f"{sender},{receiver},5\n")
            communication_baseline_path = Path(tmp_dir) / "communication_baseline.csv"
            communication_baseline_path.write_text(header + f"{sender},{receiver},100\n")
            result = load_subnet_data(
                FAKE_LOAD_SAMPLE_CSV_PATH,
                FAKE_LOAD_BASELINE_SAMPLE_CSV_PATH,
                ["ingress_messages_executed"],
                communication_path,
                communication_baseline_path,
            )
        # The counter was reset (e.g. evicted and recreated) since the baseline was collected, so
        # the fresh count is a lower bound on the number of messages exchanged in the meantime.
        self.assertEqual(result["edges"], {(1, 0): 5})

    def test_solver_sanity_check(self):
        epsilon = 0.0001
        result = find_split(
            FAKE_LOAD_SAMPLE_CSV_PATH,
            FAKE_LOAD_BASELINE_SAMPLE_CSV_PATH,
            FAKE_COMMUNICATION_SAMPLE_CSV_PATH,
            FAKE_COMMUNICATION_BASELINE_SAMPLE_CSV_PATH,
            FAKE_SUBNET_CANISTER_ID_RANGES,
            {"instructions_executed": epsilon},
            100,
        )

        self.assertEqual(
            result,
            [
                ("rwlgt-iiaaa-aaaaa-aaaaa-cai", "rwlgt-iiaaa-aaaaa-aaaaa-cai"),
                ("r7inp-6aaaa-aaaaa-aaabq-cai", "qjdve-lqaaa-aaaaa-aaaeq-cai"),
                ("qsgjb-riaaa-aaaaa-aaaga-cai", "qvhpv-4qaaa-aaaaa-aaagq-cai"),
            ],
            msg=f"`find_split` returned unexpected split: {result}",
        )
        self.assertLessEqual(
            max_load_ratio(result, "instructions_executed"),
            1 + epsilon,
            msg=f"`find_split` returned a split which doesn't balance instructions_executed: {result}",
        )

    def test_solver_balances_every_load_type(self):
        epsilon = 0.01
        load_types = ["instructions_executed", "heartbeats_and_global_timers_executed"]
        split = find_split(
            *FAKE_SAMPLE_PATHS, FAKE_SUBNET_CANISTER_ID_RANGES, {load_type: epsilon for load_type in load_types}, 100
        )

        for load_type in load_types:
            self.assertLessEqual(
                max_load_ratio(split, load_type),
                1 + epsilon,
                msg=f"`find_split` returned a split which doesn't balance {load_type}: {split}",
            )

        # Removing the heartbeats constraint makes split_finder ignore it
        instructions_only_split = find_split(
            *FAKE_SAMPLE_PATHS, FAKE_SUBNET_CANISTER_ID_RANGES, {"instructions_executed": epsilon}, 100
        )
        self.assertLessEqual(
            max_load_ratio(instructions_only_split, "instructions_executed"),
            1 + epsilon,
            msg=f"`find_split` returned a split which doesn't balance instructions_executed: {instructions_only_split}",
        )
        self.assertGreater(
            max_load_ratio(instructions_only_split, "heartbeats_and_global_timers_executed"),
            1 + epsilon,
            msg=f"`find_split` unexpectedly balanced the heartbeats: {instructions_only_split}",
        )

    def test_solver_applies_each_load_type_epsilon(self):
        load_epsilons = {"instructions_executed": 0.001, "heartbeats_and_global_timers_executed": 0.05}
        split = find_split(*FAKE_SAMPLE_PATHS, FAKE_SUBNET_CANISTER_ID_RANGES, load_epsilons, 100)

        for load_type, epsilon in load_epsilons.items():
            self.assertLessEqual(
                max_load_ratio(split, load_type),
                1 + epsilon,
                msg=f"`find_split` returned a split which doesn't balance {load_type}: {split}",
            )

        # Tightening the constraint becomes impossible
        with self.assertRaises(RuntimeError):
            find_split(
                *FAKE_SAMPLE_PATHS,
                FAKE_SUBNET_CANISTER_ID_RANGES,
                {load_type: 0.001 for load_type in load_epsilons},
                100,
            )

    def test_solver_balances_canisters_installed(self):
        epsilon = 0.0
        split = find_split(*FAKE_SAMPLE_PATHS, FAKE_SUBNET_CANISTER_ID_RANGES, {CANISTERS_INSTALLED: epsilon}, 100)

        # With no allowed deviation (epsilon == 0.0), the 20 canisters must be split evenly.
        self.assertLessEqual(
            max_load_ratio(split, CANISTERS_INSTALLED),
            1 + epsilon,
            msg=f"`find_split` returned unbalanced split: {split}",
        )

    def test_solver_balances_all_load_types(self):
        load_epsilons = {load_type: DEFAULT_EPSILON_LOAD_DEFAULT for load_type in LOAD_TYPES}
        split = find_split(*FAKE_SAMPLE_PATHS, FAKE_SUBNET_CANISTER_ID_RANGES, load_epsilons, 100)

        for load_type, epsilon in load_epsilons.items():
            self.assertLessEqual(
                max_load_ratio(split, load_type),
                1 + epsilon,
                msg=f"`find_split` returned a split which doesn't balance {load_type}: {split}",
            )

    def test_solver_splits_ranges_between_subnet_canister_id_ranges(self):
        # The subnet hosts canister 100 in its first canister ID range, canisters 1000 and 1001 in its
        # second one, and canister 2000 in its third one. Canister 100 talks to canister 1000 and
        # canister 2000 to canister 1001, so each pair stays together. None of these canisters is in
        # the baseline samples.
        split = find_split(
            str(TEST_DATA_DIR / "fake_multi_range_load_sample.csv"),
            FAKE_LOAD_BASELINE_SAMPLE_CSV_PATH,
            str(TEST_DATA_DIR / "fake_multi_range_communication_sample.csv"),
            FAKE_COMMUNICATION_BASELINE_SAMPLE_CSV_PATH,
            [(100, 199), (1000, 1099), (2000, 2099)],
            {CANISTERS_INSTALLED: 0.0},
            100,
        )

        # The range of canisters 1001 and 2000 would span the canister IDs of other subnets.
        self.assertEqual(
            split,
            [
                ("heic2-yaaaa-aaaaa-aapuq-cai", "heic2-yaaaa-aaaaa-aapuq-cai"),
                ("txegi-kaaaa-aaaaa-aa7ia-cai", "txegi-kaaaa-aaaaa-aa7ia-cai"),
            ],
            msg=f"`find_split` returned unexpected split: {split}",
        )


class TestCanisterIdRanges(unittest.TestCase):
    def test_canister_ids_convert_to_numbers(self):
        for canister_id, number in [
            ("rwlgt-iiaaa-aaaaa-aaaaa-cai", 0),
            ("rrkah-fqaaa-aaaaa-aaaaq-cai", 1),
            ("37pka-5h777-77777-7777q-cai", 2**64 - 1),
        ]:
            with self.subTest(canister_id=canister_id):
                self.assertEqual(canister_id_to_number(canister_id), number)
                self.assertEqual(number_to_canister_id(number), canister_id)

    def test_invalid_canister_ids_are_rejected(self):
        for canister_id in [
            "",
            "bogus",
            # The management canister is not a canister ID.
            "aaaaa-aa",
            # Wrong checksum.
            "rwlgt-iiaaa-aaaaa-aaaaa-caa",
            # Not the canonical textual form.
            "RWLGT-IIAAA-AAAAA-AAAAA-CAI",
        ]:
            with self.subTest(canister_id=canister_id), self.assertRaises(ValueError):
                canister_id_to_number(canister_id)

    def test_canisters_are_assigned_to_ranges(self):
        self.assertEqual(assign_canisters_to_ranges([0, 1, 5, 9, 20], [(5, 9), (0, 1), (20, 20)]), [0, 0, 1, 1, 2])

    def test_invalid_assignments_to_ranges_are_rejected(self):
        for canister_numbers, ranges in [
            # A canister lies between, before or after the ranges.
            ([0, 5, 9], [(0, 1), (6, 9)]),
            ([0, 5], [(1, 9)]),
            ([5, 10], [(0, 9)]),
            # The ranges overlap.
            ([0, 5], [(0, 5), (5, 9)]),
            # The canisters are not in increasing order.
            ([5, 0], [(0, 9)]),
            ([5, 5], [(0, 9)]),
        ]:
            with self.subTest(canister_numbers=canister_numbers, ranges=ranges), self.assertRaises(ValueError):
                assign_canisters_to_ranges(canister_numbers, ranges)


class TestArgParsing(unittest.TestCase):
    def test_load_types_without_epsilon_use_epsilon_load(self):
        args = parse_args(
            REQUIRED_ARGS
            + ["--load-type", "instructions_executed", "heartbeats_and_global_timers_executed=0.2"]
            + ["--epsilon-load", "0.01"]
        )
        self.assertEqual(
            args.load_epsilons,
            {"instructions_executed": 0.01, "heartbeats_and_global_timers_executed": 0.2},
        )

    def test_invalid_load_types_are_rejected(self):
        for load_type_args in [
            ["bogus"],
            ["bogus=0.1"],
            ["instructions_executed="],
            ["instructions_executed=abc"],
            ["instructions_executed=-0.1"],
            ["instructions_executed=nan"],
            ["instructions_executed", "instructions_executed=0.1"],
        ]:
            with (
                self.subTest(load_type_args=load_type_args),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                parse_args(REQUIRED_ARGS + ["--load-type", *load_type_args])

    def test_subnet_canister_id_ranges_are_parsed(self):
        # The ranges given last replace those in `REQUIRED_ARGS`.
        args = parse_args(
            REQUIRED_ARGS
            + ["--load-type", "instructions_executed"]
            + ["--subnet-canister-id-ranges", "rwlgt-iiaaa-aaaaa-aaaaa-cai:rwlgt-iiaaa-aaaaa-aaaaa-cai"]
            + ["rrkah-fqaaa-aaaaa-aaaaq-cai:sp3hj-caaaa-aaaaa-aaajq-cai"]
        )
        self.assertEqual(args.subnet_canister_id_ranges, [(0, 0), (1, 19)])

    def test_invalid_subnet_canister_id_ranges_are_rejected(self):
        for range_args in [
            [],
            ["bogus"],
            ["rwlgt-iiaaa-aaaaa-aaaaa-cai"],
            ["rwlgt-iiaaa-aaaaa-aaaaa-cai:bogus"],
            ["rrkah-fqaaa-aaaaa-aaaaq-cai:rwlgt-iiaaa-aaaaa-aaaaa-cai"],
        ]:
            with (
                self.subTest(range_args=range_args),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                # The ranges given last replace those in `REQUIRED_ARGS`.
                parse_args(
                    REQUIRED_ARGS + ["--load-type", "instructions_executed", "--subnet-canister-id-ranges", *range_args]
                )


if __name__ == "__main__":
    unittest.main()
