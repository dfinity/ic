import tempfile
import unittest
from pathlib import Path

from data_io import load_subnet_data
from split_finder import find_split

TEST_DATA_DIR = Path(__file__).resolve().parents[1] / "test_data"
FAKE_LOAD_SAMPLE_CSV_PATH = str(TEST_DATA_DIR / "fake_load_sample.csv")
FAKE_LOAD_BASELINE_SAMPLE_CSV_PATH = str(TEST_DATA_DIR / "fake_load_baseline_sample.csv")
FAKE_COMMUNICATION_SAMPLE_CSV_PATH = str(TEST_DATA_DIR / "fake_communication_sample.csv")
FAKE_COMMUNICATION_BASELINE_SAMPLE_CSV_PATH = str(TEST_DATA_DIR / "fake_communication_baseline_sample.csv")

# The canisters in "fake_communication_sample.csv" form a cycling graph. Subtracting
# "fake_communication_baseline_sample.csv" from it leaves one message per edge, except:
# - canister 1 sent no new message to canister 0 (diff is 0), so that edge is dropped;
# - the counter of canister 2 to canister 1 was reset, so the fresh count (1) is used;
# - the counts of canisters 10 and 19 are higher in both samples but their diff is still 1;
# - the baseline-only rows (canister 0 -> canister 1 and canister 20 -> canister 0) are ignored.
FAKE_COMMUNICATION_EDGES = {(i, (i - 1) % 20): 1 for i in range(20) if i != 1}


class TestCsvLoading(unittest.TestCase):
    def test_valid_csv_files_load(self):
        result = load_subnet_data(
            FAKE_LOAD_SAMPLE_CSV_PATH,
            FAKE_LOAD_BASELINE_SAMPLE_CSV_PATH,
            "ingress_messages_executed",
            FAKE_COMMUNICATION_SAMPLE_CSV_PATH,
            FAKE_COMMUNICATION_BASELINE_SAMPLE_CSV_PATH,
        )
        # this corresponds to the "ingress_messages_executed" column in "fake_load_sample.csv"
        self.assertEqual(
            result["load"],
            [1.0, 0.0, 1.0, 0.0, 3.0, 1.0, 3.0, 1.0, 3.0, 1.0, 3.0, 1.0, 3.0, 1.0, 3.0, 1.0, 3.0, 1.0, 3.0, 1.0],
            msg=f"`load_subnet_data` returned {result}",
        )
        self.assertEqual(result["edges"], FAKE_COMMUNICATION_EDGES)
        self.assertEqual(len(result["index_to_canister_id"]), len(result["load"]))

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
                "ingress_messages_executed",
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
                "ingress_messages_executed",
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
                "ingress_messages_executed",
                communication_path,
                communication_baseline_path,
            )
        # The counter was reset (e.g. evicted and recreated) since the baseline was collected, so
        # the fresh count is a lower bound on the number of messages exchanged in the meantime.
        self.assertEqual(result["edges"], {(1, 0): 5})

    def test_solver_sanity_check(self):
        result = find_split(
            FAKE_LOAD_SAMPLE_CSV_PATH,
            FAKE_LOAD_BASELINE_SAMPLE_CSV_PATH,
            FAKE_COMMUNICATION_SAMPLE_CSV_PATH,
            FAKE_COMMUNICATION_BASELINE_SAMPLE_CSV_PATH,
            "instructions_executed",
            0.0001,
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


if __name__ == "__main__":
    unittest.main()
