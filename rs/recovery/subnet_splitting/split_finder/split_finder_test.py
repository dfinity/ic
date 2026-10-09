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
        # the canisters in "fake_communication_sample.csv" form a cycling graph
        self.assertEqual(result["edges"], {(i, (i - 1) % 20): 1 for i in range(20)})
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
        self.assertEqual(result["edges"], {(i, (i - 1) % 20): 1 for i in range(20)})

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
                ("rwlgt-iiaaa-aaaaa-aaaaa-cai", "rrkah-fqaaa-aaaaa-aaaaq-cai"),
                ("rkp4c-7iaaa-aaaaa-aaaca-cai", "qoctq-giaaa-aaaaa-aaaea-cai"),
                ("qsgjb-riaaa-aaaaa-aaaga-cai", "qvhpv-4qaaa-aaaaa-aaagq-cai"),
                ("sp3hj-caaaa-aaaaa-aaajq-cai", "sp3hj-caaaa-aaaaa-aaajq-cai"),
            ],
            msg=f"`find_split` returned unexpected split: {result}",
        )


if __name__ == "__main__":
    unittest.main()
