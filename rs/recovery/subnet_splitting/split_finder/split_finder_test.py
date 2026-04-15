import unittest
from pathlib import Path

from data_io import load_subnet_data
from split_finder import find_split

TEST_DATA_DIR = Path(__file__).resolve().parents[1] / "test_data"
FAKE_LOAD_SAMPLE_CSV_PATH = str(TEST_DATA_DIR / "fake_load_sample.csv")
FAKE_COMMUNICATION_SAMPLE_CSV_PATH = str(TEST_DATA_DIR / "fake_communication_sample.csv")


class TestCsvLoading(unittest.TestCase):
    def test_valid_csv_files_load(self):
        result = load_subnet_data(
            FAKE_LOAD_SAMPLE_CSV_PATH, "ingress_messages_executed", FAKE_COMMUNICATION_SAMPLE_CSV_PATH
        )
        # this corresponds to the "ingress_messages_executed" column in "fake_load_sample.csv"
        self.assertEqual(result["load"], [2, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1])
        # the canisters in "fake_communication_sample.csv" form a cycling graph
        self.assertEqual(result["edges"], {(i, (i - 1) % 20): 1 for i in range(20)})
        self.assertEqual(len(result["index_to_canister_id"]), len(result["load"]))

    def test_solver_sanity_check(self):
        result = find_split(
            FAKE_LOAD_SAMPLE_CSV_PATH, FAKE_COMMUNICATION_SAMPLE_CSV_PATH, "instructions_executed", 0.0001, 100
        )

        self.assertEqual(
            result,
            [
                ("rkp4c-7iaaa-aaaaa-aaaca-cai", "rno2w-sqaaa-aaaaa-aaacq-cai"),
                ("qjdve-lqaaa-aaaaa-aaaeq-cai", "qsgjb-riaaa-aaaaa-aaaga-cai"),
                ("q3fc5-haaaa-aaaaa-aaahq-cai", "si2b5-pyaaa-aaaaa-aaaja-cai"),
            ],
            msg=f"`find_split` returned unexpected split: {result}",
        )


if __name__ == "__main__":
    unittest.main()
