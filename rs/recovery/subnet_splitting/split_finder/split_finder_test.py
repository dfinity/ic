import unittest

from data_io import load_subnet_data


class TestCsvLoading(unittest.TestCase):
    def test_valiad_csv_files_load(self):
        result = load_subnet_data(
            "rs/recovery/subnet_splitting/test_data/fake_load_sample.csv",
            "ingress_messages_executed",
            "rs/recovery/subnet_splitting/test_data/fake_communication_sample.csv",
        )
        # this corresponds to the "ingress_messages_executed" column in "fake_load_samples.csv"
        self.assertEqual(result["load"], [2, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1])
        # the canisters in "fake_communication_sample.csv" form a cycling graph
        self.assertEqual(result["edges"], [(i, (i - 1) % 20, 1) for i in range(20)])


if __name__ == "__main__":
    unittest.main()
