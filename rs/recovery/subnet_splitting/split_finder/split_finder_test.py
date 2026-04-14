import unittest

from data_io import load_subnet_data

class TestCsvLoading(unittest.TestCase):
    def test_upper(self):
        result = load_subnet_data("rs/recovery/subnet_splitting/test_data/fake_load_sample.csv", "ingress_messages_executed", "rs/recovery/subnet_splitting/test_data/fake_communication_sample.csv")
        // FIXME(kpop): validation

if __name__ == '__main__':
    unittest.main()
