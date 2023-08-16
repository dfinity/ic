import unittest

import ic
from pocket_ic import PocketIC


class CanisterTests(unittest.TestCase):
    def setUp(self) -> None:
        # this is being run for every test independently
        self.ic = PocketIC()
        return super().setUp()

    def tearDown(self) -> None:
        return super().tearDown()

    def test_counter_canister(self):
        sender = ic.Principal.anonymous()
        canister_id = self.ic.create_canister(sender)

        self.assertEqual(canister_id.to_str(), "rwlgt-iiaaa-aaaaa-aaaaa-cai")
        self.assertEqual(self.ic.add_cycles(canister_id, 1_000_000_000_000_000_000), 1_000_000_000_000_000_000)

        with open("counter.wasm", "rb") as f:
            wasm_module = f.read()

        self.assertEqual(self.ic.install_canister(sender, canister_id, bytes(wasm_module)), [])

        self.assertEqual(self.ic.canister_update_call(sender, canister_id, "read", [])["Ok"]["Reply"], [0, 0, 0, 0])
        self.assertEqual(self.ic.canister_update_call(sender, canister_id, "write", [])["Ok"]["Reply"], [1, 0, 0, 0])
        self.assertEqual(self.ic.canister_update_call(sender, canister_id, "write", [])["Ok"]["Reply"], [2, 0, 0, 0])
        self.assertEqual(self.ic.canister_update_call(sender, canister_id, "read", [])["Ok"]["Reply"], [2, 0, 0, 0])

    def test_pocket_ic(self):
        print(f"all instances: {self.ic.backend.list_instances()}")
        print(f"my instance: {self.ic.instance_url}")

    def test_get_root_key(self):
        self.assertEqual(self.ic.get_root_key(), [48, 129, 130, 48, 29, 6, 13, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 1, 2, 1, 6, 12, 43, 6, 1, 4, 1, 130, 220, 124, 5, 3, 2, 1, 3, 97, 0, 173, 246, 86, 56, 165, 48, 86, 178, 34, 44, 145, 187, 36, 87, 176, 39, 75, 202, 149, 25, 138, 90, 203, 218, 223, 231, 253, 114, 23, 143, 6, 155, 222, 168, 217, 158, 148, 121, 216, 8, 122, 38, 134, 252, 129, 191, 60, 75, 17, 254, 39, 85, 112, 212, 129, 241, 105, 143, 121, 212, 104, 175, 224, 229, 122, 204, 30, 41, 143, 139, 105, 121, 141, 167, 168, 145, 187, 236, 25, 112, 147, 236, 95, 71, 89, 9, 146, 61, 72, 191, 237, 104, 67, 219, 237, 31])

    def test_time_and_tick(self):
        self.assertEqual(self.ic.get_time(), {"secs_since_epoch": 1620328630, "nanos_since_epoch": 0})
        self.assertEqual(self.ic.set_time(1704067199999999999), None)
        self.assertEqual(self.ic.get_time(), {"secs_since_epoch": 1704067199, "nanos_since_epoch": 999999999})
        self.assertEqual(self.ic.tick(), None)
        self.assertEqual(self.ic.advance_time(1 * 1_000_000_000), None)
        self.assertEqual(self.ic.get_time(), {"secs_since_epoch": 1704067200, "nanos_since_epoch": 999999999})


if __name__ == "__main__":
    unittest.main()
