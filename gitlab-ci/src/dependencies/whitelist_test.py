import datetime
import json
import pathlib

import inventory
import pytest
import whitelist


TEST_DATA = pathlib.Path(__file__).parent / "test_data"


class FakeCargo(inventory.Cargo):
    """Fake cargo helper that accepts path to the inventory under TEST_DATA."""

    def __init__(self, inv_path):
        """Init with test data."""
        filename = inv_path + ".json"
        self.inv_path = TEST_DATA / "whitelist" / filename

    def get_whitelist_file(self):
        """Return path to the test inventory file."""
        return self.inv_path


class FakeWhitelistManager(whitelist.WhitelistManager):
    def __init__(self, test):
        super(FakeWhitelistManager, self).__init__()
        self.external = inventory.Inventory(FakeCargo(inv_path=test))


def test_valid_repo_whitelist():
    whitelist_manager = whitelist.WhitelistManager()
    assert whitelist_manager.check_whitelist_sanity()


def test_valid_whitelist():
    whitelist_manager = FakeWhitelistManager("valid_whitelist")
    assert whitelist_manager.check_whitelist_sanity()


def test_valid_empty_whitelist():
    whitelist_manager = FakeWhitelistManager("valid_empty_whitelist")
    assert whitelist_manager.check_whitelist_sanity()


def test_missing_fields_whitelist():
    whitelist_manager = FakeWhitelistManager("missing_fields")
    assert not whitelist_manager.check_whitelist_sanity()


def test_empty_fields_whitelist():
    whitelist_manager = FakeWhitelistManager("empty_fields")
    assert not whitelist_manager.check_whitelist_sanity()


def test_multiple_entries_whitelist():
    whitelist_manager = FakeWhitelistManager("multiple_entries")
    assert not whitelist_manager.check_whitelist_sanity()


def test_invalid_date_whitelist():
    whitelist_manager = FakeWhitelistManager("invalid_date")
    assert not whitelist_manager.check_whitelist_sanity()


def test_validate_whitelist():
    whitelist_manager = FakeWhitelistManager("validate_whitelist")
    vulnerable_crates = ["chrono:0.4.19", "regex:1.5.4", "thread_local:1.0.1"]
    _, fail_job = whitelist_manager.validate_whitelist(vulnerable_crates=vulnerable_crates)
    # Job should fail
    assert fail_job


def test_validate_whitelist_valid_entry():
    whitelist_manager = FakeWhitelistManager("validate_whitelist")
    vulnerable_crates = ["regex:1.5.4"]
    whitelist_status, fail_job = whitelist_manager.validate_whitelist(vulnerable_crates=vulnerable_crates)
    # Job should pass
    assert not fail_job
    # Valid expiry
    assert whitelist_status[0] == "regex:1.5.4 is present in the Whitelist with a valid expiry until 09/08/2030"


def test_validate_whitelist_expired_entry():
    whitelist_manager = FakeWhitelistManager("validate_whitelist")
    vulnerable_crates = ["chrono:0.4.19"]
    whitelist_status, fail_job = whitelist_manager.validate_whitelist(vulnerable_crates=vulnerable_crates)
    # Job should fail
    assert fail_job
    # Expired entry
    assert whitelist_status[0] == "chrono:0.4.19 is present in the Whitelist but the entry expired on 22/06/2019"


def test_validate_whitelist_no_entry():
    whitelist_manager = FakeWhitelistManager("validate_whitelist")
    vulnerable_crates = ["thread_local:1.0.1"]
    whitelist_status, fail_job = whitelist_manager.validate_whitelist(vulnerable_crates=vulnerable_crates)
    # Job should fail
    assert fail_job
    # No entry
    assert whitelist_status[0] == "thread_local:1.0.1 is not fixed and not present in the Whitelist"


@pytest.fixture
def temp_whitelist():
    whitelist_manager = FakeWhitelistManager("valid_empty_whitelist")
    yield whitelist_manager
    with open(whitelist_manager.get_whitelist_file(), "w") as whitelist_file:
        json.dump([], whitelist_file)


def test_update_whitelist_one_entry_empty_file(temp_whitelist):
    whitelist_status, fail_job = temp_whitelist.validate_whitelist(["chrono:0.4.19"])
    assert fail_job
    assert whitelist_status[0] == "chrono:0.4.19 is not fixed and not present in the Whitelist"

    temp_whitelist.update_whitelist(["chrono:0.4.19"])
    with open(temp_whitelist.get_whitelist_file(), "r") as whitelist_file:
        data = json.load(whitelist_file)

    assert len(data) == 1
    assert data[0]["name"] == "chrono"
    assert data[0]["version"] == "0.4.19"
    assert data[0]["expiry_days"] == temp_whitelist.expiry
    assert data[0]["date_added"] == datetime.date.today().strftime("%d/%m/%Y")
    assert data[0]["date_updated"] == datetime.date.today().strftime("%d/%m/%Y")

    whitelist_status, fail_job = temp_whitelist.validate_whitelist(["chrono:0.4.19"])
    assert not fail_job
    expiry_date = datetime.date.today() + datetime.timedelta(days=int(temp_whitelist.expiry))
    assert (
        whitelist_status[0]
        == f'chrono:0.4.19 is present in the Whitelist with a valid expiry until {expiry_date.strftime("%d/%m/%Y")}'
    )


def test_update_whitelist_multiple_entry_empty_file(temp_whitelist):
    whitelist_status, fail_job = temp_whitelist.validate_whitelist(["chrono:0.4.19", "regex:1.5.4"])
    assert fail_job
    assert whitelist_status[0] == "chrono:0.4.19 is not fixed and not present in the Whitelist"
    assert whitelist_status[1] == "regex:1.5.4 is not fixed and not present in the Whitelist"

    temp_whitelist.update_whitelist(["chrono:0.4.19", "regex:1.5.4"])

    with open(temp_whitelist.get_whitelist_file(), "r") as whitelist_file:
        data = json.load(whitelist_file)

    assert len(data) == 2
    assert data[0]["name"] == "chrono"
    assert data[0]["version"] == "0.4.19"
    assert data[0]["expiry_days"] == temp_whitelist.expiry
    assert data[0]["date_added"] == datetime.date.today().strftime("%d/%m/%Y")
    assert data[0]["date_updated"] == datetime.date.today().strftime("%d/%m/%Y")
    assert data[1]["name"] == "regex"
    assert data[1]["version"] == "1.5.4"
    assert data[1]["expiry_days"] == temp_whitelist.expiry
    assert data[1]["date_added"] == datetime.date.today().strftime("%d/%m/%Y")
    assert data[1]["date_updated"] == datetime.date.today().strftime("%d/%m/%Y")

    whitelist_status, fail_job = temp_whitelist.validate_whitelist(["chrono:0.4.19", "regex:1.5.4"])
    assert not fail_job
    expiry_date = datetime.date.today() + datetime.timedelta(days=int(temp_whitelist.expiry))
    assert (
        whitelist_status[0]
        == f'chrono:0.4.19 is present in the Whitelist with a valid expiry until {expiry_date.strftime("%d/%m/%Y")}'
    )
    assert (
        whitelist_status[1]
        == f'regex:1.5.4 is present in the Whitelist with a valid expiry until {expiry_date.strftime("%d/%m/%Y")}'
    )


def test_update_whitelist_existing_entry():
    whitelist_manager = FakeWhitelistManager("update_existing_whitelist")
    with open(whitelist_manager.get_whitelist_file(), "r") as whitelist_file:
        test_data = json.load(whitelist_file)

    whitelist_status, fail_job = whitelist_manager.validate_whitelist(["chrono:0.4.19"])
    assert fail_job
    assert whitelist_status[0] == "chrono:0.4.19 is present in the Whitelist but the entry expired on 23/05/2022"

    whitelist_manager.update_whitelist(["chrono:0.4.19"])
    with open(whitelist_manager.get_whitelist_file(), "r") as whitelist_file:
        data = json.load(whitelist_file)

    assert len(data) == 1
    assert data[0]["name"] == "chrono"
    assert data[0]["version"] == "0.4.19"
    assert data[0]["expiry_days"] == whitelist_manager.expiry
    assert data[0]["date_updated"] == datetime.date.today().strftime("%d/%m/%Y")

    whitelist_status, fail_job = whitelist_manager.validate_whitelist(["chrono:0.4.19"])
    assert not fail_job
    expiry_date = datetime.date.today() + datetime.timedelta(days=int(whitelist_manager.expiry))
    assert (
        whitelist_status[0]
        == f'chrono:0.4.19 is present in the Whitelist with a valid expiry until {expiry_date.strftime("%d/%m/%Y")}'
    )

    with open(whitelist_manager.get_whitelist_file(), "w") as whitelist_file:
        json.dump(test_data, whitelist_file, indent=4, default=str)
