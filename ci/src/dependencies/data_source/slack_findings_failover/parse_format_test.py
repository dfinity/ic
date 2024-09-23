from data_source.slack_findings_failover.parse_format import (
    parse_finding_project,
    parse_slack_field,
    parse_slack_optional_hyperlink,
)


def test_parse_slack_field():
    assert parse_slack_field("*name*\ncontent", "name") == "content"
    assert parse_slack_field("*some name with space*\n   some content with space", "some name with space") == "some content with space"
    assert parse_slack_field("*name*\nsome content with special char <>!@#$%^&*()_+-=;':\",./", "name") == "some content with special char <>!@#$%^&*()_+-=;':\",./"


def test_parse_slack_optional_hyperlink():
    assert parse_slack_optional_hyperlink("foo") == ("foo", None)
    assert parse_slack_optional_hyperlink("<https://example.com|Example Website>") == ("Example Website", "https://example.com")
    assert parse_slack_optional_hyperlink("<ftp://example.com:21|Example FTP Server>") == ("Example FTP Server", "ftp://example.com:21")


def test_parse_finding_project():
    assert parse_finding_project("some/project/path") == (None, "some/project/path", None)
    assert parse_finding_project("PREFIX:C:\\\\a path\\for some (really cool) project") == ("PREFIX:", "C:\\\\a path\\for some (really cool) project", None)
    assert parse_finding_project("/this is/a (long) linux path    (https://example.com)") == (None, "/this is/a (long) linux path", "https://example.com")
    assert parse_finding_project("OSP:   /some/project/path (https://example.com)") == ("OSP:   ", "/some/project/path", "https://example.com")
