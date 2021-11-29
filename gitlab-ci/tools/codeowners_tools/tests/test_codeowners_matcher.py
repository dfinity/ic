from io import StringIO

from codeowners_tools import codeowners_matcher


def test_matchers():
    matcher = codeowners_matcher.Matcher(
        inp=StringIO(
            """
/docs/          @granstrom @jancamenisch @jwiegley
/docs/spec/replica/protocol/consensus_layer/	@dfinity-lab/consensus-owners

# Hydra is being deprecated. No new Hydra jobs to be added without approval from IDX.
**/*.nix @dfinity-lab/idx

# This is a gitlab style pattern, which should not match 'nix/subdir/file'
nix/*/file @dfinity-lab/idx

# Protobuf linting config
/buf.yaml	@dfinity-lab/idx @dfinity-lab/interface-owners

# IC-OS project
/ic-os/                   @dfinity-lab/node-team
"""
        ),
        groups={
            "consensus-owners": ["user1", "user2"],
            "idx": ["valeryz", "marko"],
            "interface-owners": ["user3", "user4", "user5"],
        },
        user_map={
            "valeryz": "valeriy.zamaraiev",
        },
    )
    assert matcher.owners("something.nix") == set(["valeriy.zamaraiev", "marko"])
    assert matcher.owners("docs/abc/def") == set(["granstrom", "jancamenisch", "jwiegley"])
    assert matcher.owners("buf.yaml") == set(["user3", "user4", "user5", "valeriy.zamaraiev", "marko"])
    assert matcher.owners("nonexistent/path") == set()
    # Gitlab-style match
    assert matcher.owners("nix/somefile/another_file") == set([])
    assert matcher.owners("nix/somedir/file") == set(["valeriy.zamaraiev", "marko"])


def test_user_map():
    user_map = codeowners_matcher.parse_user_map()
    assert user_map["valeryz"] == "valeriy.zamaraiev"
