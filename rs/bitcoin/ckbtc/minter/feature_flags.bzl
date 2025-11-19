"""
Feature flags shared between Bazel targets for enabling TLA instrumentation.
"""

def test_with_tla():
    return select({
        "//conditions:default": ["tla"],
        "//rs/bitcoin/ckbtc/minter:tla_disabled": [],
    })
