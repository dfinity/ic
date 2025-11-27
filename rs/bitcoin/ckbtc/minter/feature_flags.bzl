"""
Feature flags shared between Bazel targets for enabling TLA instrumentation.
"""

def test_with_tla():
    return select({
        # Add/remove "tla" in the default conditions to enable/disable TLA-related checks in the CI
        "//conditions:default": ["tla"],
        # When this flag is set, TLA-related checks are always disabled (not in the feature list)
        "//rs/bitcoin/ckbtc/minter:tla_disabled": [],
    })
