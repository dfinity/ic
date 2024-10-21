"""
Feature flags for turning TLA-based checks on and off.
"""

def test_with_tla():
    return select({
        # Add "tla" here to enable TLA-related checks in the CI
        "//conditions:default": ["test"],
        "//rs/nns/governance:tla_disabled": ["test"],
    })
