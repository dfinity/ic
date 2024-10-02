"""
Feature flags for turning TLA-based checks on and off.
"""

def test_with_tla():
    return select({
        # Remove "tla" here to disable TLA-related checks in the CI
        "//conditions:default": ["test", "tla"],
        "//rs/nervous_system/tla:tla_disabled": ["test"],
    })
