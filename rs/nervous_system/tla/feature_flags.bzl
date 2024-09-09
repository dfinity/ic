def test_with_tla():
    return select({
        # Remove "tla" here to disable TLA-related checks in the CI
        "//conditions:default": ["test", "tla"],
        "//rs/nervous_system/common:tla_disabled": ["test"],
    })
