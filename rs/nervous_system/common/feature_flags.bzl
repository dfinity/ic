def test_with_tla():
    return select({
        # Remove "tla" here to disable it in the CI
        "//conditions:default": ["test", "tla"],
        "//rs/nervous_system/common:tla_disabled": ["test"],
    })
