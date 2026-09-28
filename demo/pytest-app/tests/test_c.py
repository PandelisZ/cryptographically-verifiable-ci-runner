from c import load_impl


def test_computed_import():
    assert load_impl("x").NAME == "x"
