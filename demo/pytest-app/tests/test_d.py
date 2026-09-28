from d import to_ascii


def test_external_package():
    assert to_ascii("bücher.example") == "xn--bcher-kva.example"
