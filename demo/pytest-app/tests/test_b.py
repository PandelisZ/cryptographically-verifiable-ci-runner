from b import load_greeting


def test_reads_fixture():
    assert load_greeting() == "hello"
