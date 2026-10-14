from b import load_greeting, load_language


def test_reads_fixture():
    assert load_greeting() == "hello"


def test_reads_language():
    assert load_language() == "en"
