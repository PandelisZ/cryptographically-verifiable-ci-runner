import idna


def to_ascii(host: str) -> str:
    return idna.encode(host).decode("ascii")
