import importlib


def load_impl(name: str):
    return importlib.import_module("pkg.impl_" + name)
