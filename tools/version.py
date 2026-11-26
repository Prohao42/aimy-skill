"""Single version source (read statically by setuptools via pyproject ``attr``).

Kept import-free on purpose: this module is imported by ``main`` on every CLI
invocation, and the old ``importlib.metadata`` lookup dragged in the whole
``email``/``zipfile`` chain (~1s) on every ``aimy`` run.
"""

__version__ = "3.7.6"

__all__ = ["__version__"]
