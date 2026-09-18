"""Bind the package as `actionguard` before any test module imports it.

`python run.py test` does this in run.py. But the first thing a reviewer
types is `pytest` or `python -m unittest discover`, and those import this
package by whatever the checkout happens to be called - which is not
`actionguard` after GitHub's "Download ZIP", a fork, or a rename. Both
runners import this file before any test module, so binding the name here
makes all three entry points behave identically.
"""
import importlib.util
import pathlib
import sys

_PKG = pathlib.Path(__file__).resolve().parent.parent

if "actionguard" not in sys.modules:
    _spec = importlib.util.spec_from_file_location(
        "actionguard", _PKG / "__init__.py",
        submodule_search_locations=[str(_PKG)],
    )
    _module = importlib.util.module_from_spec(_spec)
    sys.modules["actionguard"] = _module
    _spec.loader.exec_module(_module)
