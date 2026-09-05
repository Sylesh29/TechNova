"""Packaging invariants.

These exist because both were violated once. A module named after a standard
library module is invisible from the repo root and fatal from inside the
package directory - Python fails importing `enum` before reaching our code.
"""
import pathlib
import sys
import unittest

PKG = pathlib.Path(__file__).resolve().parent.parent


class TestNoStdlibShadowing(unittest.TestCase):
    def test_no_module_shadows_the_standard_library(self):
        stdlib = sys.stdlib_module_names
        offenders = sorted(
            p.stem for p in PKG.glob("*.py")
            if p.stem in stdlib and not p.stem.startswith("__")
        )
        self.assertEqual(
            offenders, [],
            f"these modules shadow stdlib and break `python run.py` from inside "
            f"the package: {offenders}",
        )

    def test_test_modules_do_not_shadow_either(self):
        offenders = sorted(
            p.stem for p in (PKG / "tests").glob("*.py")
            if p.stem in sys.stdlib_module_names and not p.stem.startswith("__")
        )
        self.assertEqual(offenders, [])


class TestNoThirdPartyDependencies(unittest.TestCase):
    def test_package_imports_only_the_standard_library(self):
        import ast
        stdlib = sys.stdlib_module_names
        foreign: list[str] = []
        for path in PKG.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    if node.level:          # relative import, ours
                        continue
                    names = [(node.module or "").split(".")[0]]
                else:
                    continue
                foreign += [n for n in names
                            if n and n not in stdlib and n != "actionguard"]
        self.assertEqual(sorted(set(foreign)), [],
                         "package must stay dependency-free")


if __name__ == "__main__":
    unittest.main()
