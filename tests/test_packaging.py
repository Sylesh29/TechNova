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


class TestImportsFromAnyDirectoryName(unittest.TestCase):
    """The repository root is the package, so nothing may infer the package
    name from the folder name. `git clone` gives `actionguard`; GitHub's
    "Download ZIP" gives `actionguard-main`. Both must work identically.
    """

    def test_runs_when_the_checkout_is_named_something_else(self):
        import shutil
        import subprocess
        import sys
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            dest = pathlib.Path(tmp) / "actionguard-main"
            shutil.copytree(
                PKG, dest,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"),
            )
            # `eval` rather than `test`, so this check never recurses into itself.
            proc = subprocess.run(
                [sys.executable, "run.py", "eval"],
                cwd=dest, capture_output=True, text=True, timeout=120,
            )
        self.assertEqual(
            proc.returncode, 0,
            f"package failed to import from a differently-named checkout:\n"
            f"{proc.stderr[-1500:]}",
        )
        self.assertIn("EVAL", proc.stdout)


if __name__ == "__main__":
    unittest.main()
