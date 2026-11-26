"""
Repository hygiene checks that catch mistakes before they ship:

  * every third-party module imported by the application (or the tests) is declared in requirements(-dev).txt
  * no module defines the same top-level name twice (a second `class X` silently replaces the first)
  * every JavaScript file parses (node --check), when Node.js is available
"""
import ast
import os
import re
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_SOURCES = ["app.py", "favicon_hash.py", "api", "core"]
LOCAL = {"api", "core", "app", "favicon_hash", "tests", "tools", "conftest"}
# import name -> distribution name on PyPI
DIST = {"bs4": "beautifulsoup4", "PIL": "pillow", "dns": "dnspython", "bson": "pymongo", "gridfs": "pymongo", "starlette": "fastapi",
        "yaml": "pyyaml", "sklearn": "scikit-learn"}


def py_files(paths):
    for p in paths:
        full = os.path.join(ROOT, p)
        if os.path.isfile(full):
            yield full
        else:
            for d, dirs, files in os.walk(full):
                dirs[:] = [x for x in dirs if x != "__pycache__"]
                yield from (os.path.join(d, f) for f in files if f.endswith(".py"))


def top_imports(path):
    tree = ast.parse(open(path, encoding="utf-8").read(), path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module.split(".")[0]


def declared(*files):
    names = set()
    for f in files:
        for line in open(os.path.join(ROOT, f), encoding="utf-8"):
            line = line.split("#")[0].strip()
            if line and not line.startswith("-r"):
                names.add(re.split(r"[<>=!~;\[ ]", line, maxsplit=1)[0].lower().replace("_", "-"))
    return names


def third_party(paths):
    std = set(sys.stdlib_module_names)
    test_modules = {os.path.splitext(f)[0] for f in os.listdir(os.path.join(ROOT, "tests"))}
    out = {}
    for f in py_files(paths):
        for mod in top_imports(f):
            if mod in std or mod in LOCAL or mod in test_modules or mod == "__future__":
                continue
            out.setdefault(DIST.get(mod, mod).lower().replace("_", "-"), set()).add(os.path.relpath(f, ROOT))
    return out


def test_application_imports_are_declared_in_requirements():
    have = declared("requirements.txt")
    missing = {k: sorted(v)[:3] for k, v in third_party(APP_SOURCES).items() if k not in have}
    assert not missing, f"imported but not in requirements.txt: {missing}"


def test_zoneinfo_data_is_declared_for_windows():
    uses_zoneinfo = any("zoneinfo" in set(top_imports(f)) for f in py_files(APP_SOURCES))
    assert not uses_zoneinfo or "tzdata" in declared("requirements.txt"), "zoneinfo needs the tzdata package on Windows"


def test_test_and_tool_imports_are_declared_in_requirements_dev():
    have = declared("requirements.txt", "requirements-dev.txt")
    missing = {k: sorted(v)[:3] for k, v in third_party(["tests", "tools"]).items() if k not in have and k != "pytest"}
    assert not missing, f"imported by tests/tools but not in requirements-dev.txt: {missing}"


@pytest.mark.parametrize("path", sorted(py_files(APP_SOURCES + ["tools"])), ids=lambda p: os.path.relpath(p, ROOT))
def test_no_top_level_name_is_defined_twice(path):
    tree = ast.parse(open(path, encoding="utf-8").read(), path)
    seen = {}
    dups = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in seen:
                dups.append(f"{node.name} (lines {seen[node.name]} and {node.lineno})")
            seen[node.name] = node.lineno
    assert not dups, f"defined twice (the second silently replaces the first): {dups}"


@pytest.mark.skipif(not shutil.which("node"), reason="Node.js not installed")
def test_every_javascript_file_parses():
    js_dir = os.path.join(ROOT, "web", "static", "js")
    bad = []
    for f in sorted(os.listdir(js_dir)):
        if f.endswith(".js"):
            r = subprocess.run(["node", "--check", os.path.join(js_dir, f)], capture_output=True, text=True)
            if r.returncode:
                bad.append(f"{f}: {r.stderr.strip()[:300]}")
    assert not bad, bad
