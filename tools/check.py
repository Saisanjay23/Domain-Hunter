"""
One command that runs every check, with the same fixed rules for everyone:

    python tools/check.py            # lint + JavaScript syntax + full test suite (incl. browser tests when available)
    python tools/check.py --quick    # lint + JavaScript syntax + tests without the browser suite
    python tools/check.py --live     # also run storage / scheduler / reset tests against a real MongoDB
                                     # (BRAND_HUNTER_TEST_MONGO_URI, default mongodb://127.0.0.1:27017; throwaway databases)

Exit code 0 only when every step passed. Lint never auto-fixes (see ruff.toml: auto-fixing with a partial rule set
deletes `# noqa` markers).
"""

import argparse
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def step(name, cmd, env=None):
    t = time.time()
    print(f"\n== {name}", flush=True)
    r = subprocess.run(cmd, cwd=ROOT, env={**os.environ, **(env or {})})
    ok = r.returncode == 0
    print(f"-- {name}: {'OK' if ok else 'FAILED'} ({time.time() - t:.1f} s)", flush=True)
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="skip the browser (Playwright) tests")
    ap.add_argument("--live", action="store_true", help="also test against a real MongoDB")
    args = ap.parse_args()
    py = sys.executable
    results = {"lint (ruff)": step("lint (ruff)", [py, "-m", "ruff", "check", "--no-cache", "."])}
    if shutil.which("node"):
        js = [py, "-c", "import glob, subprocess, sys; bad = [f for f in glob.glob('web/static/js/*.js') if subprocess.run(['node', '--check', f]).returncode]; sys.exit(1 if bad else 0)"]
        results["javascript syntax"] = step("javascript syntax", js)
    tests = [py, "-m", "pytest", "-q", "-p", "no:cacheprovider"] + (["-m", "not ui"] if args.quick else [])
    results["tests"] = step("tests (in-memory MongoDB)", tests)
    if args.live:
        uri = os.environ.get("BRAND_HUNTER_TEST_MONGO_URI", "mongodb://127.0.0.1:27017")
        results["live MongoDB"] = step(f"storage, scheduler and reset tests on {uri.split('@')[-1]}",
                                       [py, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_mongo.py", "tests/test_scheduler.py", "tests/test_reset.py"],
                                       env={"BRAND_HUNTER_TEST_MONGO_URI": uri})
    print("\nSummary: " + ", ".join(f"{k} {'OK' if v else 'FAILED'}" for k, v in results.items()))
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
