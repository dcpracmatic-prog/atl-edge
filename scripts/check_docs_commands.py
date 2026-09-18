#!/usr/bin/env python3
"""Every command the docs tell a buyer to run must exist in the tree.

Why this exists: `docs/ANEXO_COMPRA.md` shipped a verification block telling the
buyer to run `testbench/red_team_bypass_v1.py`. The real file is
`redteam_bypass_v1.py`. Nothing failed, because nothing checked -- the buyer
would have found it, in the one document whose whole purpose is "do not believe
us, run it yourself". A document that invites verification and then hands over a
broken command is worse than no document.

Renaming a script is normal. Silently breaking the annex while doing it is not.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Docs a buyer or operator is told to follow. Internal notes are not in scope:
# they discuss history, including files that were deliberately deleted.
AUDITED_DOCS = [
    "docs/ANEXO_COMPRA.md",
    "docs/QUICKSTART.md",
    "docs/CONSOLE.md",
    "docs/MCP_CONNECTOR.md",
]

# `python <file>` / `bash <file>`, including env-var prefixes, inside the doc.
COMMAND_RE = re.compile(r"(?:python3?|bash)\s+([A-Za-z0-9_./-]+\.(?:py|sh))")

# Paths containing a placeholder the reader is meant to substitute.
PLACEHOLDER_MARKERS = ("<", ">", "{", "}", "...", "SU-", "su-")


def audit(doc_paths: list[str]) -> list[str]:
    problems: list[str] = []
    for rel in doc_paths:
        doc = ROOT / rel
        if not doc.exists():
            problems.append(f"{rel}: audited doc is missing")
            continue
        text = doc.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            for match in COMMAND_RE.finditer(line):
                target = match.group(1)
                if any(marker in target for marker in PLACEHOLDER_MARKERS):
                    continue
                if not (ROOT / target).exists():
                    problems.append(
                        f"{rel}:{lineno}: tells the reader to run {target}, "
                        "which does not exist"
                    )
    return problems


def self_test() -> int:
    """Inject a broken command into a temp copy and require a non-zero exit."""
    with tempfile.TemporaryDirectory() as tmp:
        fake_rel = "docs/_selftest_doc.md"
        fake = ROOT / fake_rel
        if fake.exists():  # pragma: no cover - defensive
            print("[FAIL] selftest scratch doc already exists")
            return 1
        del tmp
        fake.write_text(
            "# scratch\n\n```bash\npython testbench/does_not_exist_xyz.py\n```\n",
            encoding="utf-8",
        )
        try:
            problems = audit([fake_rel])
        finally:
            fake.unlink()
    if not problems:
        print("[FAIL] the guard did not notice a command that does not exist")
        return 1
    print(f"[PASS] the guard FAILS on a broken command: {problems[0]}")

    real = audit(AUDITED_DOCS)
    if real:
        print("[FAIL] the real docs do not pass their own guard:")
        for problem in real:
            print(f"    - {problem}")
        return 1
    print("[PASS] every command in the buyer-facing docs exists")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true",
                        help="prove the guard fails when a command is broken")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    problems = audit(AUDITED_DOCS)
    if problems:
        print("DOC COMMANDS: BROKEN")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"DOC COMMANDS: OK — {len(AUDITED_DOCS)} docs, every command exists")
    return 0


if __name__ == "__main__":
    sys.exit(main())
