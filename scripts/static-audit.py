#!/usr/bin/env python3
"""Small dependency-free static safety checks for this repository."""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ERRORS: list[str] = []
TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_-])[0-9]{6,12}:[A-Za-z0-9_-]{30,80}(?![A-Za-z0-9_-])")


def error(path: Path, line: int, message: str) -> None:
    ERRORS.append(f"{path.relative_to(ROOT)}:{line}: {message}")


for path in sorted((ROOT / "src").glob("*.py")):
    text = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        error(path, exc.lineno or 1, f"syntax error: {exc.msg}")
        continue

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = ""
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name in {"eval", "exec"}:
                error(path, node.lineno, f"forbidden dynamic execution: {name}")
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "os" and node.func.attr in {"system", "popen"}:
                    error(path, node.lineno, f"forbidden os.{node.func.attr}")
                if node.func.value.id == "subprocess":
                    for keyword in node.keywords:
                        if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                            error(path, node.lineno, "subprocess shell=True is forbidden")

for path in sorted(ROOT.rglob("*")):
    if not path.is_file() or ".git" in path.parts or path.suffix in {".zip", ".pyc"}:
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    if TOKEN_RE.search(text):
        error(path, 1, "possible committed Telegram bot token")
    if path.suffix == ".sh" and re.search(r"\bchmod\s+777\b", text):
        error(path, 1, "chmod 777 is forbidden")

if ERRORS:
    print("\n".join(ERRORS), file=sys.stderr)
    raise SystemExit(1)
print("Static audit passed")

