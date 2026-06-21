from __future__ import annotations

import argparse
from pathlib import Path


def strip_solidity_comments(text: str) -> str:
    result: list[str] = []
    i = 0
    n = len(text)
    in_line_comment = False
    in_block_comment = False
    in_string: str | None = None

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                result.append(ch)
            i += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            if ch == "\n":
                result.append(ch)
            i += 1
            continue

        if in_string:
            result.append(ch)
            if ch == "\\" and i + 1 < n:
                result.append(text[i + 1])
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue

        if ch in {"'", '"'}:
            in_string = ch
            result.append(ch)
            i += 1
            continue

        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue

        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue

        result.append(ch)
        i += 1

    return "".join(result)


def collapse_blank_lines(text: str, max_consecutive_blank_lines: int = 1) -> str:
    lines = text.splitlines()
    collapsed: list[str] = []
    blank_run = 0

    for line in lines:
        if line.strip():
            blank_run = 0
            collapsed.append(line.rstrip())
            continue

        blank_run += 1
        if blank_run <= max_consecutive_blank_lines:
            collapsed.append("")

    collapsed_text = "\n".join(collapsed).strip() + "\n"
    return collapsed_text


def process_file(path: Path) -> bool:
    original = path.read_text(encoding="utf-8", errors="ignore")
    stripped = strip_solidity_comments(original)
    stripped = collapse_blank_lines(stripped, max_consecutive_blank_lines=1)
    if stripped == original:
        return False
    path.write_text(stripped, encoding="utf-8")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recursively remove Solidity comments from files under a directory."
    )
    parser.add_argument(
        "-d",
        "--dataset-dir",
        default="dataset",
        help="Root directory to search recursively (default: dataset)",
    )
    parser.add_argument(
        "-e",
        "--extension",
        default=".sol",
        help="File extension to process recursively (default: .sol)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only report matching files without modifying them",
    )
    args = parser.parse_args()

    root = Path(args.dataset_dir)
    if not root.exists() or not root.is_dir():
        raise SystemExit(f"Dataset directory not found: {root}")

    extension = args.extension if args.extension.startswith(".") else f".{args.extension}"
    files = sorted(path for path in root.rglob(f"*{extension}") if path.is_file())

    if not files:
        print(f"No {extension} files found under {root}")
        return

    changed = 0
    for path in files:
        if args.dry_run:
            print(path)
            continue
        if process_file(path):
            changed += 1
            print(f"updated: {path}")

    if args.dry_run:
        print(f"found {len(files)} file(s) with extension {extension} under {root}")
    else:
        print(f"processed {len(files)} file(s), updated {changed} file(s)")


if __name__ == "__main__":
    main()
