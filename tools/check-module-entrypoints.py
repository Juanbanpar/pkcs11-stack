#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check the restricted Rust item grammar allowed in mod.rs files."""

import argparse
import os
from pathlib import Path
import re
import sys
from typing import NamedTuple


class Token(NamedTuple):
    text: str
    line: int


class Violation(Exception):
    def __init__(self, line, message):
        super().__init__(message)
        self.line = line


COMMENT_MARKER = re.compile(r"/\*|\*/")
RAW_STRING = re.compile(r'(?:br|cr|r)(#*)"')
QUOTED_STRING = re.compile(r'(?:b|c)?"(?:[^"\\]|\\[\s\S])*"')
CHARACTER = re.compile(r"(?:b)?'(?:[^'\\\n]|\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]+\}|[^\n]))'")
# Rust token separators use Unicode Pattern_White_Space.
WHITESPACE = re.compile(r"[\t\n\v\f\r \u0085\u200e\u200f\u2028\u2029]+")
DELIMITERS = {"(": ")", "[": "]", "{": "}"}


def block_comment_end(source, start, line):
    depth = 1
    for match in COMMENT_MARKER.finditer(source, start + 2):
        depth += 1 if match[0] == "/*" else -1
        if depth == 0:
            return match.end()
    raise Violation(line, "unterminated block comment")


def identifier(text):
    return text.removeprefix("r#").isidentifier()


def tokens(source):
    cursor, line = 0, 1
    while cursor < len(source):
        start = cursor
        if space := WHITESPACE.match(source, start):
            cursor = space.end()
        elif source.startswith("//", start):
            cursor = source.find("\n", start)
            if cursor == -1:
                cursor = len(source)
        elif source.startswith("/*", start):
            cursor = block_comment_end(source, start, line)
        elif raw := RAW_STRING.match(source, start):
            closing = '"' + raw[1]
            end = source.find(closing, raw.end())
            if end == -1:
                raise Violation(line, "unterminated raw string literal")
            cursor = end + len(closing)
            yield Token("<literal>", line)
        elif literal := QUOTED_STRING.match(source, start) or CHARACTER.match(source, start):
            cursor = literal.end()
            yield Token("<literal>", line)
        elif source.startswith(('"', 'b"', 'c"'), start):
            raise Violation(line, "unterminated string literal")
        elif source.startswith("::", start):
            cursor += 2
            yield Token("::", line)
        else:
            name = start + 2 if source.startswith("r#", start) else start
            if name < len(source) and source[name].isidentifier():
                cursor = name + 1
                while cursor < len(source) and ("a" + source[cursor]).isidentifier():
                    cursor += 1
            else:
                cursor += 1
            yield Token(source[start:cursor], line)
        line += source.count("\n", start, cursor)
    yield Token("", line)


class Entrypoint:
    def __init__(self, source):
        self.tokens = iter(tokens(source))
        self.current = next(self.tokens)

    def advance(self):
        self.current = next(self.tokens)

    def take(self, text):
        if self.current.text == text:
            self.advance()
            return True
        return False

    def expect(self, text):
        if not self.take(text):
            raise Violation(self.current.line, f"expected {text!r}")

    def expect_identifier(self):
        if not identifier(self.current.text):
            raise Violation(self.current.line, "expected an identifier")
        self.advance()

    def attribute(self):
        # Outer attributes are token trees and can contain nested expressions.
        self.expect("[")
        stack = ["]"]
        while stack:
            text, line = self.current
            if not text:
                raise Violation(line, "unterminated attribute")
            if text in DELIMITERS:
                stack.append(DELIMITERS[text])
            elif text in DELIMITERS.values():
                if text != stack.pop():
                    raise Violation(line, "mismatched attribute delimiters")
            self.advance()

    def visibility(self):
        if not self.take("pub"):
            return False
        reexport = True
        if self.take("("):
            restricted_path = self.take("in")
            reexport = self.current.text != "self"
            if restricted_path:
                self.expect_identifier()
                while self.take("::"):
                    self.expect_identifier()
            else:
                if self.current.text not in {"crate", "self", "super"}:
                    raise Violation(self.current.line, "invalid visibility restriction")
                self.advance()
            self.expect(")")
        return reexport

    def use_tree(self):
        self.take("::")
        while identifier(self.current.text):
            self.advance()
            if not self.take("::"):
                if self.take("as"):
                    self.expect_identifier()
                return
        if self.take("*"):
            return
        self.expect("{")
        while not self.take("}"):
            self.use_tree()
            if self.take("}"):
                return
            self.expect(",")

    def check(self):
        while self.current.text:
            while self.take("#"):
                self.attribute()
            public = self.visibility()
            if self.take("mod"):
                self.expect_identifier()
                self.expect(";")
            elif public and self.take("use"):
                self.use_tree()
                self.expect(";")
            else:
                raise Violation(self.current.line, "only module declarations and re-exports are allowed")


def entrypoints(root):
    for directory, subdirs, files in os.walk(root):
        directory = Path(directory)
        # Cargo output directories can contain packaged copies or generated sources.
        if directory == root:
            subdirs[:] = [name for name in subdirs if name not in {".git", "target"}]
        if directory == root / "fuzz" and "target" in subdirs:
            subdirs.remove("target")
        if "mod.rs" in files:
            yield directory / "mod.rs"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    root = parser.parse_args().root.resolve()
    failed = False
    paths = sorted(entrypoints(root))
    for path in paths:
        try:
            Entrypoint(path.read_text(encoding="utf-8-sig")).check()
        except Violation as error:
            print(f"{path.relative_to(root)}:{error.line}: {error}", file=sys.stderr)
            failed = True
        except (OSError, UnicodeError) as error:
            print(f"{path.relative_to(root)}: {error}", file=sys.stderr)
            failed = True
    if failed:
        return 1
    print(f"Checked {len(paths)} declaration-only mod.rs files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
