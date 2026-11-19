#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CHECKER = Path(__file__).with_name("check-module-entrypoints.py")


class ModuleEntrypoints(unittest.TestCase):
    def check_source(self, source):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            example = root / "crates" / "sample" / "examples" / "support"
            example.mkdir(parents=True)
            (example / "mod.rs").write_text(source, encoding="utf-8")
            for build in (root / "target", root / "fuzz" / "target"):
                build.mkdir(parents=True)
                (build / "mod.rs").write_text("fn generated() {}", encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(CHECKER), "--root", directory],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_declarations_with_nested_groups_and_attributes(self):
        source = """
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Module documentation.
/* outer /* nested fn hidden() {} */ still a comment */
#[cfg(any(unix, feature = "test"))]
#[cfg_attr(unix, path = r##"path/[file]/*"##)]
pub(crate) mod cfg_impl;
#[doc = "an escaped quote: \\" and braces: { }"]
pub(in crate::outer) use super::{
    first,
    nested::{self as alias, r#type, *},
};
#[meta("(", br#"}"#, c"[", b'}', '\\u{7d}', 'a)]
pub use ::external::Résumé as renamed;
pub(super) use crate::hidden as _;
"""
        result = self.check_source(source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Checked 1", result.stdout)

    def test_rust_unicode_whitespace(self):
        result = self.check_source("pub\u200euse\u200fcrate\u2028::\u0085Example;")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_implementation_and_private_imports(self):
        for item in (
            "fn function() {}",
            "pub struct Item;",
            "enum Item {}",
            "union Item { x: u8 }",
            "pub trait Trait {}",
            "impl Item {}",
            "const VALUE: u8 = 0;",
            "static VALUE: u8 = 0;",
            "type Value = u8;",
            "macro_rules! item { () => {}; }",
            "include!(\"implementation.rs\");",
            "use super::Item;",
            "pub(self) use super::Item;",
            "mod inline { pub use super::Item; }",
        ):
            with self.subTest(item=item):
                result = self.check_source(f"mod first;\n#[cfg(test)]\n{item}\n")
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("crates/sample/examples/support/mod.rs:3:", result.stderr)

    def test_rejects_non_declarations_after_a_reexport(self):
        result = self.check_source("pub use crate::{A, b::{C as D, E}};\nfn extra() {}\n")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("mod.rs:2:", result.stderr)

    def test_rejects_unattached_attributes_and_unterminated_input(self):
        for source in (
            "#[cfg(test)]",
            '#[doc = r#"unterminated',
            '#[doc = "unterminated] mod item;',
            "/* unterminated",
            "pub use crate::{A",
        ):
            with self.subTest(source=source):
                result = self.check_source(source)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn("mod.rs:1:", result.stderr)


if __name__ == "__main__":
    unittest.main()
