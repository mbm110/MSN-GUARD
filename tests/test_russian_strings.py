"""Static checks for the Russian catalog and language picker."""
import collections
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = ROOT / "app/src/main/java/com/msnguard/vpn"
SOURCE = (APP / "Strings.kt").read_text()
RUSSIAN = (APP / "RussianStrings.kt").read_text()
LANGUAGE = (APP / "AppLanguage.kt").read_text()

LITERAL = r'"((?:[^"\\]|\\.)*)"'
SOURCE_KEYS = re.findall(LITERAL + r"\s+to\s+Triple\(", SOURCE)
RUSSIAN_ROWS = re.findall(LITERAL + r"\s+to\s+" + LITERAL + r"\s*,", RUSSIAN)
PLACEHOLDERS = re.compile(r"%(?:\d+\$)?[sdf]|%%")


class RussianStringsContract(unittest.TestCase):
    def test_catalog_covers_source_without_duplicate_keys(self):
        keys = [key for key, _ in RUSSIAN_ROWS]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(set(keys), set(SOURCE_KEYS))
        self.assertEqual(len(keys), 793)

    def test_placeholders_and_russian_copy(self):
        for key, value in RUSSIAN_ROWS:
            with self.subTest(key=key):
                self.assertTrue(value.strip())
                self.assertEqual(collections.Counter(PLACEHOLDERS.findall(key)),
                                 collections.Counter(PLACEHOLDERS.findall(value)))
                if re.search(r"[A-Za-z]{3,}", key) and key != value:
                    self.assertTrue(re.search(r"[А-Яа-яЁё]", value), value)

    def test_picker_and_dispatch(self):
        self.assertIn('listOf("en", "fa", "zh", "ru")', LANGUAGE)
        self.assertIn('"ru" -> "Русский"', LANGUAGE)
        self.assertIn('if (l == "ru") return RussianStrings.t(english)', SOURCE)


if __name__ == "__main__":
    unittest.main()
