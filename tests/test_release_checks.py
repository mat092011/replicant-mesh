"""Release checks must reject missing references and accidental artifacts."""

from pathlib import Path
import tempfile
import unittest

from scripts.check_release import check_files, tree_digest


class ReleaseChecksTests(unittest.TestCase):
    def test_missing_local_link_fails_but_external_and_anchor_links_do_not(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text(
                '[Local](missing.md) [Web](https://example.com/page) [Here](#section)\n',
                encoding='utf-8')
            result = check_files(root, ['README.md'])
            self.assertEqual(result['local_links'], 1)
            self.assertEqual(result['errors'], ['README.md: missing local link missing.md'])

    def test_encoded_local_filename_is_resolved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'My guide.md').write_text('Guide\n', encoding='utf-8')
            (root / 'README.md').write_text('[Guide](My%20guide.md#setup)\n', encoding='utf-8')
            self.assertEqual(check_files(root, ['README.md'])['errors'], [])

    def test_artifacts_and_whitespace_are_reported_without_file_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.env').write_text('PRIVATE_VALUE=example\n', encoding='utf-8')
            (root / 'model.bin').write_bytes(b'weights\n')
            (root / 'README.md').write_text('Text  \nNo newline', encoding='utf-8')
            errors = check_files(root, ['.env', 'model.bin', 'README.md'])['errors']
            self.assertEqual(len(errors), 4)
            self.assertNotIn('PRIVATE_VALUE', str(errors))

    def test_digest_changes_with_contents_and_filenames(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'first.txt').write_text('First\n', encoding='utf-8')
            first = tree_digest(root, ['first.txt'])
            (root / 'first.txt').write_text('Second\n', encoding='utf-8')
            self.assertNotEqual(first, tree_digest(root, ['first.txt']))
            (root / 'second.txt').write_text('First\n', encoding='utf-8')
            self.assertNotEqual(first, tree_digest(root, ['second.txt']))
