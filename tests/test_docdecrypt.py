"""Tests mit ausschließlich selbst erzeugten Dokumenten."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from msoffcrypto.format.ooxml import OOXMLFile

from docdecrypt.office import decrypt_to, extract_hash, is_encrypted
from docdecrypt.runner import run


def make_docx() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            "</Types>",
        )
        archive.writestr(
            "_rels/.rels",
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
            "</Relationships>",
        )
        archive.writestr(
            "word/document.xml",
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body><w:p><w:r><w:t>Prüfdokument</w:t></w:r></w:p></w:body></w:document>",
        )
        # Der Testcontainer muss größer als ein OLE-Mini-Stream sein.
        archive.writestr("word/test-padding.bin", b"x" * 5000)
    return output.getvalue()


class DocumentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.input_dir = self.root / "input"
        self.input_dir.mkdir()
        self.plain = self.input_dir / "plain.docx"
        self.plain.write_bytes(make_docx())
        self.encrypted = self.input_dir / "locked.docx"
        with self.encrypted.open("wb") as target:
            OOXMLFile(io.BytesIO(self.plain.read_bytes())).encrypt("Geheim123!", target)

    def test_recognition_hash_and_decryption(self) -> None:
        self.assertFalse(is_encrypted(self.plain))
        self.assertTrue(is_encrypted(self.encrypted))
        hash_value, mode = extract_hash(self.encrypted)
        self.assertTrue(hash_value.startswith("$office$*"))
        self.assertIn(mode, (9400, 9500, 9600))
        destination = self.root / "output.docx"
        self.assertFalse(decrypt_to(self.encrypted, destination, "falsch"))
        self.assertFalse(destination.exists())
        self.assertTrue(decrypt_to(self.encrypted, destination, "Geheim123!"))
        self.assertFalse(is_encrypted(destination))
        self.assertEqual(destination.read_bytes(), self.plain.read_bytes())

    def test_known_password_and_plain_copy(self) -> None:
        output = self.root / "output"
        state = output / ".docdecrypt" / "state"
        state.mkdir(parents=True)
        (state / "known.json").write_text(json.dumps({"completed": [], "password": "Geheim123!"}))
        self.assertEqual(run(self.input_dir, output, [], 1, False), 0)
        self.assertEqual((output / "plain.docx").read_bytes(), self.plain.read_bytes())
        self.assertFalse(is_encrypted(output / "locked.docx"))
        statuses = [json.loads(p.read_text()) for p in state.glob("*.json")]
        self.assertTrue(any(item.get("status") == "entschlüsselt" for item in statuses))

    def test_pause_then_resume_same_stage(self) -> None:
        output = self.root / "output"
        with patch("docdecrypt.runner.execute_stage", side_effect=[
            (None, False, None), ("Geheim123!", True, None),
        ]) as attack:
            self.assertEqual(run(self.input_dir, output, [], 30, False), 1)
            states = [json.loads(p.read_text()) for p in (output / ".docdecrypt" / "state").glob("*.json")]
            self.assertTrue(any(item.get("status") == "pausiert" for item in states))
            self.assertEqual(run(self.input_dir, output, [], 30, False), 0)
            self.assertEqual(attack.call_count, 2)
        self.assertFalse(is_encrypted(output / "locked.docx"))


if __name__ == "__main__":
    unittest.main()
