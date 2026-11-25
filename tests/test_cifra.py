import io
import os
import struct
import tarfile
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import spec_from_loader, module_from_spec
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CIFRA_PATH = os.path.join(REPO_ROOT, "cifra.py")
if not os.path.exists(CIFRA_PATH):
    CIFRA_PATH = os.path.join(REPO_ROOT, "cifra")

loader = SourceFileLoader("cifra_mod", CIFRA_PATH)
spec = spec_from_loader("cifra_mod", loader)
cifra = module_from_spec(spec)
loader.exec_module(cifra)


def make_symlink_or_skip(test_case, src, dst):
    try:
        os.symlink(src, dst)
    except OSError as e:
        if getattr(e, "winerror", None) == 1314:
            test_case.skipTest("Symlink privilege not enabled on Windows (enable Developer Mode)")
        raise


class TestCifra(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base = self.tmp_dir.name
        self.keyfile = os.path.join(self.base, "secret.key")
        with open(self.keyfile, "wb") as f:
            f.write(b"\x42" * 64)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_file_roundtrip_and_permissions(self):
        src = os.path.join(self.base, "document.txt")
        enc = os.path.join(self.base, "document.txt.enc")
        dec = os.path.join(self.base, "restored.txt")
        payload = b"Confidential data block " * 5000

        with open(src, "wb") as f:
            f.write(payload)

        cifra.main(["encrypt", "-k", self.keyfile, "-o", enc, src])
        self.assertTrue(os.path.isfile(enc))
        if os.name != "nt":
            mode = os.stat(enc).st_mode & 0o777
            self.assertEqual(mode, 0o600)

        cifra.main(["decrypt", "-k", self.keyfile, "-o", dec, enc])
        with open(dec, "rb") as f:
            self.assertEqual(f.read(), payload)

    def test_directory_roundtrip_excludes(self):
        folder = os.path.join(self.base, "project")
        os.makedirs(os.path.join(folder, "sub"))
        with open(os.path.join(folder, "keep.txt"), "w") as f:
            f.write("keep me")
        with open(os.path.join(folder, "debug.log"), "w") as f:
            f.write("ignore me")

        enc = os.path.join(self.base, "project.enc")
        dec_tar = os.path.join(self.base, "project.tar")

        cifra.main(["encrypt", "-k", self.keyfile, "-e", "*.log", "-o", enc, folder])
        cifra.main(["decrypt", "-k", self.keyfile, "-o", dec_tar, enc])

        with tarfile.open(dec_tar, "r") as tar:
            names = tar.getnames()
            self.assertIn("project/keep.txt", names)
            self.assertNotIn("project/debug.log", names)

    def test_directory_skips_symlinks(self):
        folder = os.path.join(self.base, "project_sym")
        os.makedirs(folder)
        with open(os.path.join(folder, "keep.txt"), "w") as f:
            f.write("keep me")
        make_symlink_or_skip(self, os.path.join(folder, "keep.txt"), os.path.join(folder, "evil_link"))

        enc = os.path.join(self.base, "project_sym.enc")
        dec_tar = os.path.join(self.base, "project_sym.tar")

        cifra.main(["encrypt", "-k", self.keyfile, "-o", enc, folder])
        cifra.main(["decrypt", "-k", self.keyfile, "-o", dec_tar, enc])

        with tarfile.open(dec_tar, "r") as tar:
            names = tar.getnames()
            self.assertIn("project_sym/keep.txt", names)
            self.assertNotIn("project_sym/evil_link", names)

    def test_wrong_key_and_tamper_detection(self):
        src = os.path.join(self.base, "data.bin")
        enc = os.path.join(self.base, "data.bin.enc")
        dec = os.path.join(self.base, "data.bin.dec")
        wrong_key = os.path.join(self.base, "wrong.key")

        with open(src, "wb") as f:
            f.write(b"Top secret payload")
        with open(wrong_key, "wb") as f:
            f.write(b"\x99" * 64)

        cifra.main(["encrypt", "-k", self.keyfile, "-o", enc, src])

        # Wrong key must exit with code 2 (AuthenticationError)
        with self.assertRaises(SystemExit) as cm:
            cifra.main(["decrypt", "-k", wrong_key, "-o", dec, enc])
        self.assertEqual(cm.exception.code, 2)
        self.assertFalse(os.path.exists(dec))

        # Tampering 1 byte in the AAD header must also fail authentication
        with open(enc, "rb") as f:
            raw = bytearray(f.read())
        raw[6] ^= 0x01  # Flip a bit in reserved header bytes
        with open(enc, "wb") as f:
            f.write(raw)

        with self.assertRaises(SystemExit) as cm:
            cifra.main(["decrypt", "-k", self.keyfile, "-o", dec, enc])
        self.assertEqual(cm.exception.code, 2)

    def test_legacy_enc2_compatibility(self):
        plaintext = b"Legacy ENC2 test vector"
        n, r, p = 16384, 8, 1
        salt = b"\x11" * 16
        nonce = b"\x22" * 12
        with open(self.keyfile, "rb") as kf:
            pwd_bytes = kf.read()

        key = cifra.get_key(pwd_bytes, salt, n, r, p)
        header = struct.pack(cifra.HEADER_ENC2_FORMAT, b"ENC2", 0, n, r, p, salt, nonce)
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(header)
        ct = encryptor.update(plaintext) + encryptor.finalize()

        legacy_file = os.path.join(self.base, "legacy.enc")
        restored = os.path.join(self.base, "legacy.txt")
        with open(legacy_file, "wb") as f:
            f.write(header + ct + encryptor.tag)

        cifra.main(["decrypt", "-k", self.keyfile, "-o", restored, legacy_file])
        with open(restored, "rb") as f:
            self.assertEqual(f.read(), plaintext)

    def test_same_file_and_hardlink_guards(self):
        src = os.path.join(self.base, "source.txt")
        with open(src, "wb") as f:
            f.write(b"important")

        # 1. Same file overwrite blocked
        with self.assertRaises(cifra.PathValidationError):
            cifra.validate_output(src, target=src, force=True)

        # 2. Hard link overwrite blocked
        hard = os.path.join(self.base, "hardlink.txt")
        os.link(src, hard)
        with self.assertRaises(cifra.PathValidationError):
            cifra.validate_output(hard, target=src, force=True)

    def test_symlink_output_and_ancestor_guards(self):
        # 1. Direct symlink output blocked
        sym = os.path.join(self.base, "sym.enc")
        make_symlink_or_skip(self, os.path.join(self.base, "real.enc"), sym)
        with self.assertRaises(cifra.PathValidationError):
            cifra.validate_output(sym, force=True)

        # 2. Nested symlink ancestor blocked
        real_dir = os.path.join(self.base, "real_dir")
        os.makedirs(real_dir)
        link_dir = os.path.join(self.base, "link_dir")
        os.symlink(real_dir, link_dir)
        nested_out = os.path.join(link_dir, "sub", "out.enc")
        with self.assertRaises(cifra.PathValidationError):
            cifra.validate_output(nested_out, force=True)

    def test_stream_pipe_roundtrip(self):
        plaintext = b"Streaming binary payload over pipes \x00\xff\x10" * 1000
        enc_buf = io.BytesIO()
        dec_buf = io.BytesIO()

        class FakeStdStream:
            def __init__(self, buf):
                self.buffer = buf

        with patch.object(cifra.sys, "stdin", FakeStdStream(io.BytesIO(plaintext))), \
             patch.object(cifra.sys, "stdout", FakeStdStream(enc_buf)):
            cifra.main(["encrypt", "-k", self.keyfile, "-"])

        ciphertext = enc_buf.getvalue()
        self.assertTrue(ciphertext.startswith(b"CFRA"))

        with patch.object(cifra.sys, "stdin", FakeStdStream(io.BytesIO(ciphertext))), \
             patch.object(cifra.sys, "stdout", FakeStdStream(dec_buf)):
            cifra.main(["decrypt", "-k", self.keyfile, "-"])

        self.assertEqual(dec_buf.getvalue(), plaintext)


if __name__ == "__main__":
    unittest.main()