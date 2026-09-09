import hashlib
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

from package_release import package


class ReleaseArchiveTests(unittest.TestCase):
    def test_each_archive_contains_binary_docs_and_matching_sha256(self):
        for target in ["x86_64-unknown-linux-musl", "aarch64-apple-darwin", "x86_64-pc-windows-msvc"]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                binary = root / "built-binary"
                binary.write_bytes(b"test executable\0")
                (root / "LICENSE").write_text("MIT", encoding="utf-8")
                (root / "README.md").write_text("portsnap", encoding="utf-8")
                archive = package(binary, target, "v0.1.0-rc.1+build.7", root / "dist", root)
                if "windows" in target:
                    with zipfile.ZipFile(archive) as bundle:
                        self.assertEqual(set(bundle.namelist()), {"portsnap.exe", "README.md", "LICENSE"})
                        self.assertEqual(bundle.read("portsnap.exe"), binary.read_bytes())
                else:
                    with tarfile.open(archive) as bundle:
                        self.assertEqual(set(bundle.getnames()), {"portsnap", "README.md", "LICENSE"})
                        self.assertEqual(bundle.getmember("portsnap").mode, 0o755)
                        self.assertEqual(bundle.extractfile("portsnap").read(), binary.read_bytes())
                checksum = archive.with_name(archive.name + ".sha256").read_text().split()[0]
                self.assertEqual(checksum, hashlib.sha256(archive.read_bytes()).hexdigest())

    def test_invalid_version_cannot_escape_output_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for version in ["../../bad", "v01.2.3", "v1.2.3-01", "v1.2.3+", "v1.2.3-alpha..1"]:
                with self.subTest(version=version), self.assertRaises(ValueError):
                    package(root / "binary", "x86_64-unknown-linux-musl", version, root / "dist", root)


if __name__ == "__main__":
    unittest.main()
