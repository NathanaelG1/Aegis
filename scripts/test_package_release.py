"""Release checksum regression checks; no Rust toolchain or native binary needed."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import package_release


class ReleaseChecksumTests(unittest.TestCase):
    def test_packaging_emits_portable_checksum_under_windows_text_translation(self):
        original_write_text = Path.write_text

        def windows_write_text(file, data, encoding=None, errors=None, newline=None):
            return original_write_text(
                file, data, encoding=encoding, errors=errors,
                newline="\r\n" if newline is None else newline,
            )

        for target, features in (
            ("x86_64-pc-windows-msvc", ""),
            ("x86_64-unknown-linux-gnu", "sprite-demo"),
        ):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "Cargo.toml").write_text('[package]\nversion = "0.0.2"\n')
                for filename in ("README.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "SECURITY.md"):
                    (root / filename).write_text("Fixture\n")
                (root / "docs").mkdir()
                (root / "docs/releases.md").write_text("Install fixture\n")
                (root / "scripts").mkdir()
                (root / "scripts/sprite_client.py").write_text("# Fixture\n")
                windows = "windows" in target
                binary = root / "target" / target / "release" / ("aegis.exe" if windows else "aegis")
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b"synthetic packaging fixture")

                # Simulate Windows' default text-file newline behavior on every
                # CI host, including the Linux job that ultimately publishes.
                with patch.object(Path, "write_text", windows_write_text), \
                     patch.object(package_release, "ROOT", root), \
                     patch.object(package_release.subprocess, "check_output", side_effect=["fixture-commit\n", "rustc fixture\n"]), \
                     patch.object(package_release, "smoke_test"):
                    package_release.package("v0.0.2", target, features)

                extension = ".zip" if windows else ".tar.gz"
                archive = root / "dist" / f"aegis-v0.0.2-{target}{extension}"
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                checksum = archive.with_name(archive.name + ".sha256").read_bytes()
                self.assertEqual(checksum, f"{digest}  {archive.name}\n".encode("ascii"))
                self.assertNotIn(b"\r", checksum)


if __name__ == "__main__":
    unittest.main()
