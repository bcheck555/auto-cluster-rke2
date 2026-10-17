from __future__ import annotations

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lab.libvirt.stage_image import download


class StageDownloadTests(unittest.TestCase):
    def response(self, data: bytes, url: str = "https://dl.rockylinux.org/image") -> io.BytesIO:
        response = io.BytesIO(data)
        response.url = url
        return response

    def test_rejects_oversized_download_without_publishing_or_leaving_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "image"
            with patch("urllib.request.urlopen", return_value=self.response(b"too big")):
                with self.assertRaisesRegex(ValueError, "size limit"):
                    download("https://dl.rockylinux.org/image", destination, 2)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_rejects_redirect_outside_official_https_host(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "image"
            with patch("urllib.request.urlopen", return_value=self.response(b"data", "https://example.org/image")):
                with self.assertRaisesRegex(ValueError, "redirected"):
                    download("https://dl.rockylinux.org/image", destination, 100)
            self.assertFalse(destination.exists())

    def test_preserves_existing_artifact_without_network_access(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "image"
            destination.write_bytes(b"existing")
            with patch("urllib.request.urlopen") as fetch:
                download("https://dl.rockylinux.org/image", destination, 100)
                fetch.assert_not_called()
            self.assertEqual(destination.read_bytes(), b"existing")

    def test_rejects_dangling_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "image"
            destination.symlink_to(Path(directory) / "missing")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                download("https://dl.rockylinux.org/image", destination, 100)

    def test_publishes_complete_download(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "image"
            with patch("urllib.request.urlopen", return_value=self.response(b"image data")):
                download("https://dl.rockylinux.org/image", destination, 100)
            self.assertEqual(destination.read_bytes(), b"image data")
            self.assertEqual(list(Path(directory).iterdir()), [destination])
