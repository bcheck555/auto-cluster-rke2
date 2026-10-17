"""Stage the pinned Rocky image; never modify libvirt or the host package set."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE_URL = "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/"
KEY_URL = "https://dl.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-9"


def download(url: str, destination: Path, limit: int) -> None:
    """Bound downloads and publish only complete files; preserve existing inputs."""
    if destination.exists() or destination.is_symlink():
        if not destination.is_file() or destination.is_symlink():
            raise ValueError(f"unsafe existing artifact: {destination}")
        return
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".stage-", delete=False) as output:
        partial = Path(output.name)
        try:
            with urllib.request.urlopen(url, timeout=120) as response:
                if not response.url.startswith("https://dl.rockylinux.org/"):
                    raise ValueError("download redirected outside the official HTTPS host")
                count = 0
                while chunk := response.read(1024 * 1024):
                    count += len(chunk)
                    if count > limit:
                        raise ValueError(f"download exceeds size limit: {url}")
                    output.write(chunk)
            output.flush()
            # Publish atomically without replacing a concurrently created input.
            os.link(partial, destination)
        finally:
            partial.unlink()


def main() -> None:
    os.chdir(ROOT)
    config = json.loads((ROOT / "lab/libvirt/rocky-source.json").read_text())
    image = config["image"]
    artifacts = ROOT / "lab/artifacts"
    artifacts.mkdir(mode=0o700, exist_ok=True)
    key_path = artifacts / "RPM-GPG-KEY-Rocky-9"
    download(KEY_URL, key_path, 64 * 1024)
    for field, suffix in (("checksum_path", ".CHECKSUM"), ("signature_path", ".CHECKSUM.asc")):
        download(BASE_URL + image["name"] + suffix, ROOT / image[field], 64 * 1024)
    with tempfile.TemporaryDirectory(prefix="rocky-key-") as home:
        result = subprocess.run(
            ["gpg", "--homedir", home, "--batch", "--with-colons", "--show-keys", str(key_path)],
            check=True, capture_output=True, text=True,
        )
        fingerprints = [line.split(":")[9] for line in result.stdout.splitlines() if line.startswith("fpr:")]
        if fingerprints != [image["signing_fingerprint"]]:
            raise ValueError("official key does not match the pinned fingerprint")
        subprocess.run(
            ["gpg", "--homedir", home, "--batch", "--import", str(key_path)],
            check=True, capture_output=True,
        )
        exported = subprocess.run(
            ["gpg", "--homedir", home, "--batch", "--export", image["signing_fingerprint"]],
            check=True, capture_output=True,
        ).stdout
        keyring = ROOT / image["keyring_path"]
        if keyring.exists():
            if keyring.is_symlink() or keyring.read_bytes() != exported:
                raise ValueError("existing keyring differs from the pinned official key")
        else:
            with keyring.open("xb") as output:
                output.write(exported)
        signed = subprocess.run(
            ["gpgv", "--homedir", home, "--status-fd=1", "--keyring", str(keyring),
             str(ROOT / image["signature_path"]), str(ROOT / image["checksum_path"])],
            check=True, capture_output=True, text=True,
        )
        if not any(line.startswith("[GNUPG:] VALIDSIG " + image["signing_fingerprint"] + " ")
                   for line in signed.stdout.splitlines()):
            raise ValueError("checksum signer differs from pinned fingerprint")
    # Never select a new digest implicitly: the tracked configuration is the pin.
    checksum = (ROOT / image["checksum_path"]).read_text().splitlines()
    expected = f"SHA256 ({image['name']}) = {image['sha256']}"
    if checksum.count(expected) != 1:
        raise ValueError("signed checksum differs from tracked image pin")
    destination = ROOT / image["staged_path"]
    download(BASE_URL + image["name"], destination, image["max_size_bytes"])
    with destination.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    if digest != image["sha256"]:
        raise ValueError("downloaded image checksum mismatch")
    report = {"image": image["name"], "bytes": destination.stat().st_size,
              "sha256": digest, "signer": image["signing_fingerprint"]}
    results = ROOT / "lab/results"
    results.mkdir(parents=True, exist_ok=True)
    (results / "rocky9-image-verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
