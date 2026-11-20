
import os
import json
import base64
import shutil
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "dist"

KEY_NAME = "ALAMMNA_ENCRYPTION_KEY"

SKIP_DIRS = {
    ".git",
    ".github",
    "dist",
    "node_modules",
    ".venv",
    "__pycache__",
}

def should_encrypt(path):
    name = path.name.lower()

    if path.suffix.lower() == ".py":
        return False

    if name == "requirements.txt":
        return False

    return True


def main():
    encoded_key = os.environ.get(KEY_NAME)

    if not encoded_key:
        raise RuntimeError(
            f"Missing environment variable: {KEY_NAME}"
        )

    try:
        key = base64.b64decode(
            encoded_key,
            validate=True
        )
    except Exception:
        raise RuntimeError(
            "Encryption key is not valid Base64"
        )

    if len(key) != 32:
        raise RuntimeError(
            "Encryption key must be 32 bytes"
        )

    if OUTPUT.exists():
        shutil.rmtree(OUTPUT)

    aes = AESGCM(key)
    count = 0

    for current, dirs, files in os.walk(ROOT):

        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS
            and not d.startswith(".")
        ]

        current_path = Path(current)
        relative_dir = current_path.relative_to(ROOT)

        for filename in files:

            source = current_path / filename
            relative_path = relative_dir / filename

            if source.resolve() == Path(__file__).resolve():
                continue

            destination = OUTPUT / relative_path
            destination.parent.mkdir(
                parents=True,
                exist_ok=True
            )

            if not should_encrypt(source):
                shutil.copy2(source, destination)
                print(f"Copied: {relative_path}")
                continue

            raw = source.read_bytes()

            nonce = os.urandom(12)

            encrypted = aes.encrypt(
                nonce,
                raw,
                None
            )

            payload = {
                "version": 1,
                "algorithm": "AES-256-GCM",
                "nonce": base64.b64encode(
                    nonce
                ).decode("ascii"),
                "data": base64.b64encode(
                    encrypted
                ).decode("ascii"),
            }

            destination.write_text(
                json.dumps(
                    payload,
                    separators=(",", ":")
                ),
                encoding="utf-8"
            )

            count += 1

            print(f"Encrypted: {relative_path}")

    if count == 0:
        raise RuntimeError(
            "No files were encrypted"
        )

    print(
        f"Build completed. Encrypted {count} files."
    )


if __name__ == "__main__":
    main()
