import hashlib


def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)

        return sha256.hexdigest()

    except Exception as e:
        print(f"[ERROR] Hashing failed for {file_path}: {e}")
        return None
