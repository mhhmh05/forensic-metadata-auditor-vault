import hashlib

def calculate_hashes(file_path: str) -> tuple[str, str]:
    """Generates MD5 and SHA-256 hashes for forensic chain-of-custody."""
    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()
    
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
                md5_hash.update(byte_block)
        return sha256_hash.hexdigest(), md5_hash.hexdigest()
    except Exception as e:
        return str(e), str(e)