import hashlib
import hmac
import secrets


def generate_salt(n: int = 16) -> bytes:
    """Generate a cryptographically random salt."""
    return secrets.token_bytes(n)


def hash_password(password: str, salt: bytes) -> str:
    """
    Compute hex(SHA256(salt || password)).
    salt: bytes
    password: str (UTF-8)
    """
    if isinstance(password, str):
        password = password.encode("utf-8")
    digest = hashlib.sha256(salt + password).hexdigest()
    return digest


def verify_password(stored_salt: bytes, stored_hash: str, candidate_password: str) -> bool:
    """Compare stored hash with hash(salt || candidate_password) in constant time."""
    candidate_hash = hash_password(candidate_password, stored_salt)
    return hmac.compare_digest(stored_hash, candidate_hash)
