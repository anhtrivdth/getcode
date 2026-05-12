import base64
import hashlib
import hmac
from cryptography.fernet import Fernet

from app.config import get_settings


settings = get_settings()


def hash_key(key_plain: str) -> str:
    secret = settings.key_hash_secret.encode("utf-8")
    return hmac.new(secret, key_plain.encode("utf-8"), hashlib.sha256).hexdigest()


def mask_email(email: str) -> str:
    try:
        local, domain = email.split("@", 1)
    except ValueError:
        return "***"
    head = local[:2] if len(local) > 2 else local[:1]
    return f"{head}***@{domain}"


def _fernet() -> Fernet:
    if settings.credential_encrypt_key:
        key = settings.credential_encrypt_key.encode("utf-8")
        return Fernet(key)
    fallback = hashlib.sha256(settings.key_hash_secret.encode("utf-8")).digest()
    key = base64.urlsafe_b64encode(fallback)
    return Fernet(key)


def encrypt_secret(raw: str) -> str:
    return _fernet().encrypt(raw.encode("utf-8")).decode("utf-8")


def decrypt_secret(cipher: str) -> str:
    return _fernet().decrypt(cipher.encode("utf-8")).decode("utf-8")
