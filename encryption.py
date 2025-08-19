import os
from cryptography.fernet import Fernet, InvalidToken

def _load_fernet() -> Fernet:
    key = os.environ.get("FERNET_KEY")
    if not key:
        path = os.environ.get("FERNET_KEY_PATH", "fernet.key")
        if os.path.exists(path):
            with open(path, "rb") as f:
                key = f.read().strip()
        else:
            key = Fernet.generate_key()
            try:
                with open(path, "wb") as f:
                    f.write(key)
                print(f"Generated Fernet key at {path} (dev use).")
            except OSError:
                print("Could not write fernet.key; using in-memory key only.")
    if isinstance(key, str):
        key = key.encode()
    return Fernet(key)

_cipher = _load_fernet()

def encrypt_text(plain: str) -> str:
    if plain is None:
        plain = ""
    return _cipher.encrypt(plain.encode("utf-8")).decode("utf-8")

def decrypt_text(token: str) -> str:
    try:
        return _cipher.decrypt(token.encode("utf-8")).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""
