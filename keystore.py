"""Gestión del almacén de claves (KeyStore) guardado en un archivo JSON."""

import base64
import hashlib
import hmac
import json
import os

KEYSTORE_FILE = "keystore.json"


class KeystoreError(Exception):
    """El almacén existe pero está dañado o no se puede leer."""


def hash_password(password, salt=None):
    """Deriva un hash PBKDF2-HMAC-SHA256 de la contraseña con una sal aleatoria."""
    if salt is None:
        salt = os.urandom(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        200_000
    )

    return {
        "salt": base64.b64encode(salt).decode(),
        "hash": base64.b64encode(digest).decode()
    }


def check_password(password, stored):
    """Compara la contraseña con el hash guardado, en tiempo constante."""
    salt = base64.b64decode(stored["salt"])
    new_hash = hash_password(password, salt)["hash"]
    return hmac.compare_digest(new_hash, stored["hash"])


def create_keystore(password):
    """Devuelve un almacén nuevo y vacío protegido con la contraseña."""
    return {
        "keystore_password": hash_password(password),
        "keys": {}
    }


def is_valid_keystore(data):
    """Comprueba que el contenido leído tiene la estructura de un almacén."""
    if not isinstance(data, dict):
        return False

    password = data.get("keystore_password")
    keys = data.get("keys")

    if not isinstance(password, dict) or not isinstance(keys, dict):
        return False

    if not all(
        isinstance(password.get(field), str)
        for field in ("salt", "hash")
    ):
        return False

    # La sal debe ser Base64 válido; si no, lanza ValueError.
    base64.b64decode(password["salt"], validate=True)

    return all(
        isinstance(entry, dict) and all(
            isinstance(entry.get(field), str)
            for field in ("private_key", "public_key", "dname")
        )
        for entry in keys.values()
    )


def load_keystore():
    """
    Lee el almacén del disco.
    Devuelve None si no existe y lanza KeystoreError si está dañado.
    """
    if not os.path.exists(KEYSTORE_FILE):
        return None

    try:
        with open(KEYSTORE_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        if not is_valid_keystore(data):
            raise ValueError

        return data

    except (ValueError, OSError):
        raise KeystoreError(
            f"el almacén '{KEYSTORE_FILE}' está dañado o no se puede leer."
        )


def save_keystore(data):
    """Guarda el almacén en el disco."""
    with open(KEYSTORE_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)
