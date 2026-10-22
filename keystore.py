"""
Gestión del almacén de claves (KeyStore).

El almacén se guarda en un archivo binario cifrado entero con la contraseña
del KeyStore, de modo que al abrirlo no se puede leer nada.

Formato del archivo:
    MAGIC (4 bytes) | sal (16 bytes) | nonce (12 bytes) | datos cifrados

- La clave de cifrado se deriva de la contraseña con PBKDF2-HMAC-SHA256.
- Los datos se cifran con AES-256-GCM, que además detecta si el archivo se ha
  modificado: si la contraseña es incorrecta o el archivo se ha manipulado,
  el descifrado falla.
"""

import hashlib
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEYSTORE_FILE = "mykeytool.keystore"

MAGIC = b"MYKS"
SALT_SIZE = 16
NONCE_SIZE = 12
HEADER_SIZE = len(MAGIC) + SALT_SIZE + NONCE_SIZE
PBKDF2_ITERATIONS = 200_000


class KeystoreError(Exception):
    """El almacén existe pero está dañado o no se puede leer."""


class WrongPasswordError(Exception):
    """La contraseña del almacén es incorrecta (o el archivo ha sido manipulado)."""


def derive_key(password, salt):
    """Deriva una clave AES de 256 bits a partir de la contraseña y la sal."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32
    )


def keystore_exists():
    return os.path.exists(KEYSTORE_FILE)


def create_keystore():
    """Devuelve un almacén nuevo y vacío."""
    return {"keys": {}}


def is_valid_keystore(data):
    """Comprueba que el contenido descifrado tiene la estructura de un almacén."""
    if not isinstance(data, dict) or not isinstance(data.get("keys"), dict):
        return False

    return all(
        isinstance(entry, dict) and all(
            isinstance(entry.get(field), str)
            for field in ("private_key", "public_key", "dname")
        )
        for entry in data["keys"].values()
    )


def load_keystore(password):
    """
    Lee y descifra el almacén del disco.
    Devuelve None si no existe, lanza WrongPasswordError si la contraseña
    no es correcta y KeystoreError si el archivo está dañado.
    """
    if not keystore_exists():
        return None

    try:
        with open(KEYSTORE_FILE, "rb") as file:
            content = file.read()
    except OSError:
        raise KeystoreError(f"no se puede leer el almacén '{KEYSTORE_FILE}'.")

    if len(content) <= HEADER_SIZE or not content.startswith(MAGIC):
        raise KeystoreError(f"el almacén '{KEYSTORE_FILE}' está dañado.")

    salt = content[len(MAGIC):len(MAGIC) + SALT_SIZE]
    nonce = content[len(MAGIC) + SALT_SIZE:HEADER_SIZE]
    ciphertext = content[HEADER_SIZE:]

    try:
        plaintext = AESGCM(derive_key(password, salt)).decrypt(
            nonce, ciphertext, MAGIC
        )
    except InvalidTag:
        raise WrongPasswordError(
            "contraseña del almacén incorrecta (o el almacén ha sido manipulado)."
        )

    try:
        data = json.loads(plaintext.decode("utf-8"))
    except ValueError:
        raise KeystoreError(f"el almacén '{KEYSTORE_FILE}' está dañado.")

    if not is_valid_keystore(data):
        raise KeystoreError(f"el almacén '{KEYSTORE_FILE}' está dañado.")

    return data


def save_keystore(data, password):
    """Cifra el almacén con la contraseña y lo guarda en el disco."""
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    plaintext = json.dumps(data).encode("utf-8")

    ciphertext = AESGCM(derive_key(password, salt)).encrypt(
        nonce, plaintext, MAGIC
    )

    with open(KEYSTORE_FILE, "wb") as file:
        file.write(MAGIC + salt + nonce + ciphertext)
