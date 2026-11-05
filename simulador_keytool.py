import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

KEYSTORE_FILE = "keystore.json"


def hash_password(password, salt=None):
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
    salt = base64.b64decode(stored["salt"])
    new_hash = hash_password(password, salt)["hash"]
    return hmac.compare_digest(new_hash, stored["hash"])


def ask_password(label):
    while True:
        password = getpass.getpass(
            f"Contraseña {label} (mín. 6 caracteres): "
        )

        if len(password) < 6:
            print("Error: la contraseña debe tener al menos 6 caracteres.")
            continue

        repeat = getpass.getpass("Repite la contraseña: ")

        if password != repeat:
            print("Error: las contraseñas no coinciden.")
            continue

        return password


def load_keystore():
    if not os.path.exists(KEYSTORE_FILE):
        return None

    try:
        with open(KEYSTORE_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        if "keystore_password" not in data or "keys" not in data:
            raise ValueError

        return data

    except (json.JSONDecodeError, ValueError, OSError):
        sys.exit(
            f"Error: el almacén '{KEYSTORE_FILE}' está dañado o no se puede leer."
        )


def save_keystore(data):
    with open(KEYSTORE_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def genkeypair():
    keystore = load_keystore()

    if keystore is None:
        print("No existe almacén; se creará uno nuevo.")

        keystore = {
            "keystore_password": hash_password(
                ask_password("del KeyStore")
            ),
            "keys": {}
        }

    else:
        password = getpass.getpass("Contraseña del KeyStore: ")

        if not check_password(
            password,
            keystore["keystore_password"]
        ):
            sys.exit("Error: contraseña del almacén incorrecta.")

    alias = input("Alias: ").strip()

    if not alias:
        sys.exit("Error: el alias no puede estar vacío.")

    if alias in keystore["keys"]:
        sys.exit(
            f"Error: el alias '{alias}' ya existe en el almacén."
        )

    print("Datos del titular (Enter para dejar vacío):")

    cn = input("  CN - Nombre y apellidos: ").strip()
    ou = input("  OU - Unidad organizativa: ").strip()
    organization = input("  O - Organización: ").strip()
    city = input("  L - Ciudad: ").strip()
    state = input("  ST - Provincia: ").strip()
    country = input("  C - País (2 letras, ej. ES): ").strip()

    if country and len(country) != 2:
        sys.exit("Error: el país debe ser un código de 2 letras.")

    attributes = []

    if cn:
        attributes.append(
            x509.NameAttribute(NameOID.COMMON_NAME, cn)
        )

    if ou:
        attributes.append(
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ou)
        )

    if organization:
        attributes.append(
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization)
        )

    if city:
        attributes.append(
            x509.NameAttribute(NameOID.LOCALITY_NAME, city)
        )

    if state:
        attributes.append(
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state)
        )

    if country:
        attributes.append(
            x509.NameAttribute(NameOID.COUNTRY_NAME, country.upper())
        )

    if not attributes:
        sys.exit("Error: debes indicar al menos un dato del titular.")

    name = x509.Name(attributes)

    key_password = ask_password(f"del alias '{alias}'")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(
            key_password.encode()
        )
    ).decode()

    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    keystore["keys"][alias] = {
        "private_key": private_pem,
        "public_key": public_pem,
        "dname": name.rfc4514_string()
    }

    save_keystore(keystore)

    print(
        f"Par de claves RSA 2048 generado y guardado "
        f"con el alias '{alias}'."
    )


def certreq():
    keystore = load_keystore()

    if keystore is None:
        sys.exit(
            f"Error: no existe el almacén '{KEYSTORE_FILE}'. "
            "Ejecuta primero --genkeypair."
        )

    password = getpass.getpass("Contraseña del KeyStore: ")

    if not check_password(
        password,
        keystore["keystore_password"]
    ):
        sys.exit("Error: contraseña del almacén incorrecta.")

    alias = input("Alias: ").strip()

    if alias not in keystore["keys"]:
        sys.exit(
            f"Error: el alias '{alias}' no existe."
        )

    entry = keystore["keys"][alias]

    key_password = getpass.getpass(
        f"Contraseña del alias '{alias}': "
    )

    try:
        private_key = serialization.load_pem_private_key(
            entry["private_key"].encode(),
            password=key_password.encode()
        )

    except (ValueError, TypeError):
        sys.exit("Error: contraseña del alias incorrecta.")

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name.from_rfc4514_string(entry["dname"])
        )
        .sign(private_key, hashes.SHA256())
    )

    filename = f"{alias}.csr"

    with open(filename, "wb") as file:
        file.write(
            csr.public_bytes(serialization.Encoding.PEM)
        )

    print(f"CSR generado en '{filename}' (formato PEM).")


def main():
    parser = argparse.ArgumentParser(
        prog="mykeytool.py",
        description="Simulador en Python de la herramienta keytool de Java."
    )

    parser.add_argument(
        "--genkeypair",
        "--genkey",
        dest="genkeypair",
        action="store_true",
        help="Genera un par de claves RSA 2048."
    )

    parser.add_argument(
        "--certreq",
        action="store_true",
        help="Genera una solicitud de certificado CSR."
    )

    args = parser.parse_args()

    if args.genkeypair:
        genkeypair()
    elif args.certreq:
        certreq()
    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nOperación cancelada.")