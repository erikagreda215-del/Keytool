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
    """Guarda la contraseña como hash PBKDF2 + sal (nunca en claro)."""
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return {"salt": base64.b64encode(salt).decode(),
            "hash": base64.b64encode(digest).decode()}


def check_password(password, stored):
    salt = base64.b64decode(stored["salt"])
    new = hash_password(password, salt)["hash"]
    return hmac.compare_digest(new, stored["hash"])


def ask_new_password(label):
    while True:
        p1 = getpass.getpass(f"Contraseña {label} (mín. 6 caracteres): ")
        if len(p1) < 6:
            print("Error: la contraseña debe tener al menos 6 caracteres.")
            continue
        if p1 != getpass.getpass("Repite la contraseña: "):
            print("Error: las contraseñas no coinciden.")
            continue
        return p1


def load_keystore():
    """Devuelve el dict del almacén, o None si no existe. Sale si está dañado."""
    if not os.path.exists(KEYSTORE_FILE):
        return None
    try:
        with open(KEYSTORE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "keystore_password" not in data or "keys" not in data:
            raise ValueError
        return data
    except (json.JSONDecodeError, ValueError, OSError):
        sys.exit(f"Error: el almacén '{KEYSTORE_FILE}' está dañado o no se puede leer.")


def save_keystore(data):
    with open(KEYSTORE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def genkeypair():
    ks = load_keystore()
    if ks is None:
        print("No existe almacén; se creará uno nuevo.")
        ks = {"keystore_password": hash_password(ask_new_password("del KeyStore")),
              "keys": {}}
    else:
        pwd = getpass.getpass("Contraseña del KeyStore: ")
        if not check_password(pwd, ks["keystore_password"]):
            sys.exit("Error: contraseña del almacén incorrecta.")

    alias = input("Alias: ").strip()
    if not alias:
        sys.exit("Error: el alias no puede estar vacío.")
    if alias in ks["keys"]:
        sys.exit(f"Error: el alias '{alias}' ya existe en el almacén.")

    print("Datos del titular (Enter para dejar vacío):")
    campos = [("CN", NameOID.COMMON_NAME, "Nombre y apellidos"),
              ("OU", NameOID.ORGANIZATIONAL_UNIT_NAME, "Unidad organizativa"),
              ("O", NameOID.ORGANIZATION_NAME, "Organización"),
              ("L", NameOID.LOCALITY_NAME, "Ciudad"),
              ("ST", NameOID.STATE_OR_PROVINCE_NAME, "Provincia"),
              ("C", NameOID.COUNTRY_NAME, "País (2 letras, ej. ES)")]
    attrs = []
    for sigla, oid, texto in campos:
        valor = input(f"  {sigla} - {texto}: ").strip()
        if sigla == "C" and valor and len(valor) != 2:
            sys.exit("Error: el país debe ser un código de 2 letras.")
        if valor:
            attrs.append(x509.NameAttribute(oid, valor.upper() if sigla == "C" else valor))
    if not attrs:
        sys.exit("Error: debes indicar al menos un dato del titular.")
    dname = x509.Name(attrs)

    key_pwd = ask_new_password(f"del alias '{alias}'")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(key_pwd.encode()),  # cifrada con la pass del alias
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    ks["keys"][alias] = {"private_key": private_pem,
                         "public_key": public_pem,
                         "dname": dname.rfc4514_string()}
    save_keystore(ks)
    print(f"Par de claves RSA 2048 generado y guardado con el alias '{alias}'.")


def certreq():
    ks = load_keystore()
    if ks is None:
        sys.exit(f"Error: no existe el almacén '{KEYSTORE_FILE}'. Ejecuta primero --genkeypair.")

    if not check_password(getpass.getpass("Contraseña del KeyStore: "),
                          ks["keystore_password"]):
        sys.exit("Error: contraseña del almacén incorrecta.")

    alias = input("Alias: ").strip()
    if alias not in ks["keys"]:
        sys.exit(f"Error: el alias '{alias}' no existe.")
    entry = ks["keys"][alias]

    key_pwd = getpass.getpass(f"Contraseña del alias '{alias}': ")
    try:
        private_key = serialization.load_pem_private_key(
            entry["private_key"].encode(), password=key_pwd.encode())
    except (ValueError, TypeError):
        sys.exit("Error: contraseña del alias incorrecta.")

    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name.from_rfc4514_string(entry["dname"]))
           .sign(private_key, hashes.SHA256()))

    filename = f"{alias}.csr"
    with open(filename, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    print(f"CSR generado en '{filename}' (formato PEM).")


def main():
    parser = argparse.ArgumentParser(
        prog="mykeytool.py",
        description="Simulador en Python de la herramienta keytool de Java.")
    parser.add_argument("--genkeypair", "--genkey", dest="genkeypair", action="store_true",
                        help="Genera un par de claves RSA 2048 y lo guarda en el KeyStore")
    parser.add_argument("--certreq", action="store_true",
                        help="Genera una solicitud de firma de certificado (CSR) en PEM")
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
