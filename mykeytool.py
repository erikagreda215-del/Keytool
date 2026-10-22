import argparse
import getpass
import os
import sys

import crypto_utils
from keystore import (
    KEYSTORE_FILE,
    KeystoreError,
    WrongPasswordError,
    create_keystore,
    keystore_exists,
    load_keystore,
    save_keystore,
)


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


def open_keystore():
    """
    Pide la contraseña y descifra el almacén existente.
    Devuelve el almacén y la contraseña, necesaria para volver a guardarlo.
    """
    if not keystore_exists():
        sys.exit(
            f"Error: no existe el almacén '{KEYSTORE_FILE}'. "
            "Ejecuta primero --genkeypair."
        )

    password = getpass.getpass("Contraseña del KeyStore: ")

    try:
        return load_keystore(password), password
    except (KeystoreError, WrongPasswordError) as error:
        sys.exit(f"Error: {error}")


def ask_existing_alias(keystore):
    alias = input("Alias: ").strip()

    if alias not in keystore["keys"]:
        sys.exit(
            f"Error: el alias '{alias}' no existe."
        )

    return alias


def unlock_private_key(entry, alias):
    key_password = getpass.getpass(
        f"Contraseña del alias '{alias}': "
    )

    try:
        return crypto_utils.pem_to_key(
            entry["private_key"],
            key_password
        )

    except (ValueError, TypeError):
        sys.exit("Error: contraseña del alias incorrecta.")


def confirm(question):
    answer = input(f"{question} (s/N): ").strip().lower()
    return answer == "s"


def write_output_file(filename, content):
    if os.path.exists(filename) and not confirm(
        f"El archivo '{filename}' ya existe. ¿Sobrescribir?"
    ):
        sys.exit("Operación cancelada: no se ha sobrescrito el archivo.")

    with open(filename, "wb") as file:
        file.write(content.encode())


def genkeypair():
    if keystore_exists():
        keystore, store_password = open_keystore()

    else:
        print("No existe almacén; se creará uno nuevo.")

        store_password = ask_password("del KeyStore")
        keystore = create_keystore()

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

    dname = crypto_utils.build_dname({
        "CN": cn,
        "OU": ou,
        "O": organization,
        "L": city,
        "ST": state,
        "C": country.upper()
    })

    if dname is None:
        sys.exit("Error: debes indicar al menos un dato del titular.")

    key_password = ask_password(f"del alias '{alias}'")

    private_key = crypto_utils.generate_rsa_keypair()

    keystore["keys"][alias] = {
        "private_key": crypto_utils.key_to_pem(private_key, key_password),
        "public_key": crypto_utils.public_key_to_pem(private_key),
        "dname": dname
    }

    save_keystore(keystore, store_password)

    print(
        f"Par de claves RSA 2048 generado y guardado "
        f"con el alias '{alias}'."
    )


def certreq():
    keystore, _ = open_keystore()
    alias = ask_existing_alias(keystore)
    entry = keystore["keys"][alias]
    private_key = unlock_private_key(entry, alias)

    filename = f"{alias}.csr"

    write_output_file(
        filename,
        crypto_utils.create_csr(private_key, entry["dname"])
    )

    print(f"CSR generado en '{filename}' (formato PEM).")


def list_entries():
    keystore, _ = open_keystore()
    keys = keystore["keys"]

    print(f"El almacén contiene {len(keys)} entrada(s).")

    for alias, entry in keys.items():
        print(f"  - {alias}: {entry['dname']}")


def delete_entry():
    keystore, store_password = open_keystore()
    alias = ask_existing_alias(keystore)

    if not confirm(f"¿Eliminar el alias '{alias}' y su par de claves?"):
        sys.exit("Operación cancelada: no se ha eliminado nada.")

    del keystore["keys"][alias]
    save_keystore(keystore, store_password)

    print(f"Alias '{alias}' eliminado del almacén.")


def selfcert():
    keystore, _ = open_keystore()
    alias = ask_existing_alias(keystore)
    entry = keystore["keys"][alias]
    private_key = unlock_private_key(entry, alias)

    days = input("Días de validez [365]: ").strip() or "365"

    if not days.isdigit() or not 1 <= int(days) <= 3650:
        sys.exit("Error: la validez debe ser un número entre 1 y 3650.")

    filename = f"{alias}.crt"

    write_output_file(
        filename,
        crypto_utils.create_self_signed_cert(
            private_key,
            entry["dname"],
            int(days)
        )
    )

    print(
        f"Certificado autofirmado generado en '{filename}' "
        f"(formato PEM, {days} días)."
    )


def main():
    parser = argparse.ArgumentParser(
        prog="mykeytool.py",
        description="Simulador en Python de la herramienta keytool de Java."
    )

    commands = parser.add_mutually_exclusive_group()

    commands.add_argument(
        "--genkeypair",
        "--genkey",
        dest="genkeypair",
        action="store_true",
        help="Genera un par de claves RSA 2048."
    )

    commands.add_argument(
        "--certreq",
        action="store_true",
        help="Genera una solicitud de certificado CSR."
    )

    commands.add_argument(
        "--list",
        dest="list_entries",
        action="store_true",
        help="Lista los alias del almacén y sus titulares."
    )

    commands.add_argument(
        "--delete",
        action="store_true",
        help="Elimina un alias y su par de claves del almacén."
    )

    commands.add_argument(
        "--selfcert",
        action="store_true",
        help="Genera un certificado X.509 autofirmado (.crt)."
    )

    args = parser.parse_args()

    if args.genkeypair:
        genkeypair()
    elif args.certreq:
        certreq()
    elif args.list_entries:
        list_entries()
    elif args.delete:
        delete_entry()
    elif args.selfcert:
        selfcert()
    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nOperación cancelada.")
