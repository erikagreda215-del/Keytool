import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

DN_FIELDS = {
    'CN': NameOID.COMMON_NAME,
    'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
    'O': NameOID.ORGANIZATION_NAME,
    'L': NameOID.LOCALITY_NAME,
    'ST': NameOID.STATE_OR_PROVINCE_NAME,
    'C': NameOID.COUNTRY_NAME
}

def generate_rsa_keypair(key_size=2048):
    """Genera un par de claves asimétricas RSA de 2048 bits."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    return private_key

def build_dname(dn_data):
    """
    Construye el Distinguished Name y lo devuelve como texto RFC 4514.
    dn_data es un diccionario con claves: CN, OU, O, L, ST, C.
    Los campos vacíos se omiten; devuelve None si no hay ninguno.
    """
    attributes = [
        x509.NameAttribute(DN_FIELDS[key], value)
        for key, value in dn_data.items()
        if value and key in DN_FIELDS
    ]

    if not attributes:
        return None

    return x509.Name(attributes).rfc4514_string()

def create_csr(private_key, dname):
    """
    Genera un CSR (Certificate Signing Request) en formato PEM.
    dname es el Distinguished Name en texto RFC 4514.
    """
    subject = x509.Name.from_rfc4514_string(dname)

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).sign(private_key, hashes.SHA256())

    # Exportar el CSR en formato PEM
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    return csr_pem.decode('utf-8')

def create_self_signed_cert(private_key, dname, days=365):
    """
    Genera un certificado X.509 autofirmado en formato PEM.
    El titular y el emisor son el mismo DN, como hace keytool de Java.
    """
    name = x509.Name.from_rfc4514_string(dname)
    now = datetime.datetime.now(datetime.timezone.utc)

    cert = x509.CertificateBuilder().subject_name(
        name
    ).issuer_name(
        name
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=days)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).sign(private_key, hashes.SHA256())

    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

def key_to_pem(private_key, password: str):
    """Convierte la clave privada a formato PEM cifrado."""
    encryption = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    return pem.decode('utf-8')

def public_key_to_pem(private_key):
    """Exporta la clave pública asociada en formato PEM."""
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def pem_to_key(pem_data: str, password: str):
    """
    Carga una clave privada desde su representación PEM.
    Lanza ValueError o TypeError si la contraseña es incorrecta.
    """
    return serialization.load_pem_private_key(
        pem_data.encode(),
        password=password.encode() if password else None
    )
