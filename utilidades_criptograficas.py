from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

def generate_rsa_keypair(key_size=2048):
    """Genera un par de claves asimétricas RSA de 2048 bits."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    return private_key

def create_csr(private_key, dn_data):
    """
    Genera un CSR (Certificate Signing Request) en formato PEM.
    dn_data es un diccionario con claves: CN, OU, O, L, ST, C
    """
    subject_attributes = []
    
    mapping = {
        'CN': NameOID.COMMON_NAME,
        'OU': NameOID.ORGANIZATIONAL_UNIT_NAME,
        'O': NameOID.ORGANIZATION_NAME,
        'L': NameOID.LOCALITY_NAME,
        'ST': NameOID.STATE_OR_PROVINCE_NAME,
        'C': NameOID.COUNTRY_NAME
    }
    
    for key, value in dn_data.items():
        if value and key in mapping:
            subject_attributes.append(x509.NameAttribute(mapping[key], value))
            
    subject = x509.Name(subject_attributes)
    
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).sign(private_key, hashes.SHA256())
    
    # Exportar el CSR en formato PEM
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    return csr_pem.decode('utf-8')

def key_to_pem(private_key, password: str):
    """Convierte la clave privada a formato PEM cifrado."""
    encryption = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    return pem.decode('utf-8')

def pem_to_key(pem_data: str, password: str):
    """Carga una clave privada desde su representación PEM."""
    return serialization.load_pem_private_key(
        pem_data.encode(),
        password=password.encode() if password else None
    )