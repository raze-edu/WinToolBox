import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
from typing import Tuple

def sha256(data: bytes) -> bytes:
    """Computes the SHA-256 hash of a byte string."""
    return hashlib.sha256(data).digest()

def sha256_hex(data: bytes) -> str:
    """Computes the SHA-256 hash of a byte string and returns it as a hex string."""
    return hashlib.sha256(data).hexdigest()

def generate_rsa_key_pair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generates an RSA private and public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key

def private_key_to_pem(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serializes an RSA private key to PEM format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def public_key_to_pem(public_key: rsa.RSAPublicKey) -> bytes:
    """Serializes an RSA public key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_private_key_from_pem(pem_bytes: bytes) -> rsa.RSAPrivateKey:
    """Loads an RSA private key from PEM bytes."""
    return serialization.load_pem_private_key(
        pem_bytes,
        password=None
    )

def load_public_key_from_pem(pem_bytes: bytes) -> rsa.RSAPublicKey:
    """Loads an RSA public key from PEM bytes."""
    return serialization.load_pem_public_key(pem_bytes)

def sign_data(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """Signs bytes using RSA PSS signature scheme with SHA-256."""
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """Verifies an RSA PSS signature. Returns True if valid, False otherwise."""
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def rsa_encrypt(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    """Encrypts bytes using RSA OAEP padding with SHA-256."""
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """Decrypts bytes using RSA OAEP padding with SHA-256."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def generate_symmetric_key() -> bytes:
    """Generates a key for symmetric encryption (Fernet key)."""
    return Fernet.generate_key()

def encrypt_symmetric(key: bytes, plaintext: bytes) -> bytes:
    """Encrypts plaintext bytes using symmetric key (Fernet)."""
    f = Fernet(key)
    return f.encrypt(plaintext)

def decrypt_symmetric(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypts ciphertext bytes using symmetric key (Fernet)."""
    f = Fernet(key)
    return f.decrypt(ciphertext)
