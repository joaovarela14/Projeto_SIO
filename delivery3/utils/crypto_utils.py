from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_public_key, load_pem_private_key
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import json

# === Key Management ===

def derive_private_key_from_password(password, salt):
    """
    Derive a private key deterministically from a password and salt using PBKDF2.
    """
    # Use PBKDF2 to derive a 32-byte key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length in bytes
        salt=salt,
        iterations=100000
    )
    derived_key_bytes = kdf.derive(password.encode())

    private_key = ec.derive_private_key(int.from_bytes(derived_key_bytes, byteorder='big'), ec.SECP256R1())
    return private_key


def generate_ec_keypair_from_password(password, credentials_file):
    """
    Generate an EC key pair deterministically from a password, and save only the public key and salt to a file.
    """
    try:
        # Generate a random salt
        salt = os.urandom(16)  # 16-byte random salt
        salt_b64 = base64.b64encode(salt).decode('utf-8')  # Encode salt to base64

        # Derive the private key
        private_key = derive_private_key_from_password(password, salt)

        # Extract the public key
        public_key = private_key.public_key()

        # Serialize the public key
        public_key_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        # Save the public key and salt to the credentials file
        os.makedirs(os.path.dirname(credentials_file), exist_ok=True)
        with open(credentials_file, "w") as f:
            f.write(json.dumps({
                "salt": salt_b64,
                "public_key": public_key_pem
            }, indent=4))

        print(f"Credentials created successfully in '{credentials_file}'.")

    except Exception as e:
        print(f"Failed to create credentials: {e}")


def load_public_key(credentials_content):
    """
    Load the public key from JSON-formatted content or directly from PEM-formatted text.
    """
    try:
        if credentials_content.startswith("-----BEGIN PUBLIC KEY-----"):
            # Directly handle PEM-formatted keys
            public_key_pem = credentials_content
        else:
            # Handle JSON-formatted content
            data = json.loads(credentials_content)
            public_key_pem = data["public_key"]

        # Load the public key
        public_key = load_pem_public_key(public_key_pem.encode("utf-8"))

        # Ensure the key is compatible with SECP256R1
        if not isinstance(public_key.curve, ec.SECP256R1):
            raise ValueError("Loaded public key is not compatible with SECP256R1")

        return public_key

    except ValueError as e:
        print(f"Error loading public key: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


# === File Encryption Key Protection ===

def encrypt_document_key(doc_key, recipient_public_key_content, sender_password, sender_salt):
    """
    Encrypt a document's symmetric encryption key using ECC-based hybrid encryption.
    """
    # Load recipient's public key
    recipient_public_key = load_public_key(recipient_public_key_content)

    # Derive sender's private key
    sender_private_key = derive_private_key_from_password(sender_password, base64.b64decode(sender_salt))

    # Perform ECDH to derive a shared secret
    shared_secret = sender_private_key.exchange(ec.ECDH(), recipient_public_key)

    # Derive a symmetric key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file encryption key'
    ).derive(shared_secret)

    # Use the derived key to encrypt the document key
    iv = os.urandom(12)  # Initialization vector for AES
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_doc_key = encryptor.update(doc_key) + encryptor.finalize()
    tag = encryptor.tag

    return encrypted_doc_key, iv, tag


def decrypt_document_key(encrypted_doc_key, iv, tag, recipient_password, recipient_salt, sender_public_key_content):
    """
    Decrypt an encrypted document key using ECC-based hybrid decryption.
    """
    # Derive recipient's private key
    recipient_private_key = derive_private_key_from_password(recipient_password, base64.b64decode(recipient_salt))

    # Load sender's public key
    sender_public_key = load_public_key(sender_public_key_content)

    # Perform ECDH to derive the shared secret
    shared_secret = recipient_private_key.exchange(ec.ECDH(), sender_public_key)

    # Derive the symmetric key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file encryption key'
    ).derive(shared_secret)

    # Use the derived key to decrypt the document key
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    doc_key = decryptor.update(encrypted_doc_key) + decryptor.finalize()

    return doc_key


def derive_document_key(session_key: bytes, doc_nonce: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=doc_nonce,
        info=b'doc_encryption'
    )
    return hkdf.derive(session_key)


# === Session Security ===
def derive_session_key(shared_key, salt=None, context_info=b'session key derivation'):
    """
    Derive a secure session key from a shared secret using HKDF.
    """
    if salt is None:
        salt = os.urandom(16)  # Generate a random 16-byte salt if not provided

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=context_info
    ).derive(shared_key)

    return derived_key, salt  # Return both the derived key and the salt used


def perform_ecdh(password, salt_bytes, peer_public_key_content):
    """
    Perform ECDH to compute a shared key dynamically derived from a password and salt.
    """
    try:
        # Ensure the salt is in bytes
        if not isinstance(salt_bytes, bytes):
            raise ValueError("Salt must be in bytes format.")

        # Derive the private key from password and salt
        private_key = derive_private_key_from_password(password, salt_bytes)

        # Load the peer's public key
        peer_public_key = load_public_key(peer_public_key_content)

        # Ensure the peer's public key is compatible with SECP256R1
        if not isinstance(peer_public_key.curve, ec.SECP256R1):
            raise ValueError("Peer's public key must be on SECP256R1 curve")

        # Perform ECDH to derive the shared secret
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

        return shared_key

    except Exception as e:
        print(f"Failed to perform ECDH: {e}")
        raise


# Utility function to update and retrieve the counter
def get_and_increment_counter(session_file):
    # Load the session data
    with open(session_file, "r") as f:
        data = json.load(f)

    data["counter"] += 1
    new_val = data["counter"]
    # Save back
    with open(session_file, "w") as f_w:
        json.dump(data, f_w, indent=4)
    # Return the counter as a string:
    return new_val
