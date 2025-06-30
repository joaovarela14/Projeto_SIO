from utils.crypto_utils import encrypt_document_key, generate_ec_keypair, decrypt_document_key
import os

# Paths for key files
sender_private_path = "utils/keys/private/sender_priv.pem"
recipient_public_path = "utils/keys/public/repository_pub.pem"

# Generate test keys (replace with your existing keys if needed)
generate_ec_keypair(sender_private_path, "utils/keys/public/sender_pub.pem")

# Document key to encrypt
doc_key = os.urandom(32)  # Example symmetric key (32 bytes for AES-256)

# Encrypt the document key
encrypted_doc_key, iv = encrypt_document_key(doc_key, recipient_public_path, sender_private_path)
print(f"Encrypted Document Key: {encrypted_doc_key.hex()}")
print(f"IV: {iv.hex()}")

# Decrypt the document key
decrypted_doc_key = decrypt_document_key(encrypted_doc_key, iv, "utils/keys/private/repository_priv.pem", "utils/keys/public/sender_pub.pem")
print(f"Decrypted Document Key: {decrypted_doc_key.hex()}")

# Verify that the decrypted key matches the original
assert doc_key == decrypted_doc_key, "Decryption failed: keys do not match!"

