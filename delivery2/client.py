import sys
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from utils.crypto_utils import *
import requests
import json
import argparse
import os
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import hashlib
from db import load_db
import hmac 

logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

KNOWN_PERMISSIONS = [
    "DOC_ACL", "DOC_READ", "DOC_DELETE",
    "ROLE_ACL", "SUBJECT_NEW", "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW",
    "ROLE_NEW", "ROLE_DOWN", "ROLE_UP", "ROLE_MOD"
]

def compute_hmac(session_key, message):
    return hmac.new(session_key, message.encode('utf-8'), hashlib.sha256).hexdigest()

# Command to generate a key pair
def rep_subject_credentials(password, credentials_file):
    
    if not credentials_file.endswith(".json"):
        credentials_file += ".json"

    keys_dir = "./keys"
    os.makedirs(keys_dir, exist_ok=True)
    full_path = os.path.join(keys_dir, credentials_file)
    generate_ec_keypair_from_password(password, full_path)
    print(f"Credentials saved to '{full_path}'.")

# Command to create an organization
def rep_create_org(org, username, name, email, public_key_file):

    url = "http://127.0.0.1:5000/organization/create"

    try:
        with open(public_key_file, "r") as f:
            credentials_content = f.read()
    except FileNotFoundError:
        print(f"Error: Credentials file '{public_key_file}' not found.")
        return

    payload = {
        "organization": org,
        "username": username,
        "name": name,
        "email": email,
        "credentials_file": credentials_content,  # Send file content
    }

    try:
        response = requests.post(url, json=payload)

        if response.status_code == 201:
            print(f"Organization '{org}' created successfully.")
        else:
            print(f"Error: {response.status_code}, Message: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

def rep_list_orgs():
    url = "http://127.0.0.1:5000/organization/list"
    
    try:
        response = requests.get(url)
        if response.status_code == 200:
            orgs = response.json()
            print(json.dumps(orgs, indent=4, sort_keys=True))
        else:
            print(f"Error: Received status code {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")    


def check_password(user_salt, password, stored_public_key):
    # Derive the private key from the password and salt
    try:
        salt_bytes = base64.b64decode(user_salt)
        private_key = derive_private_key_from_password(password, salt_bytes)

        # Extract the public key from the private key
        public_key = private_key.public_key()
        derived_public_key_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        # Compare the derived public key with the stored public key
        if derived_public_key_pem != stored_public_key:
            print("Error: Public key mismatch. Invalid password.")
            return False
        
        return True
        
    except Exception as e:
        print(f"Failed to derive private key: {e}")
        return False


# Command to create a session
def rep_create_session(organization, username, password, credentials_file, session_file):
    # Load user credentials (public key and salt)
    with open(credentials_file, "r") as f:
        credentials = json.load(f)

    user_salt = credentials["salt"]
    stored_public_key = credentials["public_key"]

    # Check the password and public key
    if not check_password(user_salt, password, stored_public_key):
        return

    # Endpoint URL to create a session
    url = "http://127.0.0.1:5000/session/create"
    payload = {
        "organization": organization,
        "username": username,
        "password": password,
        "salt": user_salt  # Include the user's salt in the payload
    }

    try:
        response = requests.post(url, json=payload)
        if response.status_code == 201:
            server_data = response.json()
            session_id = server_data["session_id"]
            session_key_base64 = server_data["session_key"]  # Server returns the session key in base64 format
            expires_at = server_data["expiration"]  # Get the expiration date for the session

            # Decode the base64 encoded session key
            session_key = base64.b64decode(session_key_base64)

            # Save session data
            session_data = {
                "session_id": session_id,
                "session_key": base64.b64encode(session_key).decode("utf-8"),
                "organization": organization,
                "username": username,
                "expires_at": expires_at,
                "counter": 0
            }
            with open(session_file, "w") as f:
                json.dump(session_data, f, indent=4)

            print(f"Session created successfully. Session data saved to '{session_file}'.")

        elif response.status_code == 403:
            print(f"Access denied: {response.json().get('error', 'Unknown error')}")
        elif response.status_code == 404:
            print(f"Organization not found: {response.json().get('error', 'Unknown error')}")
        else:
            print(f"Unexpected error: {response.status_code}, Message: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to the server: {e}")

def get_org_public_key(org):

    db = load_db()
    org_data = db["organizations"][org]
    if org_data is None:
        print(f"Organization '{org}' not found.")
        return None
    return org_data["metadata"]["admin_key"]



def rep_add_doc(session_file, document_name, file_path):
    """
    Encrypt and upload a document using a doc_key derived from the session key.
    """
    # Load session data
    with open(session_file, "r") as f:
        session_data = json.load(f)

    session_id = session_data["session_id"]
    session_key = base64.b64decode(session_data["session_key"])

    # Read the file content
    with open(file_path, "rb") as f:
        file_content = f.read()

    # Generate a doc_nonce (salt) for deriving a unique doc_key
    doc_nonce = os.urandom(16)

    # Derive the doc_key from the session_key and doc_nonce
    doc_key = derive_document_key(session_key, doc_nonce)

    # Encrypt the document using AES-GCM with the derived doc_key
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(doc_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_content = encryptor.update(file_content) + encryptor.finalize()
    tag = encryptor.tag

    # Compute file_handle for integrity verification (optional)
    file_handle = base64.b64encode(hashlib.sha256(file_content).digest()).decode("utf-8")

    counter = get_and_increment_counter(session_file)

    # Prepare payload for the server
    url = f"http://127.0.0.1:5000/documents/{document_name}"
    payload = {
        "document_name": document_name,
        "session_id": session_id,
        "doc_nonce": base64.b64encode(doc_nonce).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "encrypted_content": base64.b64encode(encrypted_content).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8"),
        "file_handle": file_handle,
        "counter": counter
    }

    try:
        response = requests.post(url, json=payload)
        if response.status_code == 201:
            print(f"Document '{document_name}' uploaded successfully.")
        else:
            print(f"Failed to upload document: {response.status_code}, {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to the server: {e}")

def rep_get_doc_file(session_file, document_name, output_file=None):
    """
    Download and decrypt a document using a doc_key derived from the session key.
    """
    # Load session data
    with open(session_file, "r") as f:
        session_data = json.load(f)

    session_id = session_data["session_id"]
    session_key = base64.b64decode(session_data["session_key"])

    # Request the document metadata
    url = f"http://127.0.0.1:5000/documents/{document_name}?session_id={session_id}"

    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()

            doc_nonce = base64.b64decode(data["doc_nonce"])
            iv = base64.b64decode(data["iv"])
            encrypted_content = base64.b64decode(data["encrypted_content"])
            tag = base64.b64decode(data["tag"])

            # Re-derive the doc_key using the doc_nonce and session_key
            doc_key = derive_document_key(session_key, doc_nonce)

            # Decrypt the document using AES-GCM
            cipher = Cipher(algorithms.AES(doc_key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()
            decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()

            # Save or print the document
            if output_file:
                with open(output_file, "wb") as f:
                    f.write(decrypted_content)
                print(f"Document '{document_name}' downloaded and saved to '{output_file}'.")
            else:
                print("Document Content:\n", decrypted_content.decode('utf-8'))
        else:
            print(f"Failed to retrieve document: {response.status_code}, {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to the server: {e}")



def rep_decrypt_file(encrypted_file, metadata_file):
    """
    Decrypts the encrypted file using the session_key and doc_nonce from the metadata provided.
    After decryption, it verifies the file_handle for integrity.
    The metadata is expected to contain at least:
      - algorithm: "AES-GCM"
      - session_key: base64-encoded session key
      - doc_nonce: base64-encoded nonce used to derive the doc_key
      - iv: base64-encoded IV for AES-GCM
      - tag: base64-encoded authentication tag for AES-GCM
      - file_handle: base64-encoded SHA-256 hash of the original plaintext
    This function prints the decrypted plaintext to stdout.
    """
    try:
        # Load metadata
        with open(metadata_file, "r") as mfile:
            metadata = json.load(mfile)

        required_fields = ["algorithm", "session_key", "doc_nonce", "iv", "tag", "file_handle"]
        for field in required_fields:
            if field not in metadata:
                raise ValueError(f"Missing required metadata field: {field}")

        if metadata["algorithm"] != "AES-GCM":
            raise ValueError("Unsupported encryption algorithm. Expected AES-GCM.")

        # Decode base64 fields
        session_key = base64.b64decode(metadata["session_key"])
        doc_nonce = base64.b64decode(metadata["doc_nonce"])
        iv = base64.b64decode(metadata["iv"])
        tag = base64.b64decode(metadata["tag"])
        expected_file_handle = metadata["file_handle"]

        # Derive doc_key from session_key and doc_nonce
        doc_key = derive_document_key(session_key, doc_nonce)

        # Read the ciphertext from the encrypted_file (assume it's base64-encoded)
        with open(encrypted_file, "rb") as ef:
            ciphertext_b64 = ef.read().strip()
        
        # Decode base64 ciphertext
        ciphertext = base64.b64decode(ciphertext_b64)

        # Decrypt using AES-GCM
        cipher = Cipher(algorithms.AES(doc_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        decrypted_content = decryptor.update(ciphertext) + decryptor.finalize()

        # Verify integrity using file_handle
        computed_hash = base64.b64encode(hashlib.sha256(decrypted_content).digest()).decode("utf-8")
        if computed_hash != expected_file_handle:
            raise ValueError("File integrity check failed: computed hash does not match the file_handle from metadata.")

        # Output decrypted content to stdout , add \n
        sys.stdout.buffer.write(decrypted_content + b'\n')

    except FileNotFoundError as e:
        print(f"Error: File not found - {e}", file=sys.stderr)
    except json.JSONDecodeError:
        print("Error: Failed to decode JSON from metadata file.", file=sys.stderr)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)

def rep_suspend_subject(session_file, username):
    # Load session data
    with open(session_file, "r") as f:
        session_data = json.load(f)

    session_id = session_data["session_id"]
    
    url = f"http://127.0.0.1:5000/subject/suspend"
    
    payload = {
        "session_id": session_id,
        "username": username,
    }
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(f"Subject '{username}' suspended successfully.")
        else:
            print(f"Failed to suspend subject: {response.status_code}, {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to the server: {e}")
        
def rep_activate_subject(session_file, username):
    # Load session data
    with open(session_file, "r") as f:
        session_data = json.load(f)

    session_id = session_data["session_id"]
    
    url = f"http://127.0.0.1:5000/subject/activate"
    
    payload = {
        "session_id": session_id,
        "username": username,
    }
    
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(f"Subject '{username}' activated successfully.")
        else:
            print(f"Failed to activate subject: {response.status_code}, {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to the server: {e}")
        
def rep_add_subject(session_file, username, name, email, credentials_file):
    # Load session data
    with open(session_file, "r") as f:
        session_data = json.load(f)

    session_id = session_data["session_id"]
    
    url = f"http://127.0.0.1:5000/subject/add"
    
    try:
        with open(credentials_file, "r") as f:
            credentials_content = f.read()
    except FileNotFoundError:
        print(f"Error: Credentials file '{credentials_file}' not found.")
        return
    
    public_key = json.loads(credentials_content)["public_key"]
    
    payload = {
        "session_id": session_id,
        "username": username,
        "name": name,
        "email": email,
        "public_key": public_key,
    }
    
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 201:
            print(f"Subject '{username}' added successfully.")
        else:
            print(f"Failed to add subject: {response.status_code}, {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to the server: {e}")

    
def rep_list_subjects(session_file, username=None):
    """
    List the subjects of the organization associated with the current session.
    If a username is provided, only that user's details are listed.
    """
    with open(session_file, "r") as f:
        session_data = json.load(f)

    session_id = session_data["session_id"]

    url = "http://127.0.0.1:5000/subjects/list"
    payload = {"session_id": session_id}
    
    if username:
        payload["username"] = username

    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            subjects = response.json()
            if username:
                print(f"Details for subject '{username}':")
                print(f"  Name: {subjects['name']}")
                print(f"  Status: {subjects['status']}")
            else:
                print("Subjects in the organization:")
                for subject in subjects:
                    print(f"  Name: {subject['name']}")
                    print(f"  Status: {subject['status']}")
                    print()
        else:
            print(f"Failed to list subjects: {response.status_code}, {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to the server: {e}")

def rep_get_doc_metadata(session_file, document_name):
    """
    Fetches metadata of a document given its name using the session file.
    """
    try:
        with open(session_file, "r") as file:
            session_data = json.load(file)
    except FileNotFoundError:
        print(f"Error: Session file '{session_file}' not found.")
        return
    except json.JSONDecodeError:
        print(f"Error: Session file '{session_file}' is corrupted.")
        return

    session_id = session_data.get("session_id")
    if not session_id:
        print("Error: Invalid session data. 'session_id' not found.")
        return

    url = f"http://localhost:5000/documents/{document_name}/metadata"
    params = {"session_id": session_id}

    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            metadata = response.json()
            print(json.dumps(metadata, indent=4, sort_keys=False))
        else:
            print(f"Error: {response.status_code} - {response.json().get('error')}")
    except requests.exceptions.RequestException as e:
        print(f"Error: Failed to connect to the server. {e}")


def rep_get_file(file_handle, output_path=None):
    """
    Fetches a file using its file handle. Writes the content to stdout or saves it to an optional file.
    """
    url = f"http://localhost:5000/file/{file_handle}"

    try:
        response = requests.get(url)

        if response.status_code == 200:
            try:
                data = response.json()
                print(f"Document Name: {data['document_name']}")
                print(f"File Handle: {data['file_handle']}")
                
                encrypted_content = data["encrypted_content"]

                if output_path:
                    with open(output_path, "w") as file:
                        file.write(encrypted_content)
                    print(f"File saved to {output_path}")
                else:
                    print("Encrypted Content:")
                    print(encrypted_content)
            except json.JSONDecodeError:
                print("Error: Response is not a valid JSON. Here is the raw response:")
                print(response.text)
        else:
            print(f"Error: {response.status_code}")
            print(f"Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error: Failed to connect to the server. {e}")



def rep_delete_doc(session_file, document_name):
    """
    Clears the file handle for a specific document in the current session's organization.
    """
    try:
        with open(session_file, "r") as file:
            session_data = json.load(file)
    except FileNotFoundError:
        print(f"Error: Session file '{session_file}' not found.")
        return
    except json.JSONDecodeError:
        print(f"Error: Session file '{session_file}' is corrupted.")
        return

    session_id = session_data.get("session_id")
    if not session_id:
        print("Error: Invalid session data. 'session_id' not found.")
        return

    url = f"http://localhost:5000/documents/{document_name}"

    try:
        response = requests.delete(url, json={"session_id": session_id})
        if response.status_code == 200:
            data = response.json()
            print(f"Message: {data['message']}")
            print(f"Cleared File Handle: {data['cleared_file_handle']}")
        else:
            print(f"Error: {response.status_code} - {response.json().get('error')}")
    except requests.exceptions.RequestException as e:
        print(f"Error: Failed to connect to the server. {e}")


def rep_list_docs(session_file, username=None, date=None, date_filter_type=None):
    """
    Lists documents of the current organization, filtered by username and/or date.
    """
    try:
        with open(session_file, "r") as file:
            session_data = json.load(file)
    except FileNotFoundError:
        print(f"Error: Session file '{session_file}' not found.")
        return
    except json.JSONDecodeError:
        print(f"Error: Session file '{session_file}' is corrupted.")
        return

    session_id = session_data.get("session_id")
    if not session_id:
        print("Error: Invalid session data. 'session_id' not found.")
        return

    url = "http://localhost:5000/documents"
    params = {}

    if username:
        params["username"] = username
    if date and date_filter_type:
        params["date_filter_type"] = date_filter_type
        params["date_filter_value"] = date

    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            documents = response.json()
            if not documents:
                print("No documents found.")
                return

            print("Documents:")
            for doc in documents:
                print(f"- {doc['document_name']} (Owner: {doc['owner']}, Date: {doc['create_date']})")
        else:
            print(f"Error: {response.status_code} - {response.json().get('error')}")
    except requests.exceptions.RequestException as e:
        print(f"Error: Failed to connect to the server. {e}")


def rep_assume_role(session_file, role):
    with open(session_file, "r") as f:
        session_data = json.load(f)
    session_id = session_data["session_id"]

    url = "http://127.0.0.1:5000/session/role/assume"
    payload = {
        "session_id": session_id,
        "role": role
    }
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(f"Role '{role}' assumed successfully.")
        else:
            print(f"Failed to assume role: {response.status_code}, {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

def rep_drop_role(session_file, role):
    with open(session_file, "r") as f:
        session_data = json.load(f)
    session_id = session_data["session_id"]

    url = "http://127.0.0.1:5000/session/role/drop"
    payload = {
        "session_id": session_id,
        "role": role
    }
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(f"Role '{role}' dropped successfully.")
        else:
            print(f"Failed to drop role: {response.status_code}, {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

def rep_list_roles(session_file):
    with open(session_file, "r") as f:
        session_data = json.load(f)
    session_id = session_data["session_id"]

    url = f"http://127.0.0.1:5000/session/roles?session_id={session_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            roles = data.get("roles", [])
            if not roles:
                print("No roles currently active.")
            else:
                print("Roles currently active:")
                for r in roles:
                    print(f" - {r}")
        else:
            print(f"Failed to list roles: {response.status_code}, {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

def rep_add_role(session_file, role):
    with open(session_file, "r") as f:
        session_data = json.load(f)
    session_id = session_data["session_id"]

    url = "http://127.0.0.1:5000/role/add"
    payload = {
        "session_id": session_id,
        "role": role
    }

    try:
        response = requests.post(url, json=payload)
        if response.status_code == 201:
            print(f"Role '{role}' added successfully.")
        else:
            print(f"Failed to add role: {response.status_code}, {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")


def rep_list_role_permissions(session_file, role):
    with open(session_file, "r") as f:
        session_data = json.load(f)
    session_id = session_data["session_id"]
    url = f"http://127.0.0.1:5000/role/{role}/permissions?session_id={session_id}"
    try:
        resp = requests.get(url)
        if resp.status_code == 200:
            data = resp.json()
            perms = data.get("permissions", [])
            if perms:
                print(f"Permissions for role '{role}':")
                for p in perms:
                    print(" -", p)
            else:
                print(f"No permissions for role '{role}'.")
        else:
            print(f"Error: {resp.status_code}, {resp.text}")
    except requests.RequestException as e:
        print(f"Error: {e}")

def rep_list_permission_roles(session_file, permission):
    with open(session_file, "r") as f:
        session_data = json.load(f)
    session_id = session_data["session_id"]
    url = f"http://127.0.0.1:5000/permission/{permission}/roles?session_id={session_id}"
    try:
        resp = requests.get(url)
        if resp.status_code == 200:
            data = resp.json()
            roles = data.get("roles", [])
            if roles:
                print(f"Roles with permission '{permission}':")
                for r in roles:
                    print(" -", r)
            else:
                print(f"No roles have permission '{permission}'.")
        else:
            print(f"Error: {resp.status_code}, {resp.text}")
    except requests.RequestException as e:
        print(f"Error: {e}")

def rep_suspend_role(session_file, role):
    with open(session_file, "r") as f:
        session_data = json.load(f)
    session_id = session_data["session_id"]
    url = "http://127.0.0.1:5000/role/suspend"
    payload = {"session_id": session_id, "role": role}
    try:
        resp = requests.post(url, json=payload)
        if resp.status_code == 200:
            print(f"Role '{role}' suspended successfully.")
        else:
            print(f"Error: {resp.status_code}, {resp.text}")
    except requests.RequestException as e:
        print(f"Error: {e}")

def rep_reactivate_role(session_file, role):
    with open(session_file, "r") as f:
        session_data = json.load(f)
    session_id = session_data["session_id"]
    url = "http://127.0.0.1:5000/role/reactivate"
    payload = {"session_id": session_id, "role": role}
    try:
        resp = requests.post(url, json=payload)
        if resp.status_code == 200:
            print(f"Role '{role}' reactivated successfully.")
        else:
            print(f"Error: {resp.status_code}, {resp.text}")
    except requests.RequestException as e:
        print(f"Error: {e}")

def rep_list_subject_roles(session_file, username):
    with open(session_file, "r") as f:
        session_data = json.load(f)
    session_id = session_data["session_id"]
    url = f"http://127.0.0.1:5000/subject/{username}/roles?session_id={session_id}"
    try:
        resp = requests.get(url)
        if resp.status_code == 200:
            data = resp.json()
            roles = data.get("roles", [])
            if roles:
                print(f"Roles in subject '{username}':")
                for r in roles:
                    print(" -", r)
            else:
                print(f"No roles in subject '{username}'.")
        else:
            print(f"Error: {resp.status_code}, {resp.text}")
    except requests.RequestException as e:
        print(f"Error: {e}")

def rep_list_role_subjects(session_file, role):
    with open(session_file, "r") as f:
        session_data = json.load(f)
    session_id = session_data["session_id"]
    url = f"http://127.0.0.1:5000/role/{role}/subjects?session_id={session_id}"
    try:
        resp = requests.get(url)
        if resp.status_code == 200:
            data = resp.json()
            subs = data.get("subjects", [])
            if subs:
                print(f"Subjects in role '{role}':")
                for s in subs:
                    print(" -", s)
            else:
                print(f"No subjects in role '{role}'.")
        else:
            print(f"Error: {resp.status_code}, {resp.text}")
    except requests.RequestException as e:
        print(f"Error: {e}")

def rep_acl_doc(session_file, document_name, sign, role, permission):
    with open(session_file, "r") as f:
        session_data = json.load(f)
    session_id = session_data["session_id"]
    url = f"http://127.0.0.1:5000/documents/{document_name}/acl"
    payload = {
        "session_id": session_id,
        "sign": sign,
        "role": role,
        "permission": permission
    }
    try:
        resp = requests.post(url, json=payload)
        if resp.status_code == 200:
            print("Document ACL updated successfully.")
        else:
            print(f"Error: {resp.status_code}, {resp.text}")
    except requests.RequestException as e:
        print(f"Error: {e}")



def rep_add_permission(session_file, role, arg):
    """
    rep_add_permission <session file> <role> <username/permission>:
    If arg is a known permission, add that permission to the role.
    If arg is not a known permission, treat it as a username and add that user to the role.
    """
    with open(session_file, "r") as f:
        session_data = json.load(f)
    session_id = session_data["session_id"]

    if arg in KNOWN_PERMISSIONS:
        # Add permission to role
        url = "http://127.0.0.1:5000/role/permission/add"
        payload = {
            "session_id": session_id,
            "role": role,
            "permission": arg
        }
        action_desc = f"permission '{arg}' to role '{role}'"
    else:
        # Add subject to role
        # This endpoint must exist on the server side: /role/subject/add
        url = "http://127.0.0.1:5000/role/subject/add"
        payload = {
            "session_id": session_id,
            "role": role,
            "username": arg
        }
        action_desc = f"subject '{arg}' to role '{role}'"

    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(f"Added {action_desc} successfully.")
        else:
            print(f"Failed to add {action_desc}: {response.status_code}, {response.text}")
    except requests.RequestException as e:
        print(f"Error: {e}")

def rep_remove_permission(session_file, role, arg):
    """
    rep_remove_permission <session file> <role> <username/permission>:
    If arg is a known permission, remove that permission from the role.
    If arg is not a known permission, treat it as a username and remove that user from the role.
    """
    with open(session_file, "r") as f:
        session_data = json.load(f)
    session_id = session_data["session_id"]

    if arg in KNOWN_PERMISSIONS:
        # Remove permission from role
        url = "http://127.0.0.1:5000/role/permission/remove"
        payload = {
            "session_id": session_id,
            "role": role,
            "permission": arg
        }
        action_desc = f"permission '{arg}' from role '{role}'"
    else:
        # Remove subject from role
        # This endpoint must exist on the server side: /role/subject/remove
        url = "http://127.0.0.1:5000/role/subject/remove"
        payload = {
            "session_id": session_id,
            "role": role,
            "username": arg
        }
        action_desc = f"subject '{arg}' from role '{role}'"

    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print(f"Removed {action_desc} successfully.")
        else:
            print(f"Failed to remove {action_desc}: {response.status_code}, {response.text}")
    except requests.RequestException as e:
        print(f"Error: {e}")



# Load state
def load_state():
    state = {}
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    logger.debug('State folder: ' + state_dir)
    logger.debug('State file: ' + state_file)

    if os.path.exists(state_file):
        logger.debug('Loading state')
        with open(state_file,'r') as f:
            state = json.loads(f.read())

    if state is None:
        state = {}

    return state

def parse_env(state):
    if 'REP_ADDRESS' in os.environ:
        state['REP_ADDRESS'] = os.getenv('REP_ADDRESS')
        logger.debug('Setting REP_ADDRESS from Environment to: ' + state['REP_ADDRESS'])

    if 'REP_PUB_KEY' in os.environ:
        rep_pub_key = os.getenv('REP_PUB_KEY')
        logger.debug('Loading REP_PUB_KEY fron: ' + state['REP_PUB_KEY'])
        if os.path.exists(rep_pub_key):
            with open(rep_pub_key, 'r') as f:
                state['REP_PUB_KEY'] = f.read()
                logger.debug('Loaded REP_PUB_KEY from Environment')
    return state

# Parse command-line arguments
def parse_args(state):
    parser = argparse.ArgumentParser()

    parser.add_argument("-k", '--key', nargs=1, help="Path to the key file")
    parser.add_argument("-r", '--repo', nargs=1, help="Address:Port of the repository")
    parser.add_argument("-v", '--verbose', help="Increase verbosity", action="store_true")
    parser.add_argument(
        "command",
        choices=[
            "rep_create_session",
            "rep_create_org",
            "rep_list_orgs",
            "rep_subject_credentials",
            "rep_add_doc",
            "rep_get_doc_file",
            "rep_suspend_subject",
            "rep_activate_subject",
            "rep_add_subject",
            "rep_list_subjects",
            "rep_get_doc_metadata",
            "rep_get_file",
            "rep_delete_doc",
            "rep_list_docs",
            "rep_decrypt_file",
            "rep_add_role",
            "rep_drop_role",
            "rep_assume_role",
            "rep_list_roles",
            "rep_list_role_subjects",
            "rep_list_subject_roles",
            "rep_list_role_permissions",
            "rep_list_permission_roles",
            "rep_suspend_role",
            "rep_reactivate_role",
            "rep_add_permission",
            "rep_remove_permission",
            "rep_acl_doc",
        ],
        help="Command to execute"
    )
    parser.add_argument("args", nargs=argparse.REMAINDER, help="Arguments for the command")

    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info('Setting log level to DEBUG')

    if args.key:
        if not os.path.exists(args.key[0]) or not os.path.isfile(args.key[0]):
            logger.error(f'Key file not found or invalid: {args.key[0]}')
            sys.exit(-1)
        
        with open(args.key[0], 'r') as f:
            state['REP_PUB_KEY'] = f.read()
            logger.info('Overriding REP_PUB_KEY from command line')

    if args.repo:
        state['REP_ADDRESS'] = args.repo[0]
        logger.info('Overriding REP_ADDRESS from command line')

    return state, args

def save(state):
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    if not os.path.exists(state_dir):
      logger.debug('Creating state folder')
      os.mkdir(state_dir)

    with open(state_file, 'w') as f:
        f.write(json.dumps(state, indent=4))

state = load_state()
state = parse_env(state)
state, args = parse_args(state)
COMMANDS = {
    "rep_create_org": {
        "function": rep_create_org,
        "args": 5,
        "usage": "USAGE: rep_create_org <org> <username> <name> <email> <public key file>",
    },
    "rep_create_session": {
        "function": rep_create_session,
        "args": 5,
        "usage": "USAGE: rep_create_session <org> <username> <password> <credentials file> <session file>",
    },
    "rep_list_orgs": {
        "function": rep_list_orgs,
        "args": 0,
        "usage": None, 
    },
    "rep_subject_credentials": {
        "function": rep_subject_credentials,
        "args": 2,
        "usage": "USAGE: rep_subject_credentials <password> <credentials file>",
    },
    "rep_add_doc": {
        "function": rep_add_doc,
        "args": 3,
        "usage": "USAGE: rep_add_doc <session file> <document name> <file path>",
    },
    "rep_get_doc_file": {
        "function": rep_get_doc_file,
        "args": 3,
        "usage": "USAGE: rep_get_doc_file <session file> <document name> [output file]",
    },
    "rep_suspend_subject": {
        "function": rep_suspend_subject,
        "args": 2,
        "usage": "USAGE: rep_suspend_subject <session file> <username>",
    },
    "rep_activate_subject": {
        "function": rep_activate_subject,
        "args": 2,
        "usage": "USAGE: rep_activate_subject <session file> <username>",
    },
    "rep_add_subject":{
        "function": rep_add_subject,
        "args": 5,
        "usage": "USAGE: rep_add_subject <session file> <username> <name> <email> <credentials file>",
    },
    "rep_list_subjects": {
        "function": rep_list_subjects,
        "args": [1, 2],
        "usage": "USAGE: rep_list_subjects <session file> [username]",
    },
        "rep_get_doc_metadata": {
        "function": rep_get_doc_metadata,
        "args": 2,
        "usage": "USAGE: rep_get_doc_metadata <session file> <document name>",
    },
    "rep_get_file": {
        "function": rep_get_file,
        "args": [1, 2],
        "usage": "USAGE: rep_get_file <file handle> [output file]",
    },
    "rep_delete_doc": {
        "function": rep_delete_doc,
        "args": 2,
        "usage": "USAGE: rep_delete_doc <session file> <document name>",
    },
    "rep_list_docs": {
        "function": rep_list_docs,
        "args": [1,3, 6, 4],
        "usage": "USAGE: rep_list_docs <session file> [-s username] [-d nt/ot/et date]",
    },
    "rep_decrypt_file": {
        "function": rep_decrypt_file,
        "args": 2,
        "usage": "USAGE: rep_decrypt_file <encrypted file> <metadata file>",
    },
    "rep_add_role": {
        "function": rep_add_role,
        "args": 2,
        "usage": "USAGE: rep_add_role <session file> <role>",
    },
    "rep_drop_role": {
        "function": rep_drop_role,
        "args": 2,
        "usage": "USAGE: rep_drop_role <session file> <role>",
    },
    "rep_assume_role": {
        "function": rep_assume_role,
        "args": 2,
        "usage": "USAGE: rep_assume_role <session file> <role>",
    },
    "rep_list_roles": {
        "function": rep_list_roles,
        "args": 1,
        "usage": "USAGE: rep_list_roles <session file>",
    },
    "rep_list_role_subjects": {
        "function": rep_list_role_subjects,
        "args": 2,
        "usage": "USAGE: rep_list_roles_subject <session file> <role>",
    },
    "rep_list_subject_roles": {
        "function": rep_list_subject_roles,
        "args": 2,
        "usage": "USAGE: rep_list_subject_roles <session file> <username>",
    },
    "rep_list_role_permissions": {
        "function": rep_list_role_permissions,
        "args": 2,
        "usage": "USAGE: rep_list_role_permissions <session file> <role>",
    },
    "rep_list_permission_roles": {
        "function": rep_list_permission_roles,
        "args": 2,
        "usage": "USAGE: rep_list_permission_roles <session file> <permission>",
    },
    "rep_suspend_role": {
        "function": rep_suspend_role,
        "args": 2,
        "usage": "USAGE: rep_suspend_role <session file> <role>",
    },
    "rep_reactivate_role": {
        "function": rep_reactivate_role,
        "args": 2,
        "usage": "USAGE: rep_reactivate_role <session file> <role>",
    },
    "rep_acl_doc": {
        "function": rep_acl_doc,
        "args": 5,
        "usage": "USAGE: rep_acl_doc <session file> <document name> [+/-] <role> <permission>",
    },
    "rep_add_permission": {
        "function": rep_add_permission,
        "args": 3,
        "usage": "USAGE: rep_add_permission <session file> <role> (<permission> | <username>)",
    },
    "rep_remove_permission": {
        "function": rep_remove_permission,
        "args": 3,
        "usage": "USAGE: rep_remove_permission <session file> <role> (<permission> | <username>)",
    },
}

# Command Execution
def execute_command(command, args):
    if command not in COMMANDS:
        logger.error(f"Invalid command: {command}")
        return

    cmd_info = COMMANDS[command]
    expected_args = cmd_info["args"]
    
    if command == "rep_list_docs":
        if "-s" in args:
            username = args[args.index("-s") + 1]
            args.remove("-s")
            args.remove(username)
        else:
            username = None

        if "-d" in args:
            date_filter_type = args[args.index("-d") + 1]
            date = args[args.index("-d") + 2]
            args.remove("-d")
            args.remove(date_filter_type)
            args.remove(date)
        else:
            date = None
            date_filter_type = None

        cmd_info["function"](args[0], username, date, date_filter_type)
        return

    if isinstance(expected_args, list):
        if len(args) not in expected_args:
            print(cmd_info["usage"])
            return
    else:
        if len(args) != expected_args:
            print(cmd_info["usage"])
            return


    # Call the function with the provided arguments
    cmd_info["function"](*args)

# Main logic
execute_command(args.command, args.args)