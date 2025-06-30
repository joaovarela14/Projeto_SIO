from functools import wraps

from flask import Flask, request, jsonify
from uuid import uuid4
import logging
from utils.crypto_utils import *
import base64
import time
import hmac
import hashlib
from urllib.parse import unquote
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from db import load_db, save_db

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load the database into memory
db = load_db()
documents = json.load(open("documents.json"))

SESSION_EXPIRATION = time.time() + 3600  # 1 hour from now

## === Helper Functions ===


import json
import time
from datetime import datetime

def is_session_expired(session_id, db_file="db.json"):
    with open(db_file, "r") as file:
        db = json.load(file)
    
    if session_id not in db.get("sessions", {}):
        return False  # Session does not exist
    
    session_data = db["sessions"][session_id]
    expiration = session_data.get("expiration")

    if expiration is not None and time.time() > expiration:
        del db["sessions"][session_id]
        with open(db_file, "w") as file:
            json.dump(db, file, indent=4)
        print(f"Session {session_id} has expired and has been removed.")
        return True

    session_data["expiration"] = SESSION_EXPIRATION
    
    return False

        
def user_has_permission(session_data, org, permission):
    active_roles = session_data.get("active_roles", [])
    if not active_roles:
        print("No roles assumed.")
        return False

    org_data = db["organizations"].get(org, {})
    org_roles = org_data.get("roles", {})

    for role in active_roles:
        role_data = org_roles.get(role)
        if not role_data:
            continue
        if role_data.get("status") != "active":
            continue
        if permission in role_data.get("permissions", []):
            return True
        
    print(f"Permission '{permission}' not found in any of the active roles: {active_roles}")
    return False


def get_user_public_key(username, org):
    for pk, subj in db["subjects"].items():
        if subj["username"] == username and org in subj["organizations"]:
            return pk
    return None

def verify_hmac(session_key, message, received_hmac):
    computed_hmac = hmac.new(session_key, message.encode('utf-8'), hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed_hmac, received_hmac)


def verify_request(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # 1) read session_id from header
        session_id = request.headers.get("X-Session-ID", None)
        if not session_id:
            return jsonify({"error": "Missing X-Session-ID header"}), 400

        session_data = db["sessions"].get(session_id)
        if not session_data:
            return jsonify({"error": "Invalid session ID"}), 403

        session_key = base64.b64decode(session_data["session_key"])

        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400
        encrypted_body = request.get_json()
        if not all(k in encrypted_body for k in ("iv","tag","data")):
            return jsonify({"error": "Encrypted request must have iv, tag, data"}), 400

        # 2) Decrypt
        try:
            decrypted_data = decrypt_payload(session_key, encrypted_body)
        except Exception as e:
            return jsonify({"error": f"Failed to decrypt request: {str(e)}"}), 400

        # 3) HMAC check
        received_hmac = decrypted_data.get("hmac")
        if not received_hmac:
            return jsonify({"error": "Missing HMAC in payload"}), 400

        data_no_hmac = dict(decrypted_data)
        del data_no_hmac["hmac"]
        serialized_payload = json.dumps(data_no_hmac, sort_keys=True)
        computed_hmac = hmac.new(session_key, serialized_payload.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(computed_hmac, received_hmac):
            return jsonify({"error": "Invalid HMAC signature"}), 403

        # 4) counter check
        if "counter" not in decrypted_data:
            return jsonify({"error": "Missing counter"}), 400
        try:
            counter = int(decrypted_data["counter"])
        except:
            return jsonify({"error": "Counter must be int"}), 400

        expected_counter = session_data.get("last_counter", 0) + 1
        if counter != expected_counter:
            return jsonify({"error": "Invalid counter value"}), 403

        # update the session's last_counter
        session_data["last_counter"] = counter
        db["sessions"][session_id] = session_data
        save_db()

        # store the real request data for the route
        request.decrypted_payload = decrypted_data

        return func(*args, **kwargs)
    return wrapper


def load_private_key():
    with open("keys/server_private_key.pem", "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    
SERVER_PRIVATE_KEY = load_private_key()
    

## ==== Encryption Functions ====


@app.route("/organization/list", methods=["GET"])
def list_organizations():
    organizations = db["organizations"]
    return jsonify(organizations), 200


@app.route("/organization/create", methods=["POST"])
def create_organization():
    try:
        data = request.get_json()

        encrypted_aes_key = data.get("encrypted_aes_key")
        iv = data.get("iv")
        encrypted_data = data.get("encrypted_data")

        if not all([encrypted_aes_key, iv, encrypted_data]):
            return jsonify({"error": "Missing encrypted_aes_key, iv, or encrypted_data"}), 400


        # Decrypt the payload using AES
        decrypted_payload = decrypt_payload_aes(iv, encrypted_data, encrypted_aes_key, SERVER_PRIVATE_KEY)

        # Now process the payload
        org_name = decrypted_payload.get("organization")
        username = decrypted_payload.get("username")
        name = decrypted_payload.get("name")
        email = decrypted_payload.get("email")
        credentials_content = decrypted_payload.get("credentials_file")

        if not all([org_name, username, name, email, credentials_content]):
            return jsonify({"error": "All fields (organization, username, name, email, credentials_file) are required"}), 400

        if org_name in db["organizations"]:
            return jsonify({"error": f"Organization '{org_name}' already exists"}), 400

        try:
            public_key = load_public_key(credentials_content)
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")
        except Exception as e:
            return jsonify({"error": f"Failed to load public key: {str(e)}"}), 400

        organization = {
            "name": org_name,
            "metadata": {
                "created_at": str(datetime.now()),
                "admin_username": username,
                "admin_email": email,
                "admin_key": public_key_pem,
            },
            "acl": {
                "ROLE_ACL": ["Manager"],
                "SUBJECT_NEW": ["Manager"],
                "SUBJECT_DOWN": ["Manager"],
                "SUBJECT_UP": ["Manager"],
                "DOC_NEW": ["Manager"]
            },
            "documents": {},
            "users": [username],
            "roles": {
                "Managers": {
                    "permissions": [
                        "ROLE_ACL", "SUBJECT_NEW", "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW",
                        "ROLE_NEW", "ROLE_DOWN", "ROLE_UP", "ROLE_MOD",
                        "DOC_READ", "DOC_DELETE", "DOC_ACL"
                    ],
                    "subjects": [username],
                    "status": "active"
                }
            }
        }
        db["organizations"][org_name] = organization

        # Update or create the subject entry
        if public_key_pem in db["subjects"]:
            db["subjects"][public_key_pem]["organizations"].append(org_name)
        else:
            subject = {
                "username": username,
                "name": name,
                "email": email,
                "public_key": public_key_pem,
                "organizations": [org_name],
                "status": "active",
            }
            db["subjects"][public_key_pem] = subject

        save_db()
        return jsonify({"message": f"Organization '{org_name}' created successfully"}), 201

    except Exception as e:
        print(f"Exception: {e}")  # Add this for debugging
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 400

@app.route("/session/create", methods=["POST"])
def create_session():
    data = request.get_json()

    encrypted_aes_key = data.get("encrypted_aes_key")
    iv = data.get("iv")
    encrypted_data = data.get("encrypted_data")

    if not all([encrypted_aes_key, iv, encrypted_data]):
        return jsonify({"error": "Fields 'encrypted_aes_key', 'iv', and 'encrypted_data' are required"}), 400
    
    data = decrypt_payload_aes(iv, encrypted_data, encrypted_aes_key, SERVER_PRIVATE_KEY)

    org_name = data.get("organization")
    username = data.get("username")
    password = data.get("password")
    user_salt_b64 = data.get("salt")  # Get the salt from the request

    # Validate input
    if not all([org_name, username, password, user_salt_b64]):
        return jsonify({"error": "Fields 'organization', 'username', 'password', and 'salt' are required"}), 400

    # Verify organization and user exist
    if org_name not in db["organizations"]:
        return jsonify({"error": f"Organization '{org_name}' does not exist"}), 404

    organization = db["organizations"][org_name]
    if username not in organization.get("users", []):
        return jsonify({"error": f"User '{username}' does not belong to the organization '{org_name}'"}), 403

    # Load organization's public key
    org_public_key_content = organization["metadata"]["admin_key"]

    try:
        # Decode the user salt from base64 to bytes
        user_salt = base64.b64decode(user_salt_b64)

        # Derive shared key using ECDH
        shared_key = perform_ecdh(password, user_salt, org_public_key_content)

        # Derive session key using HKDF
        session_key, session_salt = derive_session_key(shared_key)

        # Create session ID and expiration
        session_id = str(uuid4())
        expiration = SESSION_EXPIRATION 

        # Store session information
        session_data = {
            "session_id": session_id,
            "session_key": base64.b64encode(session_key).decode("utf-8"),
            "organization": org_name,
            "username": username,
            "expiration": expiration,
            "last_counter": 0
        }

        db["sessions"][session_id] = session_data
        save_db()

        logger.info(f"Session created successfully for user '{username}' in organization '{org_name}'.")
        return jsonify({
            "message": "Session created successfully",
            "session_id": session_id,
            "session_key": base64.b64encode(session_key).decode("utf-8"),  # Send encoded session key
            "expiration": expiration
        }), 201

    except Exception as e:
        logger.error(f"Failed to create session: {e}")
        return jsonify({"error": f"Failed to create session: {str(e)}"}), 500


@app.route("/documents/<document_name>", methods=["POST"])
@verify_request
def add_document(document_name):
    """
    Endpoint to upload and store an encrypted document.
    """
    data = request.decrypted_payload

    document_name = data.get("document_name")
    session_id = data.get("session_id")
    iv = data.get("iv")
    encrypted_content = data.get("encrypted_content")
    tag = data.get("tag")
    file_handle = data.get("file_handle")
    doc_nonce_b64 = data.get("doc_nonce")
    session_data = db["sessions"][session_id]
    username = session_data["username"]
    organization = session_data["organization"]
    session_key = session_data["session_key"]

    # Check if user has a role with DOC_NEW permission
    if not user_has_permission(session_data, organization, "DOC_NEW"):
        return jsonify({"error": "User does not have permission to add a new document"}), 403

    if not all([session_id, iv, encrypted_content, file_handle, document_name, tag]):
        return jsonify({"error": "Missing required fields."}), 400

    if session_id not in db["sessions"]:
        return jsonify({"error": "Invalid session ID"}), 403
    
    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403

    if organization not in documents:
        documents[organization] = {}

    document_handle = hmac.new(
        key=session_data["session_key"].encode("utf-8"),
        msg=document_name.encode("utf-8"),
        digestmod=hashlib.sha256
    ).hexdigest()

    public_metadata = {
        "document_handle": document_handle,
        "name": document_name,
        "create_date": str(datetime.now()),
        "creator": username,
        "file_handle": file_handle,
        "acl": {
            "DOC_READ": [username],
            "DOC_DELETE": [username],
            "DOC_ACL": [username],
        },
        "deleter": None,
    }

    restricted_metadata = {
        "algorithm": "AES-GCM",
        "tag": tag,
    }

    document_name_without_ext, _ = os.path.splitext(document_name)
    document_name_encrypted = document_name_without_ext + "encrypted"

    document_data = {
        "organization": organization,
        "public_metadata": public_metadata,
        "restricted_metadata": restricted_metadata,
        "encrypted_content": encrypted_content,
        "iv": iv,
        "doc_nonce": doc_nonce_b64,
        "session_key": session_key
    }

    documents[organization][document_name] = {
        "organization": organization,
        "public_metadata": public_metadata,
        "restricted_metadata": restricted_metadata,
        "encrypted_content": encrypted_content,
        "iv": iv,
        "doc_nonce": doc_nonce_b64,
        "session_key": session_key
    }

    with open(f"{document_name_encrypted}.json", "w") as json_file:
        json.dump(document_data, json_file, indent=4)

    # Save only document name and owner in db.json
    if "documents" not in db["organizations"][organization]:
        db["organizations"][organization]["documents"] = {}

    db["organizations"][organization]["documents"][document_name] = {
        "owner": username
    }

    save_documents()
    save_db()

    logger.info(f"Document '{document_name}' uploaded successfully by user '{username}'.")
    return jsonify({"message": f"Document '{document_name}' uploaded successfully"}), 201

def save_documents():
    """Save the documents metadata to documents.json."""
    with open("documents.json", "w") as doc_file:
        json.dump(documents, doc_file, indent=4)


@app.route("/documents/<document_name>", methods=["GET"])
@verify_request
def get_document(document_name):
    """
    Endpoint to retrieve an encrypted document using the session's organization.
    """
    data = request.decrypted_payload
    session_id = data["session_id"]

    if not session_id:
        return jsonify({"error": "Field 'session_id' is required"}), 400

    if session_id not in db["sessions"]:
        return jsonify({"error": "Invalid session ID"}), 403

    session_data = db["sessions"][session_id]
    organization = session_data["organization"]

    if organization not in db["organizations"]:
        return jsonify({"error": f"Organization '{organization}' not found"}), 404

    if (
            "documents" not in db["organizations"][organization]
            or document_name not in db["organizations"][organization]["documents"]
    ):
        return jsonify({"error": f"Document '{document_name}' not found in organization '{organization}'"}), 404
    
    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403


    if organization not in documents.keys():
        return jsonify({"error": f"Metadata for organization '{organization}' not found"}), 404

    if document_name not in documents[organization]:
        return jsonify({"error": f"Metadata for document '{document_name}' not found"}), 404

    document_metadata = documents[organization][document_name]

    # if username not in document_metadata["acl"]["DOC_READ"]:
    #     return jsonify({"error": "Access denied to read document"}), 403

    if not document_metadata["public_metadata"]["file_handle"]:
        return jsonify({"error": "Document doesnt't exist, or has been deleted"}), 404

    return jsonify({
        "owner": document_metadata["public_metadata"]["creator"],
        "iv": document_metadata["iv"],
        "encrypted_content": document_metadata["encrypted_content"],
        "file_handle": document_metadata["public_metadata"]["file_handle"],
        "tag": document_metadata["restricted_metadata"]["tag"],
        "create_date": document_metadata["public_metadata"]["create_date"],
        "acl": document_metadata["public_metadata"]["acl"],
        "doc_nonce": document_metadata["doc_nonce"],

    }), 200


@app.route("/subject/suspend", methods=["POST"])
@verify_request
def suspend_subject():
    data = request.decrypted_payload
    username = data.get("username")
    session_id = data.get("session_id")
    session_data = db["sessions"].get(session_id)
    org = session_data["organization"]

    if not user_has_permission(session_data, org, "SUBJECT_DOWN"):
        return jsonify({"error": "User does not have permission to suspend a subject"}), 403

    if not username:
        return jsonify({"error": "Username is required"}), 400

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403

    
    for subject_key, subject in db["subjects"].items():
        if subject.get("username") == username:
            if subject.get("status") == "suspended":
                return jsonify({"error": "Subject is already suspended"}), 400
            subject["status"] = "suspended"
            save_db()
            return jsonify({"message": "Subject suspended successfully"}), 200

    return jsonify({"error": "Subject not found"}), 404


@app.route("/subject/activate", methods=["POST"])
@verify_request
def activate_subject():
    data = request.decrypted_payload
    username = data.get("username")
    session_id = data.get("session_id")
    session_data = db["sessions"].get(session_id)
    org = session_data["organization"]

    if not user_has_permission(session_data, org, "SUBJECT_UP"):
        return jsonify({"error": "User does not have permission to activate a subject"}), 403

    if not username:
        return jsonify({"error": "Username is required"}), 400

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403

    
    for subject_key, subject in db["subjects"].items():
        if subject.get("username") == username:
            if subject.get("status") == "active":
                return jsonify({"error": "Subject is already active"}), 400
            subject["status"] = "active"
            save_db()
            return jsonify({"message": "Subject activated successfully"}), 200

    return jsonify({"error": "Subject not found"}), 404


@app.route("/subject/add", methods=["POST"])
@verify_request
def add_subject():
    data = request.decrypted_payload

    session_id = data.get("session_id")
    session_data = db["sessions"].get(session_id)
    org = session_data["organization"]

    # Check if user has a role with SUBJECT_NEW permission
    if not user_has_permission(session_data, org, "SUBJECT_NEW"):
        return jsonify({"error": "User does not have permission to add a new subject"}), 403

    username = data.get("username")
    name = data.get("name")
    email = data.get("email")
    public_key_pem = data.get("public_key")

    if not all([session_id, username, name, email, public_key_pem]):
        return jsonify({"error": "All fields (session_id, username, name, email, public_key) are required"}), 400

    session = db["sessions"].get(session_id)
    if not session:
        return jsonify({"error": "Invalid session ID"}), 404

    organization = session.get("organization")
    if not organization:
        return jsonify({"error": "Session is not linked to any organization"}), 400
    
    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403

    
    existing_subject = None
    for subject_key, subject in db["subjects"].items():
        if subject.get("username") == username:
            existing_subject = subject
            break

    if existing_subject:
        if organization not in existing_subject["organizations"]:
            existing_subject["organizations"].append(organization)
            db["organizations"][organization]["users"].append(username)
            save_db()
            return jsonify({"message": f"Subject '{username}' added to organization '{organization}'"}), 200
        else:
            return jsonify({"message": f"Subject '{username}' is already part of organization '{organization}'"}), 200
    else:
        new_subject = {
            "username": username,
            "name": name,
            "email": email,
            "public_key": public_key_pem,
            "organizations": [organization],
            "status": "active",
        }
        if public_key_pem in db["subjects"]:
            db["subjects"][f"{public_key_pem}_{username}"] = new_subject
        else:
            db["subjects"][public_key_pem] = new_subject

        if organization not in db["organizations"]:
            return jsonify({"error": f"Organization '{organization}' not found"}), 404

        db["organizations"][organization]["users"].append(username)
        save_db()
        return jsonify({"message": "Subject added successfully"}), 201


@app.route("/subjects/list", methods=["POST"])
@verify_request
def list_subjects():
    """
    List all subjects in the organization associated with the current session.
    Optionally, return details for a specific subject if a username is provided.
    """
    data = request.decrypted_payload

    session_id = data.get("session_id")
    username_filter = data.get("username")

    if session_id not in db["sessions"]:
        return jsonify({"error": "Invalid session ID"}), 403

    session_data = db["sessions"][session_id]
    organization = session_data["organization"]

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403

    
    subjects = []
    for public_key, subject_data in db["subjects"].items():
        if organization in subject_data["organizations"]:
            if username_filter:
                if subject_data["username"] == username_filter:
                    return jsonify({
                        "username": subject_data["username"],
                        "name": subject_data["name"],
                        "email": subject_data["email"],
                        "status": subject_data["status"]
                    }), 200
            else:
                subjects.append({
                    "username": subject_data["username"],
                    "name": subject_data["name"],
                    "email": subject_data["email"],
                    "status": subject_data["status"]
                })

    if username_filter:
        return jsonify({"error": f"Subject '{username_filter}' not found in organization"}), 404

    return jsonify(subjects), 200


@app.route("/documents/<document_name>/metadata", methods=["POST"])
@verify_request
def get_doc_metadata(document_name):
    """
    Retrieves metadata for a specific document.
    """
    data = request.decrypted_payload
    session_id = data.get("session_id")
    session_data = db["sessions"][session_id]
    organization = session_data["organization"]
    document_metadata = documents[organization][document_name]

    # Check if user has a role with DOC_READ permission
    if not user_has_permission(session_data, organization, "DOC_READ"):
        return jsonify({"error": "User does not have permission to read document metadata"}), 403

    if not session_id:
        return jsonify({"error": "Field 'session_id' is required"}), 400

    if session_id not in db["sessions"]:
        return jsonify({"error": "Invalid session ID"}), 403
    
    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403


    if organization not in documents:
        return jsonify({"error": f"Metadata for organization '{organization}' not found"}), 404

    if document_name not in documents[organization]:
        return jsonify({"error": f"Metadata for document '{document_name}' not found"}), 404

    if not document_metadata["public_metadata"]["file_handle"]:
        return jsonify({"error": "Document doesnt't exist, or has been deleted"}), 404

    return jsonify({
        "creator": document_metadata["public_metadata"]["creator"],
        "iv": document_metadata["iv"],
        "encrypted_content": document_metadata["encrypted_content"],
        "file_handle": document_metadata["public_metadata"]["file_handle"],
        "create_date": document_metadata["public_metadata"]["create_date"],
        "acl": document_metadata["public_metadata"]["acl"],
        "algorithm": document_metadata["restricted_metadata"]["algorithm"],
        "tag": document_metadata["restricted_metadata"]["tag"],
        "doc_nonce": document_metadata["doc_nonce"],
        "session_key": session_data["session_key"]
    }), 200


@app.route("/documents/<document_name>/file", methods=["GET"])
@verify_request
def get_doc_file(document_name):
    """
    Downloads a specific document file, returning its encrypted content and all necessary
    parameters to decrypt it. Requires 'session_id' as a query parameter.
    """

    data = request.decrypted_payload

    session_id = data.get("session_id")
    session_data = db["sessions"].get(session_id)
    org = session_data["organization"]

    # Check if user has a role with DOC_READ permission
    if not user_has_permission(session_data, org, "DOC_READ"):
        return jsonify({"error": "User does not have permission to read document file"}), 403

    if not session_id:
        return jsonify({"error": "Field 'session_id' is required"}), 400

    if session_id not in db["sessions"]:
        return jsonify({"error": "Invalid session ID"}), 403
    
    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403


    session_data = db["sessions"][session_id]
    organization = session_data["organization"]
    if organization not in db["organizations"]:
        return jsonify({"error": f"Organization '{organization}' not found"}), 404

    if ("documents" not in db["organizations"][organization]
            or document_name not in db["organizations"][organization]["documents"]):
        return jsonify({"error": f"Document '{document_name}' not found in organization '{organization}'"}), 404

    if organization not in documents or document_name not in documents[organization]:
        return jsonify({"error": f"Metadata for document '{document_name}' not found"}), 404

    document_metadata = documents[organization][document_name]

    if not document_metadata["public_metadata"]["file_handle"]:
        return jsonify({"error": "Document doesnt't exist, or has been deleted"}), 404

    return jsonify({
        "iv": document_metadata["iv"],
        "encrypted_content": document_metadata["encrypted_content"],
        "tag": document_metadata["restricted_metadata"]["tag"],
        "doc_nonce": document_metadata["doc_nonce"]
    }), 200


@app.route("/documents/<document_name>", methods=["DELETE"])
@verify_request
def delete_document(document_name):
    """
    Clears the file handle for a specific document, effectively deleting it.
    """
    data = request.decrypted_payload
    session_id = data.get("session_id")
    session_data = db["sessions"][session_id]
    organization = session_data["organization"]

    # Check if user has a role with DOC_DELETE permission
    if not user_has_permission(session_data, organization, "DOC_DELETE"):
        return jsonify({"error": "User does not have permission to delete document"}), 403

    if not session_id:
        return jsonify({"error": "Field 'session_id' is required"}), 400

    if session_id not in db["sessions"]:
        return jsonify({"error": "Invalid session ID"}), 403

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403


    if organization not in documents:
        return jsonify({"error": f"Metadata for organization '{organization}' not found"}), 404

    if document_name not in documents[organization]:
        return jsonify({"error": f"Metadata for document '{document_name}' not found"}), 404

    document_metadata = documents[organization][document_name]

    cleared_file_handle = document_metadata["public_metadata"]["file_handle"]

    document_metadata["public_metadata"]["file_handle"] = None
    document_metadata["public_metadata"]["deleter"] = session_data["username"]

    save_documents()
    save_db()

    return jsonify({"message": f"Document '{document_name}' deleted successfully",
                    "cleared_file_handle": cleared_file_handle}), 200


@app.route("/documents", methods=["POST"])
@verify_request
def list_documents():
    data = request.decrypted_payload
    username_filter = data.get("username")
    date_filter_type = data.get("date_filter_type")
    date_filter_value = data.get("date_filter_value")

    filtered_documents = []

    for org, docs in documents.items():
        for doc_name, metadata in docs.items():
            creator = metadata["public_metadata"]["creator"]
            create_date_str = metadata["public_metadata"]["create_date"]
            create_date = datetime.strptime(create_date_str, "%Y-%m-%d %H:%M:%S.%f")

            # Filter by username
            if username_filter and creator != username_filter:
                continue

            if not metadata["public_metadata"]["file_handle"]:
                continue

            # Filter by date if provided
            if date_filter_value:
                filter_date = datetime.strptime(date_filter_value, "%d-%m-%Y")
                if date_filter_type == "nt" and create_date <= filter_date:
                    continue
                elif date_filter_type == "ot" and create_date >= filter_date:
                    continue
                elif date_filter_type == "et" and create_date.date() != filter_date.date():
                    continue

            filtered_documents.append({
                "document_name": doc_name,
                "owner": creator,
                "create_date": create_date_str
            })

    return jsonify(filtered_documents), 200


@app.route("/file/<path:file_handle>", methods=["GET"])
def get_file(file_handle):

    decoded_handle = unquote(file_handle)

    document_name = None
    document_metadata = None

    for _, docs in documents.items():
        for doc_name, metadata in docs.items():
            if metadata["public_metadata"]["file_handle"] == decoded_handle:
                document_name = doc_name
                document_metadata = metadata
                break
        if document_name:
            break

    if not document_name:
        return jsonify({"error": f"File handle '{decoded_handle}' not found"}), 404

    if not document_metadata["public_metadata"]["file_handle"]:
        return jsonify({"error": "Document doesnt't exist, or has been deleted"}), 404

    return jsonify({
        "document_name": document_metadata["public_metadata"]["name"],
        "file_handle": document_metadata["public_metadata"]["file_handle"],
        "encrypted_content": document_metadata["encrypted_content"],
        "owner": document_metadata["public_metadata"]["creator"]
    }), 200


@app.route("/file/decrypt", methods=["POST"])
def decrypt_file():
    try:
        data = request.json
        session_id = data.get("session_id")
        doc_nonce_b64 = data.get("doc_nonce")
        encrypted_content_b64 = data.get("encrypted_content")
        iv_b64 = data.get("iv")
        tag_b64 = data.get("tag")

        if not all([session_id, doc_nonce_b64, encrypted_content_b64, iv_b64, tag_b64]):
            return jsonify(
                {"error": "Missing required fields (session_id, doc_nonce, encrypted_content, iv, tag)."}), 400

        if session_id not in db["sessions"]:
            return jsonify({"error": "Invalid session ID"}), 403

        session_data = db["sessions"][session_id]
        session_key = base64.b64decode(session_data["session_key"])

        doc_nonce = base64.b64decode(doc_nonce_b64)
        iv = base64.b64decode(iv_b64)
        tag = base64.b64decode(tag_b64)
        encrypted_content = base64.b64decode(encrypted_content_b64)

        # Derive doc_key using the session_key and doc_nonce
        doc_key = derive_document_key(session_key, doc_nonce)

        # Decrypt the content using doc_key
        cipher = Cipher(algorithms.AES(doc_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()

        return jsonify({
            "decrypted_content": base64.b64encode(decrypted_content).decode('utf-8')
        }), 200

    except Exception as e:
        return jsonify({"error": f"Failed to decrypt file: {str(e)}"}), 500


@app.route("/session/role/assume", methods=["POST"])
@verify_request
def assume_role():
    data = request.decrypted_payload
    session_id = data.get("session_id")
    role = data.get("role")

    if not session_id or not role:
        return jsonify({"error": "Missing session_id or role"}), 400

    session_data = db["sessions"].get(session_id)
    if not session_data:
        return jsonify({"error": "Invalid session ID"}), 403

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403


    org = session_data["organization"]
    org_data = db["organizations"].get(org, {})
    org_roles = org_data.get("roles", {})

    if role not in org_roles:
        return jsonify({"error": f"Role '{role}' not found"}), 404


    if org_roles[role]["status"] != "active":
        return jsonify({"error": "Role is not active"}), 403
    

    # add subject to the roles subjects
    if session_data["username"] not in org_roles[role]["subjects"]:
        org_roles[role]["subjects"].append(session_data["username"])

    if "active_roles" not in session_data:
        session_data["active_roles"] = []
    if role not in session_data["active_roles"]:
        session_data["active_roles"].append(role)

    if "assumed_roles" not in session_data:
        session_data["assumed_roles"] = []

    if role not in session_data["assumed_roles"]:
        session_data["assumed_roles"].append(role)
    else:
        return jsonify({"error": "Role already assumed"}), 403

    db["sessions"][session_id] = session_data
    save_db()
    return jsonify({"message": f"Role '{role}' assumed successfully"}), 200


@app.route("/session/role/drop", methods=["POST"])
@verify_request
def drop_role():
    data = request.decrypted_payload
    session_id = data.get("session_id")
    role = data.get("role")

    if not session_id or not role:
        return jsonify({"error": "Missing session_id or role"}), 400

    session_data = db["sessions"].get(session_id)
    if not session_data:
        return jsonify({"error": "Invalid session ID"}), 403

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403

    if "active_roles" not in session_data or role not in session_data["active_roles"]:
        return jsonify({"error": f"Role '{role}' not assumed in this session"}), 400

    org = session_data["organization"]
    org_data = db["organizations"].get(org)
    if not org_data:
        return jsonify({"error": "Organization not found"}), 404

    roles = org_data.get("roles", {})
    if role not in roles:
        return jsonify({"error": f"Role '{role}' not found in organization"}), 404

    session_data["active_roles"].remove(role)
    session_data["assumed_roles"].remove(role)

    db["sessions"][session_id] = session_data
    save_db()
    return jsonify({"message": f"Role '{role}' dropped successfully"}), 200


@app.route("/session/roles", methods=["GET"])
@verify_request
def list_session_roles():
    data = request.decrypted_payload
    session_id = data.get("session_id")

    if not session_id:
        return jsonify({"error": "session_id is required"}), 400
    session_data = db["sessions"].get(session_id)
    if not session_data:
        return jsonify({"error": "Invalid session ID"}), 403

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403

    roles = session_data.get("active_roles", [])
    return jsonify({"roles": roles}), 200


@app.route("/role/add", methods=["POST"])
@verify_request
def add_role():
    data = request.decrypted_payload
    session_id = data.get("session_id")
    new_role = data.get("role")
    session_data = db["sessions"].get(session_id)
    org = session_data["organization"]

    # Check if user has a role with ROLE_NEW permission
    if not user_has_permission(session_data, org, "ROLE_NEW"):
        return jsonify({"error": "User does not have permission to add a new role"}), 403

    if not session_id or not new_role:
        return jsonify({"error": "Missing session_id or role"}), 400

    if not session_data:
        return jsonify({"error": "Invalid session ID"}), 403

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403

    if org not in db["organizations"]:
        return jsonify({"error": f"Organization '{org}' not found"}), 404

    # Create the role
    if "roles" not in db["organizations"][org]:
        db["organizations"][org]["roles"] = {}
    if new_role in db["organizations"][org]["roles"]:
        return jsonify({"error": "Role already exists"}), 400


    db["organizations"][org]["roles"][new_role] = {
        "permissions": [],
        "subjects": [],
        "status": "active"
    }

    if "active_roles" not in session_data:
        session_data["active_roles"] = []

    session_data["active_roles"].append(new_role)

    save_db()
    return jsonify({"message": f"Role '{new_role}' added successfully"}), 201


@app.route("/role/<role>/permissions", methods=["GET"])
@verify_request
def list_role_permissions(role):
    data = request.decrypted_payload
    session_id = data.get("session_id")
    if not session_id or session_id not in db["sessions"]:
        return jsonify({"error": "Invalid or missing session_id"}), 403

    session_data = db["sessions"][session_id]
    org = session_data["organization"]
    org_data = db["organizations"].get(org, {})
    org_roles = org_data.get("roles", {})

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403

    if role not in org_roles:
        return jsonify({"error": f"Role '{role}' not found"}), 404

    perms = org_roles[role].get("permissions", [])
    return jsonify({"permissions": perms}), 200


@app.route("/permission/<permission>/roles", methods=["GET"])
@verify_request
def list_permission_roles(permission):
    data = request.decrypted_payload
    session_id = data.get("session_id")
    if not session_id or session_id not in db["sessions"]:
        return jsonify({"error": "Invalid or missing session_id"}), 403

    session_data = db["sessions"][session_id]
    org = session_data["organization"]
    org_data = db["organizations"].get(org, {})
    org_roles = org_data.get("roles", {})

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403

    matching_roles = [r for r, d in org_roles.items() if permission in d.get("permissions", [])]

    return jsonify({"roles": matching_roles}), 200


@app.route("/role/suspend", methods=["POST"])
@verify_request
def suspend_role():
    data = request.decrypted_payload
    session_id = data.get("session_id")
    role = data.get("role")
    session_data = db["sessions"].get(session_id)
    org = session_data["organization"]
    org_data = db["organizations"][org]
    org_roles = org_data.get("roles", {})

    if not session_id or not role:
        return jsonify({"error": "Missing session_id or role"}), 400
    
    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403

    # Check if role is already suspended
    if org_roles.get(role, {}).get("status") == "suspended":
        return jsonify({"error": "Role is already suspended"}), 400

    # Check if user has a role with ROLE_DOWN permission
    if not user_has_permission(session_data, org, "ROLE_DOWN"):
        return jsonify({"error": "No permission (ROLE_DOWN)"}), 403

    if not session_data:
        return jsonify({"error": "Invalid session ID"}), 403

    if role not in org_roles:
        return jsonify({"error": f"Role '{role}' not found"}), 404

    if role == "Managers":
        return jsonify({"error": "Cannot suspend Managers role"}), 400

    org_roles[role]["status"] = "suspended"
    save_db()
    return jsonify({"message": f"Role '{role}' suspended successfully"}), 200


@app.route("/role/reactivate", methods=["POST"])
@verify_request
def reactivate_role():
    data = request.decrypted_payload
    session_id = data.get("session_id")
    role = data.get("role")
    session_data = db["sessions"].get(session_id)

    org = session_data["organization"]
    org_data = db["organizations"][org]
    org_roles = org_data.get("roles", {})

    if not session_id or not role:
        return jsonify({"error": "Missing session_id or role"}), 400

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403


    # Check if user has a role with ROLE_UP permission
    if not user_has_permission(session_data, org, "ROLE_UP"):
        return jsonify({"error": "No permission (ROLE_UP)"}), 403

    # Check if role is already active
    if org_roles.get(role, {}).get("status") == "active":
        return jsonify({"error": "Role is already active"}), 400

    if not session_data:
        return jsonify({"error": "Invalid session ID"}), 403

    if role not in org_roles:
        return jsonify({"error": f"Role '{role}' not found"}), 404

    org_roles[role]["status"] = "active"
    save_db()
    return jsonify({"message": f"Role '{role}' reactivated successfully"}), 200


@app.route("/subject/<username>/roles", methods=["GET"])
@verify_request
def list_subject_roles(username):

    data = request.decrypted_payload
    session_id = data.get("session_id")
    if not session_id or session_id not in db["sessions"]:
        return jsonify({"error": "Invalid or missing session_id"}), 403

    session_data = db["sessions"][session_id]
    org = session_data["organization"]
    org_data = db["organizations"].get(org, {})
    org_roles = org_data.get("roles", {})

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403


    # check if username is in the org
    if username not in org_data.get("users", []):
        return jsonify({"error": "User not found"}), 404
    # Find roles that the subject belongs to
    subject_roles = []
    for role_name, role_data in org_roles.items():
        if username in role_data["subjects"]:
            subject_roles.append(role_name)

    return jsonify({"roles": subject_roles}), 200


@app.route("/role/<role>/subjects", methods=["GET"])
@verify_request
def list_role_subjects(role):
    data = request.decrypted_payload
    session_id = data.get("session_id")
    if not session_id or session_id not in db["sessions"]:
        return jsonify({"error": "Invalid or missing session_id"}), 403

    session_data = db["sessions"][session_id]
    org = session_data["organization"]
    org_data = db["organizations"].get(org, {})
    org_roles = org_data.get("roles", {})

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403


    if role not in org_roles:
        return jsonify({"error": f"Role '{role}' not found"}), 404

    subs = org_roles[role]["subjects"]
    return jsonify({"subjects": subs}), 200


@app.route("/documents/<document_name>/acl", methods=["POST"])
@verify_request
def change_doc_acl(document_name):
    data = request.decrypted_payload
    session_id = data.get("session_id")
    sign = data.get("sign")
    role = data.get("role")
    permission = data.get("permission")
    session_data = db["sessions"].get(session_id)
    org = session_data["organization"]

    # Check if user has a role with DOC_ACL permission
    if not user_has_permission(session_data, org, "DOC_ACL"):
        return jsonify({"error": "No permission (DOC_ACL)"}), 403

    if not all([session_id, sign, role, permission]):
        return jsonify({"error": "Missing fields"}), 400

    if not session_data:
        return jsonify({"error": "Invalid session ID"}), 403

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403


    if not permission.startswith("DOC_"):
        return jsonify({"error": "Not a valid permission"}), 400

    if org not in documents:
        return jsonify({"error": f"Organization '{org}' not found"}), 404
    if document_name not in documents[org]:
        return jsonify({"error": f"Document '{document_name}' not found"}), 404

    doc_metadata = documents[org][document_name]
    doc_acl = doc_metadata["public_metadata"]["acl"]

    if sign == "+":
        if permission not in doc_acl:
            doc_acl[permission] = []
        if role not in doc_acl[permission]:
            doc_acl[permission].append(role)
    elif sign == "-":
        if permission in doc_acl and role in doc_acl[permission]:
            doc_acl[permission].remove(role)
    else:
        return jsonify({"error": "Invalid sign. Use + or -."}), 400

    save_documents()
    return jsonify({"message": "Document ACL updated successfully"}), 200


@app.route("/role/permission/add", methods=["POST"])
@verify_request
def add_permission_to_role():
    data = request.decrypted_payload
    session_id = data.get("session_id")
    role = data.get("role")
    permission = data.get("permission")
    session_data = db["sessions"].get(session_id)
    org = session_data["organization"]
    org_data = db["organizations"][org]
    org_roles = org_data["roles"]

    # Check if user has a role with ROLE_MOD permission
    if not user_has_permission(session_data, org, "ROLE_MOD"):
        return jsonify({"error": "No permission (ROLE_MOD)"}), 403

    if not all([session_id, role, permission]):
        return jsonify({"error": "Missing fields"}), 400

    if not session_data:
        return jsonify({"error": "Invalid session ID"}), 403

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403


    if role not in org_roles:
        return jsonify({"error": f"Role '{role}' not found"}), 404

    if permission in org_roles[role]["permissions"]:
        return jsonify({"error": f"Permission '{permission}' already in role '{role}'"}), 400

    org_roles[role]["permissions"].append(permission)

    save_db()
    return jsonify({"message": f"Permission '{permission}' added to role '{role}'"}), 200


@app.route("/role/permission/remove", methods=["POST"])
@verify_request
def remove_permission_from_role():
    data = request.decrypted_payload
    session_id = data.get("session_id")
    role = data.get("role")
    permission = data.get("permission")
    session_data = db["sessions"].get(session_id)
    org = session_data["organization"]
    org_data = db["organizations"][org]
    org_roles = org_data["roles"]

    # Check if user has a role with ROLE_MOD permission
    if not user_has_permission(session_data, org, "ROLE_MOD"):
        return jsonify({"error": "No permission (ROLE_MOD)"}), 403

    if not all([session_id, role, permission]):
        return jsonify({"error": "Missing fields"}), 400

    if not session_data:
        return jsonify({"error": "Invalid session ID"}), 403

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403


    if role not in org_roles:
        return jsonify({"error": f"Role '{role}' not found"}), 404

    if permission not in org_roles[role]["permissions"]:
        return jsonify({"error": f"Permission '{permission}' not found in role '{role}'"}), 404

    org_roles[role]["permissions"].remove(permission)

    save_db()
    return jsonify({"message": f"Permission '{permission}' removed from role '{role}'"}), 200


@app.route("/role/subject/add", methods=["POST"])
@verify_request
def add_subject_to_role():
    data = request.decrypted_payload
    session_id = data.get("session_id")
    role = data.get("role")
    username = data.get("username")

    if not all([session_id, role, username]):
        return jsonify({"error": "Missing fields"}), 400

    session_data = db["sessions"].get(session_id)
    if not session_data:
        return jsonify({"error": "Invalid session ID"}), 403

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403

    org = session_data["organization"]
    if not user_has_permission(session_data, org, "ROLE_MOD"):
        return jsonify({"error": "No permission (ROLE_MOD)"}), 403


    org_data = db["organizations"][org]
    org_roles = org_data["roles"]

    if role not in org_roles:
        return jsonify({"error": f"Role '{role}' not found"}), 404

    # Check if user is in organization
    if username not in org_data["users"]:
        return jsonify({"error": f"User '{username}' not in organization"}), 404

    # Check if user already has the role
    if username in org_roles[role]["subjects"]:
        return jsonify({"error": f"User '{username}' already has role '{role}'"}), 400

    org_roles[role]["subjects"].append(username)

    save_db()
    return jsonify({"message": f"Subject '{username}' added to role '{role}'"}), 200


@app.route("/role/subject/remove", methods=["POST"])
@verify_request
def remove_subject_from_role():
    data = request.decrypted_payload
    session_id = data.get("session_id")
    role = data.get("role")
    username = data.get("username")

    if not all([session_id, role, username]):
        return jsonify({"error": "Missing fields"}), 400

    session_data = db["sessions"].get(session_id)
    if not session_data:
        return jsonify({"error": "Invalid session ID"}), 403

    if is_session_expired(session_id):
        return jsonify({"error": "Session has expired"}), 403


    org = session_data["organization"]
    if not user_has_permission(session_data, org, "ROLE_MOD"):
        return jsonify({"error": "No permission (ROLE_MOD)"}), 403

    org_data = db["organizations"][org]
    org_roles = org_data["roles"]

    if role not in org_roles:
        return jsonify({"error": f"Role '{role}' not found"}), 404

    # check if subject has the role
    if username not in org_roles[role]["subjects"]:
        return jsonify({"error": f"Subject '{username}' not in role '{role}'"}), 404

    org_roles[role]["subjects"].remove(username)

        # Ensure if role is "Managers", it still has an active subject
        # If no active subject in Managers role, revert
        # (Implement that logic as needed)

    save_db()
    return jsonify({"message": f"Subject '{username}' removed from role '{role}'"}), 200


if __name__ == "__main__":
    app.run(debug=True)
