from functools import wraps

from flask import Flask, request, jsonify
from utils.crypto_utils import load_public_key
import json
import os
from uuid import uuid4
import logging
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
import logging
from datetime import datetime
from utils.crypto_utils import *
import base64
from datetime import datetime
import hmac
import hashlib


from db import load_db, save_db
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Load the database into memory
db = load_db()
documents = json.load(open("documents.json"))


@app.route("/organization/list", methods=["GET"])
def list_organizations():
    organizations = db["organizations"]
    return jsonify(organizations), 200

## === Helper Functions ===
def user_has_permission(session_data, org, permission):
    assumed_role = session_data.get("assumed_role")
    if not assumed_role:
        print("No role assumed.")
        return False

    org_data = db["organizations"].get(org, {})
    org_roles = org_data.get("roles", {})

    role_data = org_roles.get(assumed_role)
    if not role_data:
        print(f"Assumed role '{assumed_role}' does not exist.")
        return False

    if role_data.get("status") != "active":
        print(f"Assumed role '{assumed_role}' is not active.")
        return False

    if permission in role_data.get("permissions", []):
        return True

    print(f"Permission '{permission}' not found in assumed role '{assumed_role}'.")
    return False


def get_user_public_key(username, org):
    for pk, subj in db["subjects"].items():
        if subj["username"] == username and org in subj["organizations"]:
            return pk
    return None


def verify_counter(func):
    @wraps(func)
    def wrapper(document_name):
        data = request.get_json()
        session_id = data.get("session_id")
        counter = data.get("counter")

        if not session_id or not counter:
            return jsonify({"error": "Missing session_id or counter"}), 400

        session_data = db["sessions"].get(session_id)
        if not session_data:
            return jsonify({"error": "Invalid session ID"}), 403

        last_counter = session_data.get("last_counter", 0)
        if counter != last_counter + 1:
            return jsonify({"error": "Invalid counter value"}), 403

        # Update the last_counter
        db["sessions"][session_id]["last_counter"] = counter
        save_db()

        return func(document_name)

    return wrapper


@app.route("/organization/create", methods=["POST"])
def create_organization():
    data = request.get_json()
    org_name = data.get("organization")
    username = data.get("username")
    name = data.get("name")
    email = data.get("email")
    credentials_content = data.get("credentials_file")

    if not all([org_name, username, name, email, credentials_content]):
        return jsonify({"error": "All fields (...) are required"}), 400

    if org_name in db["organizations"]:
        return jsonify({"error": f"Organization '{org_name}' already exists"}), 400

    try:
        public_key = load_public_key(credentials_content)
        public_key_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
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



@app.route("/session/create", methods=["POST"])
def create_session():
    data = request.get_json()
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
        expiration = None  # Set expiration for 1 hour

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
@verify_counter
def add_document(document_name):
    """
    Endpoint to upload and store an encrypted document.
    """
    data = request.get_json()

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

    # Check if user has a role with DOC_NEW permission
    if not user_has_permission(session_data, organization, "DOC_NEW"):
        return jsonify({"error": "User does not have permission to add a new document"}), 403

    if not all([session_id, iv, encrypted_content, file_handle, document_name, tag]):
        return jsonify({"error": "Missing required fields."}), 400

    if session_id not in db["sessions"]:
        return jsonify({"error": "Invalid session ID"}), 403

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


    documents[organization][document_name] = {
        "public_metadata": public_metadata,
        "restricted_metadata": restricted_metadata,
        "encrypted_content": encrypted_content,
        "iv": iv,
        "doc_nonce": doc_nonce_b64,
    }

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
def get_document(document_name):
    """
    Endpoint to retrieve an encrypted document using the session's organization.
    """
    session_id = request.args.get("session_id") 

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

    if organization not in documents.keys():
        return jsonify({"error": f"Metadata for organization '{organization}' not found"}), 404

    if document_name not in documents[organization]:
        return jsonify({"error": f"Metadata for document '{document_name}' not found"}), 404

    document_metadata = documents[organization][document_name]

    # if username not in document_metadata["acl"]["DOC_READ"]:
    #     return jsonify({"error": "Access denied to read document"}), 403

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
def suspend_subject():
    data = request.get_json()
    username = data.get("username")
    session_id = data.get("session_id")
    session_data = db["sessions"].get(session_id)
    org = session_data["organization"]

    if not user_has_permission(session_data, org, "SUBJECT_DOWN"):
        return jsonify({"error": "User does not have permission to suspend a subject"}), 403

    if not username:
        return jsonify({"error": "Username is required"}), 400

    for subject_key, subject in db["subjects"].items():
        if subject.get("username") == username:
            if subject.get("status") == "suspended":
                return jsonify({"error": "Subject is already suspended"}), 400
            subject["status"] = "suspended"
            save_db()
            return jsonify({"message": "Subject suspended successfully"}), 200

    return jsonify({"error": "Subject not found"}), 404


@app.route("/subject/activate", methods=["POST"])
def activate_subject():
    data = request.get_json()
    username = data.get("username")
    session_id = data.get("session_id")
    session_data = db["sessions"].get(session_id)
    org = session_data["organization"]

    if not user_has_permission(session_data, org, "SUBJECT_UP"):
        return jsonify({"error": "User does not have permission to activate a subject"}), 403

    if not username:
        return jsonify({"error": "Username is required"}), 400

    for subject_key, subject in db["subjects"].items():
        if subject.get("username") == username:
            if subject.get("status") == "active":
                return jsonify({"error": "Subject is already active"}), 400
            subject["status"] = "active"
            save_db()
            return jsonify({"message": "Subject activated successfully"}), 200

    return jsonify({"error": "Subject not found"}), 404


@app.route("/subject/add", methods=["POST"])
def add_subject():
    data = request.get_json()

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
def list_subjects():
    """
    List all subjects in the organization associated with the current session.
    Optionally, return details for a specific subject if a username is provided.
    """
    data = request.get_json()

    session_id = data.get("session_id")
    username_filter = data.get("username")  

    if session_id not in db["sessions"]:
        return jsonify({"error": "Invalid session ID"}), 403

    session_data = db["sessions"][session_id]
    organization = session_data["organization"]

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

@app.route("/documents/<document_name>/metadata", methods=["GET"])
def get_doc_metadata(document_name):
    """
    Retrieves metadata for a specific document.
    """
    session_id = request.args.get("session_id") 
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

    if organization not in documents:
        return jsonify({"error": f"Metadata for organization '{organization}' not found"}), 404

    if document_name not in documents[organization]:
        return jsonify({"error": f"Metadata for document '{document_name}' not found"}), 404


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
def get_doc_file(document_name):
    """
    Downloads a specific document file, returning its encrypted content and all necessary
    parameters to decrypt it. Requires 'session_id' as a query parameter.
    """


    data = request.get_json()

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
    return jsonify({
        "iv": document_metadata["iv"],
        "encrypted_content": document_metadata["encrypted_content"],
        "tag": document_metadata["restricted_metadata"]["tag"],
        "doc_nonce": document_metadata["doc_nonce"]
    }), 200


@app.route("/documents/<document_name>", methods=["DELETE"])
def delete_document(document_name):
    """
    Clears the file handle for a specific document, effectively deleting it.
    """
    data = request.get_json()
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

    return jsonify({"message": f"Document '{document_name}' deleted successfully", "cleared_file_handle": cleared_file_handle}), 200


@app.route("/documents", methods=["GET"])
def list_documents():
    username_filter = request.args.get("username")
    date_filter_type = request.args.get("date_filter_type")
    date_filter_value = request.args.get("date_filter_value")

    filtered_documents = []

    for org, docs in documents.items():
        for doc_name, metadata in docs.items():
            creator = metadata["public_metadata"]["creator"]
            create_date_str = metadata["public_metadata"]["create_date"]
            create_date = datetime.strptime(create_date_str, "%Y-%m-%d %H:%M:%S.%f")

            # Filter by username
            if username_filter and creator != username_filter:
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


@app.route("/file/<file_handle>", methods=["GET"])
def get_file(file_handle):
    document_name = None
    document_metadata = None

    for _, docs in documents.items():
        for doc_name, metadata in docs.items():
            if metadata["public_metadata"]["file_handle"] == file_handle:
                document_name = doc_name
                document_metadata = metadata
                break
        if document_name:
            break

    if not document_name:
        return jsonify({"error": f"File handle '{file_handle}' not found"}), 404

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
            return jsonify({"error": "Missing required fields (session_id, doc_nonce, encrypted_content, iv, tag)."}), 400

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
def assume_role():
    data = request.get_json()
    session_id = data.get("session_id")
    role = data.get("role")

    if not session_id or not role:
        return jsonify({"error": "Missing session_id or role"}), 400

    session_data = db["sessions"].get(session_id)
    if not session_data:
        return jsonify({"error": "Invalid session ID"}), 403

    org = session_data["organization"]
    org_data = db["organizations"].get(org, {})
    org_roles = org_data.get("roles", {})

    if role not in org_roles:
        return jsonify({"error": f"Role '{role}' not found"}), 404
    
    username = session_data["username"]

    # if username not in org_roles[role]["subjects"]:
    #     return jsonify({"error": "User not authorized for this role"}), 403
    
    if org_roles[role]["status"] != "active":
        return jsonify({"error": "Role is not active"}), 403

    if "active_roles" not in session_data:
        session_data["active_roles"] = []
    if role not in session_data["active_roles"]:
        session_data["active_roles"].append(role)

    db["sessions"][session_id]["assumed_role"] = role
    db["sessions"][session_id] = session_data
    save_db()
    return jsonify({"message": f"Role '{role}' assumed successfully"}), 200

@app.route("/session/role/drop", methods=["POST"])
def drop_role():
    data = request.get_json()
    session_id = data.get("session_id")
    role = data.get("role")

    if not session_id or not role:
        return jsonify({"error": "Missing session_id or role"}), 400

    session_data = db["sessions"].get(session_id)
    if not session_data:
        return jsonify({"error": "Invalid session ID"}), 403

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

    if db["sessions"][session_id].get("assumed_role") == role:
        db["sessions"][session_id]["assumed_role"] = None
        
    db["sessions"][session_id] = session_data
    del org_data["roles"][role]
    save_db()
    return jsonify({"message": f"Role '{role}' dropped successfully"}), 200

@app.route("/session/roles", methods=["GET"])
def list_session_roles():
    session_id = request.args.get("session_id")

    if not session_id:
        return jsonify({"error": "session_id is required"}), 400
    session_data = db["sessions"].get(session_id)
    if not session_data:
        return jsonify({"error": "Invalid session ID"}), 403

    roles = session_data.get("active_roles", [])
    return jsonify({"roles": roles}), 200


@app.route("/role/add", methods=["POST"])
def add_role():
    data = request.get_json()
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

    if org not in db["organizations"]:
        return jsonify({"error": f"Organization '{org}' not found"}), 404

    # Create the role
    if "roles" not in db["organizations"][org]:
        db["organizations"][org]["roles"] = {}
    if new_role in db["organizations"][org]["roles"]:
        return jsonify({"error": "Role already exists"}), 400

    #session_data["active_roles"].append(new_role)

    db["organizations"][org]["roles"][new_role] = {
        "permissions": [],
        "subjects": [],
        "status": "active"
    }
    save_db()
    return jsonify({"message": f"Role '{new_role}' added successfully"}), 201


@app.route("/role/<role>/permissions", methods=["GET"])
def list_role_permissions(role):
    session_id = request.args.get("session_id")
    if not session_id or session_id not in db["sessions"]:
        return jsonify({"error": "Invalid or missing session_id"}), 403

    session_data = db["sessions"][session_id]
    org = session_data["organization"]
    org_data = db["organizations"].get(org, {})
    org_roles = org_data.get("roles", {})

    if role not in org_roles:
        return jsonify({"error": f"Role '{role}' not found"}), 404
    
    perms = org_roles[role].get("permissions", [])
    return jsonify({"permissions": perms}), 200



@app.route("/permission/<permission>/roles", methods=["GET"])
def list_permission_roles(permission):
    session_id = request.args.get("session_id")
    if not session_id or session_id not in db["sessions"]:
        return jsonify({"error": "Invalid or missing session_id"}), 403

    session_data = db["sessions"][session_id]
    org = session_data["organization"]
    org_data = db["organizations"].get(org, {})
    org_roles = org_data.get("roles", {})

    matching_roles = [r for r, d in org_roles.items() if permission in d.get("permissions", [])]

    return jsonify({"roles": matching_roles}), 200



@app.route("/role/suspend", methods=["POST"])
def suspend_role():
    data = request.get_json()
    session_id = data.get("session_id")
    role = data.get("role")
    session_data = db["sessions"].get(session_id)
    org = session_data["organization"]
    org_data = db["organizations"][org]
    org_roles = org_data.get("roles", {})


    if not session_id or not role:
        return jsonify({"error": "Missing session_id or role"}), 400
    
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
def reactivate_role():
    data = request.get_json()
    session_id = data.get("session_id")
    role = data.get("role")
    session_data = db["sessions"].get(session_id)

    org = session_data["organization"]
    org_data = db["organizations"][org]
    org_roles = org_data.get("roles", {})
    
    if not session_id or not role:
        return jsonify({"error": "Missing session_id or role"}), 400


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
def list_subject_roles(username):
    session_id = request.args.get("session_id")
    if not session_id or session_id not in db["sessions"]:
        return jsonify({"error": "Invalid or missing session_id"}), 403
    
    session_data = db["sessions"][session_id]
    org = session_data["organization"]
    org_data = db["organizations"].get(org, {})
    org_roles = org_data.get("roles", {})

    # Find roles that the subject belongs to
    subject_roles = []
    for role_name, role_data in org_roles.items():
        if username in role_data["subjects"]:
            subject_roles.append(role_name)

    return jsonify({"roles": subject_roles}), 200


@app.route("/role/<role>/subjects", methods=["GET"])
def list_role_subjects(role):
    session_id = request.args.get("session_id")
    if not session_id or session_id not in db["sessions"]:
        return jsonify({"error": "Invalid or missing session_id"}), 403
    
    session_data = db["sessions"][session_id]
    org = session_data["organization"]
    org_data = db["organizations"].get(org, {})
    org_roles = org_data.get("roles", {})

    if role not in org_roles:
        return jsonify({"error": f"Role '{role}' not found"}), 404

    subs = org_roles[role]["subjects"]
    return jsonify({"subjects": subs}), 200

@app.route("/documents/<document_name>/acl", methods=["POST"])
def change_doc_acl(document_name):
    data = request.get_json()
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
def add_permission_to_role():
    data = request.get_json()
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

    if role not in org_roles:
        return jsonify({"error": f"Role '{role}' not found"}), 404

    if permission not in org_roles[role]["permissions"]:
        org_roles[role]["permissions"].append(permission)
    save_db()
    return jsonify({"message": f"Permission '{permission}' added to role '{role}'"}), 200

@app.route("/role/permission/remove", methods=["POST"])
def remove_permission_from_role():
    data = request.get_json()
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

    if role not in org_roles:
        return jsonify({"error": f"Role '{role}' not found"}), 404

    if permission in org_roles[role]["permissions"]:
        org_roles[role]["permissions"].remove(permission)
    save_db()
    return jsonify({"message": f"Permission '{permission}' removed from role '{role}'"}), 200

@app.route("/role/subject/add", methods=["POST"])
def add_subject_to_role():
    data = request.get_json()
    session_id = data.get("session_id")
    role = data.get("role")
    username = data.get("username")

    if not all([session_id, role, username]):
        return jsonify({"error": "Missing fields"}), 400

    session_data = db["sessions"].get(session_id)
    if not session_data:
        return jsonify({"error": "Invalid session ID"}), 403

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

    if username not in org_roles[role]["subjects"]:
        org_roles[role]["subjects"].append(username)
    save_db()
    return jsonify({"message": f"Subject '{username}' added to role '{role}'"}), 200

@app.route("/role/subject/remove", methods=["POST"])
def remove_subject_from_role():
    data = request.get_json()
    session_id = data.get("session_id")
    role = data.get("role")
    username = data.get("username")

    if not all([session_id, role, username]):
        return jsonify({"error": "Missing fields"}), 400

    session_data = db["sessions"].get(session_id)
    if not session_data:
        return jsonify({"error": "Invalid session ID"}), 403

    org = session_data["organization"]
    if not user_has_permission(session_data, org, "ROLE_MOD"):
        return jsonify({"error": "No permission (ROLE_MOD)"}), 403

    org_data = db["organizations"][org]
    org_roles = org_data["roles"]

    if role not in org_roles:
        return jsonify({"error": f"Role '{role}' not found"}), 404

    if username in org_roles[role]["subjects"]:
        org_roles[role]["subjects"].remove(username)

        # Ensure if role is "Managers", it still has an active subject
        # If no active subject in Managers role, revert
        # (Implement that logic as needed)

    save_db()
    return jsonify({"message": f"Subject '{username}' removed from role '{role}'"}), 200


if __name__ == "__main__":
    app.run(debug=True)
