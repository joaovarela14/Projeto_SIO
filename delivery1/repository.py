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


@app.route("/organization/create", methods=["POST"])
def create_organization():
    data = request.get_json()

    org_name = data.get("organization")
    username = data.get("username")
    name = data.get("name")
    email = data.get("email")
    credentials_content = data.get("credentials_file")

    if not all([org_name, username, name, email, credentials_content]):
        return jsonify({"error": "All fields (organization, username, name, email, credentials_file) are required"}), 400

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

    # Create the organization entry
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
    }
    db["organizations"][org_name] = organization

    # Update or create the subject entry
    if public_key_pem in db["subjects"]:
        # Update the existing subject with the new organization
        db["subjects"][public_key_pem]["organizations"].append(org_name)
    else:
        # Create a new subject entry
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
def add_document(document_name):
    """
    Endpoint to upload and store an encrypted document.
    """
    data = request.get_json()

    document_name = data.get("document_name")
    session_id = data.get("session_id")
    iv = data.get("iv")
    encrypted_content = data.get("encrypted_content")
    file_handle = data.get("file_handle")
    encrypted_file_key = data.get("encrypted_file_key")
    encrypted_file_key_iv = data.get("encrypted_file_key_iv")
    tag = data.get("tag")

    # Validate required fields
    if not all([session_id, iv, encrypted_content, file_handle, encrypted_file_key, encrypted_file_key_iv, tag]):
        return jsonify({"error": "Missing required fields."}), 400

    # Validate session
    if session_id not in db["sessions"]:
        return jsonify({"error": "Invalid session ID"}), 403

    session_data = db["sessions"][session_id]
    username = session_data["username"]
    organization = session_data["organization"]

    # Save document metadata to documents.json
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
        "encrypted_file_key": encrypted_file_key,
        "encrypted_file_key_iv": encrypted_file_key_iv,
        "tag": tag,
    }


    documents[organization][document_name] = {
        "public_metadata": public_metadata,
        "restricted_metadata": restricted_metadata,
        "encrypted_content": encrypted_content,
        "iv": iv,
    }

    # Save only document name and creator in db.json
    if "documents" not in db["organizations"][organization]:
        db["organizations"][organization]["documents"] = {}

    db["organizations"][organization]["documents"][document_name] = {
        "creator": username
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
        "creator": document_metadata["public_metadata"]["creator"],
        "iv": document_metadata["iv"],
        "encrypted_content": document_metadata["encrypted_content"],
        "file_handle": document_metadata["public_metadata"]["file_handle"],
        "encrypted_file_key": document_metadata["restricted_metadata"]["encrypted_file_key"],
        "encrypted_file_key_iv": document_metadata["restricted_metadata"]["encrypted_file_key_iv"],
        "tag": document_metadata["restricted_metadata"]["tag"],
        "create_date": document_metadata["public_metadata"]["create_date"],
        "acl": document_metadata["public_metadata"]["acl"],
        
    }), 200

@app.route("/subject/suspend", methods=["POST"])
def suspend_subject():
    data = request.get_json()
    username = data.get("username")

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

    if not session_id:
        return jsonify({"error": "Field 'session_id' is required"}), 400

    if session_id not in db["sessions"]:
        return jsonify({"error": "Invalid session ID"}), 403

    session_data = db["sessions"][session_id]
    organization = session_data["organization"]

    if organization not in documents:
        return jsonify({"error": f"Metadata for organization '{organization}' not found"}), 404

    if document_name not in documents[organization]:
        return jsonify({"error": f"Metadata for document '{document_name}' not found"}), 404

    document_metadata = documents[organization][document_name]

    return jsonify({
        "creator": document_metadata["public_metadata"]["creator"],
        "iv": document_metadata["iv"],
        "encrypted_content": document_metadata["encrypted_content"],
        "file_handle": document_metadata["public_metadata"]["file_handle"],
        "encrypted_file_key": document_metadata["restricted_metadata"]["encrypted_file_key"],
        "encrypted_file_key_iv": document_metadata["restricted_metadata"]["encrypted_file_key_iv"],
        "tag": document_metadata["restricted_metadata"]["tag"],
        "create_date": document_metadata["public_metadata"]["create_date"],
        "acl": document_metadata["public_metadata"]["acl"],
    }), 200



@app.route("/documents/<document_name>/file", methods=["GET"])
def get_doc_file(document_name):
    """
    Downloads a specific document file or outputs it to stdout if no file path is provided.
    """
    pass


@app.route("/documents/<document_name>", methods=["DELETE"])
def delete_document(document_name):
    """
    Clears the file handle for a specific document, effectively deleting it.
    """

    data = request.get_json()
    session_id = data.get("session_id")

    if not session_id:
        return jsonify({"error": "Field 'session_id' is required"}), 400

    if session_id not in db["sessions"]:
        return jsonify({"error": "Invalid session ID"}), 403

    session_data = db["sessions"][session_id]
    organization = session_data["organization"]

    if organization not in documents:
        return jsonify({"error": f"Metadata for organization '{organization}' not found"}), 404

    if document_name not in documents[organization]:
        return jsonify({"error": f"Metadata for document '{document_name}' not found"}), 404

    document_metadata = documents[organization][document_name]

    # if session_data["username"] not in document_metadata["acl"]["DOC_DELETE"]:
    #     return jsonify({"error": "Access denied to delete document"}), 403

    cleared_file_handle = document_metadata["public_metadata"]["file_handle"]

    document_metadata["public_metadata"]["file_handle"] = None
    document_metadata["public_metadata"]["deleter"] = session_data["username"]

    save_documents()
    save_db()

    return jsonify({"message": f"Document '{document_name}' deleted successfully", "cleared_file_handle": cleared_file_handle}), 200


@app.route("/documents", methods=["GET"])
def list_documents():
    """
    Lists all documents with optional filters for username and date.
    """
    username_filter = request.args.get("username")
    date_filter_type = request.args.get("date_filter_type")
    date_filter_value = request.args.get("date_filter_value")

    filtered_documents = []

    for _, docs in documents.items():
        for doc_name, metadata in docs.items():
            # Filter by username
            if username_filter and metadata["creator"] != username_filter:
                continue

            # Filter by date
            if date_filter_value:
                try:
                    doc_date = datetime.strptime(metadata["create_date"], "%Y-%m-%d %H:%M:%S.%f")
                    filter_date = datetime.strptime(date_filter_value, "%d-%m-%Y")

                    if date_filter_type == "nt" and doc_date <= filter_date:
                        continue
                    elif date_filter_type == "ot" and doc_date >= filter_date:
                        continue
                    elif date_filter_type == "et" and doc_date.date() != filter_date.date():
                        continue
                except ValueError:
                    return jsonify({"error": "Invalid date format. Use DD-MM-YYYY."}), 400

            # Append document metadata to the result
            filtered_documents.append({
                "document_name": doc_name,
                "creator": metadata["public_metadata"]["creator"],
                "create_date": metadata["public_metadata"]["create_date"]
            })

    return jsonify(filtered_documents), 200


@app.route("/file/<file_handle>", methods=["GET"])
def get_file(file_handle):
    """
    Downloads a file using its file handle.
    """
    document_name = None
    document_metadata = None

    for org, docs in documents.items():
        for doc_name, metadata in docs.items():
            if metadata["public_metadata"]["file_handle"] == file_handle:
                print(file_handle)
                document_name = doc_name
                document_metadata = metadata
                break

    if not document_name:
        return jsonify({"error": f"File handle '{file_handle}' not found"}), 404

    return jsonify({
        "document_name": document_name,
        "file_handle": file_handle,
        "encrypted_content": document_metadata["encrypted_content"],
        "creator": document_metadata["public_metadata"]["creator"]
    }), 200



@app.route("/file/decrypt", methods=["POST"])
def decrypt_file():
    """
    Decrypts a given file using encryption metadata.
    """
    
    try:
        # Parse request JSON
        data = request.json
        encrypted_content = base64.b64decode(data.get("encrypted_content", ""))
        encrypted_file_key = base64.b64decode(data.get("encrypted_file_key", ""))
        iv = base64.b64decode(data.get("iv", ""))
        tag = base64.b64decode(data.get("tag", ""))
        algorithm = data.get("algorithm")

        if not all([encrypted_content, encrypted_file_key, iv, tag, algorithm]):
            return jsonify({"error": "Invalid or incomplete metadata provided."}), 400

        if algorithm != "AES-GCM":
            return jsonify({"error": "Unsupported encryption algorithm. Expected AES-GCM."}), 400

        # Decrypt the file key (simplified for demonstration; adapt as needed for production)
        file_key = encrypted_file_key

        # Decrypt the content
        cipher = Cipher(algorithms.AES(file_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()

        # Return the decrypted content
        return jsonify({
            "decrypted_content": base64.b64encode(decrypted_content).decode('utf-8')
        }), 200

    except Exception as e:
        return jsonify({"error": f"Failed to decrypt file: {str(e)}"}), 500




if __name__ == "__main__":
    app.run(debug=True)
