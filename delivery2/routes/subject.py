from flask import Blueprint, jsonify, request
import json
import os
from .organization import *
from utils.crypto_utils import *

subject_bp = Blueprint('subject', __name__)
SUBJECTS_FILE = "subjects.json"

class Subject:

    def __init__(self, username, name, email, public_key):
        self.username = username
        self.name = name
        self.email = email
        self.public_key = public_key
        self.organizations = []

    def to_dict(self):
        return {
            "username": self.username,
            "name": self.name,
            "email": self.email,
            "public_key": self.public_key,
            "organizations": self.organizations
        }
    
def load_subjects():
    try:
        with open(SUBJECTS_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    
def save_subjects(subjects):
    try:
        with open(SUBJECTS_FILE, "w") as f:
            json.dump(subjects, f, indent=4)
    except FileNotFoundError:
        # Create the file if it does not exist
        with open(SUBJECTS_FILE, "x") as f:
            json.dump(subjects, f, indent=4)

@subject_bp.route("/create", methods=["POST"])
def create_subject():

    data = request.json
    username = data.get("username")
    name = data.get("name")
    email = data.get("email")
    credentials_file = data.get("credentials_file")
    organization_name = data.get("organization")


    if not all([username, name, email, credentials_file, organization_name]):
        return jsonify({"error": "All fields are required"}), 400

    try:
        organization = get_organization(organization_name)
    except KeyError as e:
        return jsonify({"error": str(e)}), 400


    # load pulic key
    public_key = load_public_key(credentials_file)

    subject = Subject(username, name, email, public_key)

    # Add user to the organization
    try:
        organization.add_user(subject)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
    # Save organization back to the store
    save_subjects(load_subjects())
    save_organizations(load_organizations())

    return jsonify({"message": f"Subject '{username}' created successfully"}), 201
