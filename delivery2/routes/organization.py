from flask import Blueprint, jsonify, request
from .subject import load_subjects, save_subjects, Subject
import json
import os
from db import load_db, save_db
from utils.crypto_utils import *


organization_bp = Blueprint('organization', __name__)
ORGANIZATIONS_FILE = "organizations.json"
db = load_db()


class Organization:

    def __init__(self, name, admin_name, admin_username, admin_email, admin_key):
        admin_key =  load_public_key(admin_key)
        self.name = name
        self.documents = []
        self.users = {
            admin_username: {
                "name": admin_name,
                "email": admin_email,
                "public_key": admin_key
            }
        }

    def add_user(self, subject):
        for user in self.users.values():
            if user["public_key"] == subject.public_key:
                raise ValueError(f"User '{subject.name}' with public key already exists in the organization.")
        self.users[subject.username] = {
            "name": subject.name,
            "email": subject.email,
            "public_key": subject.public_key
        }


    def to_dict(self):
        return {
            "documents": self.documents,
            "users": self.users
        }
    
    
    
def get_organization(organization_name):
    organizations = load_organizations()
    if organization_name in organizations:
        return organizations[organization_name]
    raise KeyError(f"Organization '{organization_name}' does not exist.")


def load_organizations():
    try:
        with open(ORGANIZATIONS_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_organizations(organizations):
    with open(ORGANIZATIONS_FILE, "w") as f:
        json.dump(organizations, f, indent=4)

organizations = load_organizations()

def create_organization():

    data = request.json
    org_name = data.get("organization")
    username = data.get("username")
    name = data.get("name")
    email = data.get("email")
    public_key = data.get("public_key")

    if not all([org_name, username, name, email, public_key]):
        return jsonify({"error": "All fields are required"}), 400

    if org_name in organizations:
        return jsonify({"error": "Organization already exists"}), 400

    organization= Organization(
        name=org_name,
        admin_name=name,
        admin_username=username,
        admin_email=email,
        admin_key=public_key 
    )

    organizations[org_name] = organization.to_dict()

    save_organizations(organizations)

    # save subject
    subjects = load_subjects()
    if public_key in subjects:
        subjects[public_key]["organizations"].append(org_name)
    else:
        subject = Subject(username, name, email, public_key)
        subject.organizations.append(org_name)
        subjects[public_key] = subject.to_dict()

    save_subjects(subjects)

    db["organizations"][org_name] = organization.to_dict()
    save_db()

    return jsonify({"message": f"Organization '{org_name}' created successfully"}), 201

@organization_bp.route("/list", methods=["GET"])
def list_organizations():
    return jsonify(organizations), 200

