#!/bin/bash

# Variables
SERVER_URL="http://127.0.0.1:5000"
ORG_NAME="TestOrg"
ADMIN_USERNAME="admin"
ADMIN_NAME="Admin User"
ADMIN_EMAIL="admin@test.org"
PASSWORD="password123"
CREDENTIALS_FILE="admin_credentials.json"
SESSION_FILE="barcelona_session.json"
DOCUMENT_NAME="passaro.txt"
DOCUMENT_PATH="passaro.txt"
OUTPUT_FILE="output_document.txt"
METADATA_FILE="metadata.json"
ENCRYPTED_FILE="passaro.txt"
ROLE_NAME="TestRole"
NEW_USER="new_user"
NEW_USER_NAME="New User"
NEW_USER_EMAIL="new_user@test.org"

JSON_FILE="documents.json"  
FILE_HANDLE=$(jq -r '."TestOrg"."passaro.txt".public_metadata.file_handle' "$JSON_FILE")

# Helper Functions
function check_command() {
    if [ $? -ne 0 ]; then
        echo "Error: $1 failed."
        exit 1
    fi
}

# Step 0: Activate virtual environment
source venv/bin/activate

# Step 0: Start the server
echo "Starting the server..."
python3 repository.py &

# 1. Generate credentials for the admin
echo "Generating credentials for admin..."
python3 client.py rep_subject_credentials "$PASSWORD" "$CREDENTIALS_FILE"
check_command "Generate admin credentials"

# 2. Create an organization
echo "Creating organization..."
python3 client.py rep_create_org "$ORG_NAME" "$ADMIN_USERNAME" "$ADMIN_NAME" "$ADMIN_EMAIL" "./keys/$CREDENTIALS_FILE"
check_command "Create organization"

# 3. List organizations
echo "Listing organizations..."
python3 client.py rep_list_orgs
check_command "List organizations"

# 4. Create a session
echo "Creating session..."
python3 client.py rep_create_session "$ORG_NAME" "$ADMIN_USERNAME" "$PASSWORD" "./keys/$CREDENTIALS_FILE" "$SESSION_FILE"
check_command "Create session"

# 5. Add a document
echo "Adding a document..."
python3 client.py rep_add_doc "$SESSION_FILE" "$DOCUMENT_NAME" "$DOCUMENT_PATH"
check_command "Add document"

# 6. Get document file
echo "Retrieving document file..."
python3 client.py rep_get_doc_file "$SESSION_FILE" "$DOCUMENT_NAME" "$OUTPUT_FILE"
check_command "Retrieve document file"

# 7. Suspend a subject
echo "Suspending a subject..."
python3 client.py rep_suspend_subject "$SESSION_FILE" "$ADMIN_USERNAME"
check_command "Suspend subject"

# 8. Activate a subject
echo "Activating a subject..."
python3 client.py rep_activate_subject "$SESSION_FILE" "$ADMIN_USERNAME"
check_command "Activate subject"

# 9. Add a subject
echo "Adding a subject..."
python3 client.py rep_add_subject "$SESSION_FILE" "$NEW_USER" "$NEW_USER_NAME" "$NEW_USER_EMAIL" "./keys/$CREDENTIALS_FILE"
check_command "Add subject"

# 10. List subjects
echo "Listing subjects..."
python3 client.py rep_list_subjects "$SESSION_FILE"
check_command "List subjects"

# 11. Retrieve document metadata and store it in a file
echo "Retrieving document metadata..."
python3 client.py rep_get_doc_metadata "$SESSION_FILE" "$DOCUMENT_NAME" > "metadata.json"
check_command "Retrieve document metadata"

# 12. Decrypt a file
echo "Decrypting a file..."
python3 client.py rep_decrypt_file "$ENCRYPTED_FILE" "metadata.json"
check_command "Decrypt file"

# 13. List documents
echo "Listing documents..."
python3 client.py rep_list_docs "$SESSION_FILE" "-s $ADMIN_USERNAME" "-d nt $(date +'%d-%m-%Y')"
check_command "List documents"

# 14. Get a file by file_handle and store it in a file
echo "Getting a file by file_handle and storing it in a file..."
python3 client.py rep_get_file "$FILE_HANDLE" "$OUTPUT_FILE"


# New Commands

# 16. List roles for a subject
echo "Listing roles for a subject..."
python3 client.py rep_list_subject_roles "$SESSION_FILE" "$ADMIN_USERNAME"
check_command "List roles for a subject"

# 17. Assume a role
echo "Assuming a role..."
python3 client.py rep_assume_role "$SESSION_FILE" "$ROLE_NAME"
check_command "Assume a role"

# 18. Drop a role
echo "Dropping a role..."
python3 client.py rep_drop_role "$SESSION_FILE" "$ROLE_NAME"
check_command "Drop a role"

# 19. List roles
echo "Listing roles..."
python3 client.py rep_list_roles "$SESSION_FILE"
check_command "List roles"

# 20. List subjects of a role
echo "Listing subjects of a role..."
python3 client.py rep_list_role_subjects "$SESSION_FILE" "Managers"
check_command "List subjects of a role"

# 21. List permissions of a role
echo "Listing permissions of a role..."
python3 client.py rep_list_role_permissions "$SESSION_FILE" "Managers"
check_command "List permissions of a role"

# 22. List roles with a specific permission
echo "Listing roles with a specific permission..."
python3 client.py rep_list_permission_roles "$SESSION_FILE" "DOC_READ"
check_command "List roles with a specific permission"

# 23. Add a role
echo "Adding a role..."
python3 client.py rep_add_role "$SESSION_FILE" "$ROLE_NAME"
check_command "Add role"

# 24. Suspend a role
echo "Suspending a role..."
python3 client.py rep_suspend_role "$SESSION_FILE" "$ROLE_NAME"
check_command "Suspend role"

# 25. Reactivate a role
echo "Reactivating a role..."
python3 client.py rep_reactivate_role "$SESSION_FILE" "$ROLE_NAME"
check_command "Reactivate role"

# 26. Add a permission to a role
echo "Adding a permission to a role..."
python3 client.py rep_add_permission "$SESSION_FILE" "$ROLE_NAME" "DOC_NEW"
check_command "Add a permission to a role"

# 27. Remove a permission from a role
echo "Removing a permission from a role..."
python3 client.py rep_remove_permission "$SESSION_FILE" "$ROLE_NAME" "DOC_NEW"
check_command "Remove a permission from a role"

# 28. Add a subject to a role
echo "Adding a subject to a role..."
python3 client.py rep_add_permission "$SESSION_FILE" "$ROLE_NAME" "$NEW_USER"
check_command "Add a subject to a role"

# 29. Remove a subject from a role
echo "Removing a subject from a role..."
python3 client.py rep_remove_permission "$SESSION_FILE" "$ROLE_NAME" "$NEW_USER"
check_command "Remove a subject from a role"

# 30. Modify ACL for a document
echo "Modifying ACL for a document..."
python3 client.py rep_acl_doc "$SESSION_FILE" "$DOCUMENT_NAME" "+ Managers DOC_READ"
check_command "Modify ACL for a document"

# 15. Delete a document
echo "Deleting a document..."
python3 client.py rep_delete_doc "$SESSION_FILE" "$DOCUMENT_NAME"
check_command "Delete document"

echo "All commands tested successfully!"
