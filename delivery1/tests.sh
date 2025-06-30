#!/bin/bash

# Variables
SERVER_URL="http://127.0.0.1:5000"
ORG_NAME="TestOrg"
ADMIN_USERNAME="admin"
ADMIN_NAME="Admin User"
ADMIN_EMAIL="admin@test.org"
PASSWORD="password123"
CREDENTIALS_FILE="admin_credentials.json"
SESSION_FILE="session_data.json"
DOCUMENT_NAME="passaro.txt"
DOCUMENT_PATH="passaro.txt"
OUTPUT_FILE="output_document.txt"
METADATA_FILE="metadata.json"
ENCRYPTED_FILE="passaro.txt"

JSON_FILE="documents.json"  
FILE_HANDLE=$(jq -r '."TestOrg"."passaro.txt".public_metadata.file_handle' "$JSON_FILE")


# Helper Functions
function check_command() {
    if [ $? -ne 0 ]; then
        echo "Error: $1 failed."
        exit 1
    fi
}

# Step 0: activate virtual environment
source venv/bin/activate

# Step 0: Start the server
echo "Starting the server..."
python3 repository.py &


# 1.Generate credentials for the admin
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
python3 client.py rep_add_subject "$SESSION_FILE" "new_user" "New User" "new_user@test.org" "./keys/$CREDENTIALS_FILE"
check_command "Add subject"

# 10. List subjects
echo "Listing subjects..."
python3 client.py rep_list_subjects "$SESSION_FILE"
check_command "List subjects"

# 11. Retrieve document metadata
echo "Retrieving document metadata..."
python3 client.py rep_get_doc_metadata "$SESSION_FILE" "$DOCUMENT_NAME"
check_command "Retrieve document metadata"


# 12. List documents
echo "Listing documents..."
python3 client.py rep_list_docs "$SESSION_FILE" "-s $ADMIN_USERNAME" "-d nt $(date +'%d-%m-%Y')"
check_command "List documents"

# 13. Get a file by file_handle and store it in a file
echo "Getting a file by file_handle and storing it in a file..."
python3 client.py rep_get_file "$FILE_HANDLE" "$OUTPUT_FILE"



# 14. Delete a document
echo "Deleting a document..."
python3 client.py rep_delete_doc "$SESSION_FILE" "$DOCUMENT_NAME"
check_command "Delete document"

echo "All commands tested successfully!"
