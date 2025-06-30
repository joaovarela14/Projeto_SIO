#!/bin/bash

# Test Script for Commands
# Prepare environment

# Step 1: Generate a public/private key pair (if not already created)
if [ ! -f "$PUBLIC_KEY_FILE" ] || [ ! -f "$PRIVATE_KEY_FILE" ]; then
    echo "Generating keys..."
    python3 ../utils/crypto_utils.py generate_keys "$PRIVATE_KEY_FILE" "$PUBLIC_KEY_FILE"
fi

# Step 2: Create a new organization
echo "Creating a new organization..."
python3 ../client.py rep_create_org "TestOrg" "admin_user" "Admin User" "admin@example.com" "$PUBLIC_KEY_FILE"

# Step 3: List all organizations
echo "Listing all organizations..."
python3 ../client.py rep_list_orgs

# Step 4: Create a session for the organization
echo "Creating a session..."
python3 ../client.py rep_create_session "TestOrg" "admin_user" "password123" "$PRIVATE_KEY_FILE" "$SESSION_FILE"

# Step 5: Add a subject to the organization
echo "Adding a new subject to the organization..."
python3 ../client.py rep_add_subject "$SESSION_FILE" "new_user" "New User" "newuser@example.com" "$PUBLIC_KEY_FILE"

# Step 6: List subjects in the organization
echo "Listing all subjects in the organization..."
python3 ../client.py rep_list_subjects "$SESSION_FILE"

# Step 7: Delete the session file
echo "Cleaning up: Deleting session file..."
rm -f "$SESSION_FILE"

echo "All tests completed successfully."
