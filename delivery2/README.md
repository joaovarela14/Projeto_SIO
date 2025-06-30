
# Group members
- João Varela 113780
- Carolina Prata 114246
- Henrique Teixeira 114588


In this delivery, we fixed some of the issues that were present in the previous delivery. We also implemented the following features:


## Step 1: Assume a Role
./rep_assume_role <session_id> <role>
1. **Validate Input**:
   - Ensure `session_id` and `role` are provided.
   - If not, return an error.
2. **Validate Session**:
   - Confirm the session ID is valid.
   - If not, return an error.
3. **Verify Role Existence**:
   - Confirm the role exists within the organization.
   - If not, return an error.
4. **Check Role Status**:
   - Ensure the role is `active`.
   - If not, return an error.
5. **Assume Role**:
   - Add the role to the session's `active_roles` list if not already present.
   - Set the assumed role in the session data.
6. **Persist Data**:
   - Save the updated session information to the database.

## Step 2: Drop a Role
./rep_drop_role <session_id> <role>
1. **Validate Input**:
   - Ensure `session_id` and `role` are provided.
   - If not, return an error.
2. **Validate Session**:
   - Confirm the session ID is valid.
   - If not, return an error.
3. **Check Active Roles**:
   - Ensure the role is currently assumed in the session.
   - If not, return an error.
4. **Verify Role Existence**:
   - Confirm the role exists within the organization.
   - If not, return an error.
5. **Drop Role**:
   - Remove the role from the session's `active_roles` list.
   - If the dropped role is the `assumed_role`, reset `assumed_role` to `None`.
6. **Persist Data**:
   - Save the updated session information to the database.

## Step 3: List Roles
./rep_list_roles <session_id> <role>  we don't need the role here we think
1. **Validate Input**:
   - Ensure `session_id` is provided.
   - If not, return an error.
2. **Validate Session**:
   - Confirm the session ID is valid.
   - If not, return an error.
3. **Retrieve Roles**:
   - Access the session data and fetch the list of `active_roles`.
4. **Return Roles**:
   - Send the list of roles as the response.

## Step 4: List Permissions by Role
./rep_list_role_permissions <session_id> <role>
1. **Validate Session**:
   - Ensure `session_id` is provided and valid.
   - If not, return an error.
2. **Fetch Organization Data**:
   - Retrieve the organization associated with the session.
   - Access the roles defined within the organization.
3. **Verify Role Existence**:
   - Confirm the specified role exists within the organization.
   - If not, return an error.
4. **Retrieve Permissions**:
   - Extract the list of permissions associated with the role.
5. **Return Permissions**:
   - Send the list of permissions as the response.

## Step 5: List Roles by Permission
./rep_list_permission_roles <session_id> <permission>
1. **Validate Session**:
   - Ensure `session_id` is provided and valid.
   - If not, return an error.
2. **Fetch Organization Data**:
   - Retrieve the organization associated with the session.
   - Access the roles defined within the organization.
3. **Filter Roles**:
   - Identify roles that have the specified permission in their `permissions` list.
4. **Return Matching Roles**:
   - Send the list of matching roles as the response.

## Step 6: Add Role to Session
./rep_add_role <session_id> <role>
1. **Fetch Session Data**:
   - Retrieve session information using the provided `session_id`.
2. **Verify Permissions**:
   - Check if the user has the `ROLE_NEW` permission within the organization.
3. **Validate Input**:
   - Ensure `session_id` and `role` are provided.
   - Check if the session ID is valid.
   - Confirm the organization exists in the database.
4. **Add Role**:
   - Create the role under the organization if it does not already exist.
   - Initialize the role with the following attributes:
     - `permissions`: An empty list.
     - `subjects`: An empty list.
     - `status`: Set to `active`.
5. **Persist Data**:
   - Save the updated data to the database.



## Step 7: Suspend Role
./rep_suspend_role <session_id> <role>
1. **Validate Permissions**:
   - Ensure the user has the `ROLE_DOWN` permission for the organization.
   - Ensure the Role is not the "Managers" role, which cannot be suspended.
   - Ensure the role is not already suspended.
   - If not, return a permission error.
2. **Validate Input**:
   - Ensure `session_id` and `role` are provided.
   - Confirm the session ID is valid.
3. **Check Role Existence**:
   - Verify the role exists within the organization.
   - Ensure the role is not the "Managers" role, which cannot be suspended.
4. **Suspend Role**:
   - Update the role's status to `suspended`.
5. **Persist Data**:
   - Save the updated data to the database.

## Step 8: Activate Role
./rep_reactivate_role <session_id> <role>
1. **Validate Input**:
   - Ensure `session_id` and `role` are provided.
   - If not, return an error.
2. **Validate Session**:
   - Confirm the session ID is valid.
3. **Verify Permissions**:
   - Ensure the user has the `ROLE_UP` permission for the organization.
   - Ensure the role is currently suspended before reactivating.
   - If not, return a permission error.
4. **Check Role Status**:
   - Ensure the role exists within the organization.
   - Confirm the role is currently suspended before reactivating.
5. **Reactivate Role**:
   - Update the role's status to `active`.
6. **Persist Data**:
   - Save the updated data to the database.

## Step 9: List Subject Roles
./rep_list_subject_roles <session_id> <username>
1. **Validate Session**:
   - Ensure `session_id` is provided and valid.
   - If not, return an error.
2. **Fetch Organization Data**:
   - Retrieve the organization associated with the session.
   - Access the roles defined within the organization.
3. **Identify Subject Roles**:
   - Iterate through roles to find those where the `username` is listed as a subject.
4. **Return Roles**:
   - Send the list of roles assigned to the specified subject.

## Step 10: List Roles by Subject
./rep_list_role_subjects <session_id> <role>
1. **Validate Session**:
   - Ensure `session_id` is provided and valid.
   - If not, return an error.
2. **Fetch Organization Data**:
   - Retrieve the organization associated with the session.
   - Access the roles defined within the organization.
3. **Verify Role Existence**:
   - Confirm the specified role exists within the organization.
   - If not, return an error.
4. **Retrieve Subjects**:
   - Extract the list of subjects associated with the role.
5. **Return Subjects**:
   - Send the list of subjects as the response.

## Step 11: Modict document ACL by Role
./rep_acl_doc <session file> <document name> [+/-] <role> <permission>
1. **Validate Permissions**:
   - Ensure the user has the `DOC_ACL` permission for the organization.
   - If not, return a permission error.
2. **Validate Input**:
   - Ensure all required fields (`session_id`, `sign`, `role`, `permission`) are provided.
   - Validate the `session_id` and ensure the `permission` starts with `DOC_`.
3. **Check Document Existence**:
   - Confirm the organization exists and the document is present within it.
4. **Modify ACL**:
   - If `sign` is `+`, add the permission for the specified role.
   - If `sign` is `-`, remove the permission for the specified role.
   - If the `sign` is invalid, return an error.
5. **Persist Data**:
   - Save the updated document metadata to the database.

## Step 12: Add Subject or Permission to Role
./rep_add_permission <session file> <role> (<username>|<permission>)
### if permission
1. **Validate Permissions**:
   - Ensure the user has the `ROLE_MOD` permission for the organization.
   - If not, return a permission error.
2. **Validate Input**:
   - Ensure all required fields (`session_id`, `role`, `permission`) are provided.
   - If not, return an error.
   - Validate the `session_id`.
3. **Verify Role Existence**:
   - Confirm the role exists within the organization.
   - If not, return an error.
4. **Add Permission**:
   - If the permission is not already assigned to the role, append it to the role's `permissions` list.
5. **Persist Data**:
   - Save the updated role information to the database.

### if username
1. **Validate Input**:
   - Ensure all required fields (`session_id`, `role`, `username`) are provided.
   - If not, return an error.
2. **Validate Session**:
   - Confirm the session ID is valid.
   - If not, return an error.
3. **Check Permissions**:
   - Ensure the user has the `ROLE_MOD` permission for the organization.
   - If not, return a permission error.
4. **Verify Role Existence**:
   - Confirm the role exists within the organization.
   - If not, return an error.
5. **Check User Membership**:
   - Ensure the user is part of the organization.
   - If not, return an error.
6. **Add Subject to Role**:
   - If the subject is not already assigned to the role, append their username to the role's `subjects` list.
7. **Persist Data**:
   - Save the updated role information to the database.

## Step 13: Remove Permission from Role
./rep_remove_permission <session file> <role> (<username>|<permission>)
### if permission
1. **Validate Permissions**:
   - Ensure the user has the `ROLE_MOD` permission for the organization.
   - If not, return a permission error.
2. **Validate Input**:
   - Ensure all required fields (`session_id`, `role`, `permission`) are provided.
   - If not, return an error.
   - Validate the `session_id`.
3. **Verify Role Existence**:
   - Confirm the role exists within the organization.
   - If not, return an error.
4. **Remove Permission**:
   - If the permission exists in the role's `permissions` list, remove it.
5. **Persist Data**:
   - Save the updated role information to the database.

### if username
1. **Validate Input**:
   - Ensure all required fields (`session_id`, `role`, `username`) are provided.
   - If not, return an error.
2. **Validate Session**:
   - Confirm the session ID is valid.
   - If not, return an error.
3. **Check Permissions**:
   - Ensure the user has the `ROLE_MOD` permission for the organization.
   - If not, return a permission error.
4. **Verify Role Existence**:
   - Confirm the role exists within the organization.
   - If not, return an error.
5. **Remove Subject from Role**:
   - If the subject is assigned to the role, remove their username from the role's `subjects` list.
   - Ensure that the "Managers" role maintains at least one active subject, if applicable.
6. **Persist Data**:
   - Save the updated role information to the database.
