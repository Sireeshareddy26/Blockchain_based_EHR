# app.py - Main Streamlit Application

import streamlit as st
import hashlib
import os
import datetime
import bcrypt
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# --- Database Setup (from step 3 and 7) ---
# Use a local SQLite database for persistence
DATABASE_URL = "sqlite:///./ehr_app.db"
engine = create_engine(DATABASE_URL)

# Define Base and Models (User, Department) - Redefine for this script's context
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, nullable=False) # 'Patient', 'Doctor', 'Staff/Technician', 'Admin'

    def __repr__(self):
        return f"<User(username='{self.username}', role='{self.role}')>"

class Department(Base):
    __tablename__ = 'departments'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)

    def __repr__(self):
        return f"<Department(name='{self.name}')>"

# Create tables if they don't exist
Base.metadata.create_all(bind=engine)
Session = sessionmaker(bind=engine)

def get_session():
    """Provides a SQLAlchemy session."""
    db_session = Session()
    try:
        yield db_session
    finally:
        db_session.close()

# --- Authentication Functions (from step 3) ---
def hash_password(password):
    """Hashes a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8') # Store as string

def check_password(password, hashed_password):
    """Checks if a provided password matches the stored hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def register_user(username, password, role):
    """Registers a new user."""
    db_session = next(get_session())
    if db_session.query(User).filter_by(username=username).first():
        return False, "Username already exists."

    hashed_password = hash_password(password)
    new_user = User(username=username, password=hashed_password, role=role)
    db_session.add(new_user)
    db_session.commit()
    return True, "User registered successfully."

def login_user(username, password):
    """Logs in a user by verifying credentials."""
    db_session = next(get_session())
    user = db_session.query(User).filter_by(username=username).first()
    if user and check_password(password, user.password):
        return True, user.role, "Login successful."
    else:
        return False, None, "Invalid username or password."

def technician_login(technician_id, secure_token):
    """
    Conceptual login for technicians using a secure token.
    In a real application, this would involve validating the token
    against a secure store (e.g., database, separate key management system).
    The token could grant temporary or specific access rights.
    """
    # Placeholder for actual token validation logic
    # NOTE: HARDCODED TOKEN - REPLACE WITH A SECURE IMPLEMENTATION IN PRODUCTION
    if technician_id == "tech1" and secure_token == "valid_tech_token_123":
        return True, "Technician login successful."
    else:
        return False, "Invalid technician ID or token."

def has_access(user_role, required_roles):
    """Checks if a user's role is in the list of required roles."""
    return user_role in required_roles

# --- Placeholder Blockchain Interaction Functions (from step 5 & 6) ---
# In a real application, replace these with Web3.py or a specific blockchain library
def create_blockchain_account():
    """Placeholder: Creates a new account on the blockchain."""
    print("Placeholder: Creating blockchain account...")
    # Simulate returning an address
    import random
    return f"0x" + ''.join(random.choice('0123456789abcdef') for _ in range(40))

def add_record_to_blockchain(record_data):
    """Placeholder: Adds a record (or its hash) to the blockchain."""
    print(f"Placeholder: Adding record to blockchain: {record_data}")
    # Simulate a transaction hash
    import random
    return f"0x" + ''.join(random.choice('0123456789abcdef') for _ in range(64))

def get_records_from_blockchain(query_params):
    """Placeholder: Retrieves records from the blockchain based on query parameters."""
    print(f"Placeholder: Retrieving records from blockchain with params: {query_params}")
    # Simulate returning some test result records for a specific patient ID
    patient_id = query_params.get("patient_id")
    if patient_id == "patient123": # Example patient ID used in patient dashboard placeholder
        return [
            {"record_id": "test_res_001", "type": "test_result", "patient_id": "patient123", "appointment_id": "app_abc", "document_hash": "hash_of_file1", "storage_ref": os.path.join("uploaded_results", "test_result_1.pdf"), "timestamp": "2023-10-26T10:00:00"},
            {"record_id": "test_res_002", "type": "test_result", "patient_id": "patient123", "appointment_id": "app_xyz", "document_hash": "hash_of_file2", "storage_ref": os.path.join("uploaded_results", "test_result_2.pdf"), "timestamp": "2023-11-15T14:30:00"}
        ]
    elif patient_id == "patient_with_remarks": # Example for doctor dashboard
         return [
            {"record_id": "remark_001", "type": "doctor_remarks", "patient_id": "patient_with_remarks", "doctor": "doctor1", "remarks": "Patient presenting with symptoms.", "timestamp": "2023-12-01T09:00:00"},
             {"record_id": "order_001", "type": "test_order", "patient_id": "patient_with_remarks", "doctor": "doctor1", "test_order": "Blood Test", "timestamp": "2023-12-01T09:10:00"}
         ]
    else:
        return [] # No records found for other patients

def update_blockchain_record(record_id, update_data):
    """Placeholder: Updates a record on the blockchain (if mutable, or adds a new linked record)."""
    print(f"Placeholder: Updating blockchain record {record_id} with data: {update_data}")
    # In a real app, this might add a new linked record or interact with an update function if designed
    import random
    return f"0x" + ''.join(random.choice('0123456789abcdef') for _ in range(64))

# --- Backend Logic Functions (from step 5) ---
# These functions integrate authentication, database, and blockchain placeholders

def create_user_account_with_blockchain(username, password, role):
    """
    Creates a user account and potentially records the registration on the blockchain.
    """
    # First, register the user in the traditional database
    success, message = register_user(username, password, role)

    if success:
        print(f"User '{username}' registered in database.")
        # Now, interact with the blockchain
        blockchain_address = create_blockchain_account() # Create a blockchain account for the user
        registration_data = {
            "username": username,
            "role": role,
            "blockchain_address": blockchain_address,
            "timestamp": datetime.datetime.now().isoformat()
        }
        # Add a record of the user registration to the blockchain
        transaction_hash = add_record_to_blockchain({"type": "user_registration", "details": registration_data})
        print(f"User registration recorded on blockchain with transaction hash: {transaction_hash}")
        return True, "User registered successfully and recorded on blockchain."
    else:
        return False, message

def book_appointment_with_blockchain(patient_username, doctor_username, appointment_datetime, department):
    """
    Books an appointment and records the details (or hash) on the blockchain.
    Includes department information.
    """
    # In a real app, you would also need to store appointment details in a database,
    # check doctor availability, etc. This is a simplified placeholder.

    appointment_details = {
        "patient": patient_username,
        "doctor": doctor_username,
        "datetime": appointment_datetime.isoformat(),
        "department": department,
        "status": "requested", # Initial status
        "timestamp": datetime.datetime.now().isoformat()
    }

    # Add the appointment details (or a hash of them) to the blockchain
    transaction_hash = add_record_to_blockchain({"type": "appointment_booking", "details": appointment_details})
    print(f"Appointment booking recorded on blockchain with transaction hash: {transaction_hash}")

    # In a real app, you'd also save this appointment to a database for easier querying/management
    return True, "Appointment request submitted successfully and recorded on blockchain."

def get_patient_records_from_blockchain(patient_id):
    """
    Retrieves all relevant patient records from the blockchain.
    This function would query the blockchain for records linked to the patient.
    """
    # In a real app, you would need to map patient_id to a blockchain identifier (e.g., hashed ID)
    patient_blockchain_identifier = f"hashed_id_of_{patient_id}" # Placeholder

    # Query the blockchain for records related to this patient
    blockchain_records = get_records_from_blockchain({"patient_id": patient_id}) # Using patient_id directly for placeholder query

    # Process blockchain_records to fetch linked external documents if needed
    processed_records = []
    for record in blockchain_records:
        # Placeholder: In a real app, you would use record['document_hash'] or storage_ref to fetch the actual data
        # from a decentralized storage system (like IPFS) or a secure off-chain database.
        # For this placeholder, we'll just include the available info.
        processed_records.append(record)

    return processed_records

def doctor_add_remarks_or_order_tests_with_blockchain(patient_id, doctor_username, remarks=None, test_order=None, technician_department=None):
    """
    Allows a doctor to add remarks or order tests and records the action on the blockchain.
    Includes technician department for test orders.
    """
    action_details = {
        "patient_id": patient_id,
        "doctor": doctor_username,
        "timestamp": datetime.datetime.now().isoformat(),
    }
    record_type = None

    if remarks:
        action_details["remarks"] = remarks
        record_type = "doctor_remarks"
        print(f"Doctor {doctor_username} adding remarks for patient {patient_id}.")

    if test_order:
        action_details["test_order"] = test_order
        action_details["technician_department"] = technician_department if technician_department else "N/A"
        record_type = "test_order"
        print(f"Doctor {doctor_username} ordering test '{test_order}' for patient {patient_id} for department {technician_department}.")

    if remarks and test_order:
         record_type = "remarks_and_test_order" # Combine type if both are present

    if not remarks and not test_order:
        return False, "No remarks or test order provided."

    # Add the action details (or a hash) to the blockchain
    transaction_hash = add_record_to_blockchain({"type": record_type, "details": action_details})
    print(f"Doctor action recorded on blockchain with transaction hash: {transaction_hash}")

    return True, f"{record_type.replace('_', ' ').title()} recorded successfully on blockchain."

# --- Test Result Handling Functions (from step 6) ---
UPLOAD_FOLDER = "uploaded_results"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def save_uploaded_file(uploaded_file):
    """Saves the uploaded Streamlit file to a designated folder."""
    if uploaded_file is not None:
        # Sanitize filename to prevent directory traversal
        filename = os.path.basename(uploaded_file.name)
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        return file_path
    return None

def calculate_file_hash(file_path):
    """Calculates the SHA256 hash of a file."""
    if not os.path.exists(file_path):
        return None
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(4096) # Read in chunks
                if not chunk:
                    break
                hasher.update(chunk)
    except Exception as e:
        print(f"Error calculating file hash: {e}")
        return None
    return hasher.hexdigest()

def record_test_result_on_blockchain(patient_id, appointment_id, file_hash, file_path, technician_id):
    """
    Records the test result hash and linkage info on the blockchain.
    Uses a placeholder for blockchain interaction.
    Includes technician ID.
    """
    record_data = {
        "type": "test_result",
        "patient_id": patient_id,
        "appointment_id": appointment_id if appointment_id else "N/A",
        "document_hash": file_hash,
        "technician_id": technician_id,
        "timestamp": datetime.datetime.now().isoformat(),
        "storage_ref": file_path # In a real system, this might be an IPFS hash or secure ID
    }

    transaction_hash = add_record_to_blockchain(record_data)
    print(f"Test result for patient {patient_id} recorded on blockchain. Tx Hash: {transaction_hash}")
    return transaction_hash

def get_patient_test_results(patient_id):
    """
    Retrieves test result records for a given patient from the blockchain.
    Filters records by type "test_result".
    """
    # Query the blockchain for records linked to this patient
    all_patient_records = get_records_from_blockchain({"patient_id": patient_id})

    # Filter for records specifically marked as "test_result"
    test_results = [record for record in all_patient_records if record.get("type") == "test_result"]

    return test_results

# --- Admin Backend Functions (from step 7) ---
def add_user_by_admin(db_session, username, password, role):
    """Admin function to add a new user."""
    if db_session.query(User).filter_by(username=username).first():
        return False, "Username already exists."

    # Hash the password
    hashed_password = hash_password(password)

    new_user = User(username=username, password=hashed_password, role=role)
    db_session.add(new_user)
    db_session.commit()
    return True, "User added successfully."

def get_all_users(db_session):
    """Admin function to get all users."""
    return db_session.query(User).all()

def get_user_by_id(db_session, user_id):
     """Admin function to get a user by ID."""
     return db_session.query(User).filter_by(id=user_id).first()

def edit_user_by_admin(db_session, user_id, username=None, password=None, role=None):
    """Admin function to edit an existing user."""
    user = db_session.query(User).filter_by(id=user_id).first()
    if not user:
        return False, "User not found."

    if username and username != user.username and db_session.query(User).filter_by(username=username).first():
         return False, "Username already exists."

    if username:
        user.username = username
    if password:
        # Hash the new password
        user.password = hash_password(password)
    if role:
        user.role = role

    db_session.commit()
    return True, "User updated successfully."

def delete_user_by_admin(db_session, user_id):
    """Admin function to delete a user."""
    user = db_session.query(User).filter_by(id=user_id).first()
    if not user:
        return False, "User not found."

    db_session.delete(user)
    db_session.commit()
    return True, "User deleted successfully."

def add_department_by_admin(db_session, name):
    """Admin function to add a new department."""
    if db_session.query(Department).filter_by(name=name).first():
        return False, "Department name already exists."

    new_department = Department(name=name)
    db_session.add(new_department)
    db_session.commit()
    return True, "Department added successfully."

def get_all_departments(db_session):
    """Admin function to get all departments."""
    return db_session.query(Department).all()

def get_department_by_id(db_session, department_id):
    """Admin function to get a department by ID."""
    return db_session.query(Department).filter_by(id=department_id).first()

def edit_department_by_admin(db_session, department_id, name):
    """Admin function to edit an existing department."""
    department = db_session.query(Department).filter_by(id=department_id).first()
    if not department:
        return False, "Department not found."

    if name != department.name and db_session.query(Department).filter_by(name=name).first():
         return False, "Department name already exists."

    department.name = name
    db_session.commit()
    return True, "Department updated successfully."

def delete_department_by_admin(db_session, department_id):
    """Admin function to delete a department."""
    department = db_session.query(Department).filter_by(id=department_id).first()
    if not department:
        return False, "Department not found."

    db_session.delete(department)
    db_session.commit()
    return True, "Department deleted successfully."


# --- User Interface (Streamlit) Functions (from step 4, 6, 7) ---

# Patient Interface
def show_patient_dashboard():
    st.header("Patient Dashboard")
    # Assuming patient_id is available and linked to the logged-in username
    # For this example, we'll use the username as a placeholder patient_id
    current_patient_id = st.session_state.get('username', 'Unknown Patient') # Use username as placeholder ID

    st.write(f"Welcome, {current_patient_id}! Here you can view your records, book appointments, and view test results.")

    st.subheader("Your Records")
    # Placeholder for displaying all patient records (appointments, remarks, test results)
    st.write("Display your full health records here.")
    # Fetch and display records using get_patient_records_from_blockchain (placeholder)
    patient_records = get_patient_records_from_blockchain(current_patient_id)
    if patient_records:
        st.write("Recent Activity:")
        for record in patient_records:
            st.write(f"- Type: {record.get('type', 'N/A')}, Timestamp: {record.get('timestamp', 'N/A')}, Details: {record.get('details', record)}") # Display placeholder details or full record dict
    else:
        st.info("No records found yet.")

    st.subheader("Book Appointment")
    # Form for appointment booking
    db_session = next(get_session())
    departments = get_all_departments(db_session)
    department_names = [dept.name for dept in departments]
    db_session.close() # Close the session

    with st.form("appointment_form"):
        st.write("Request a new appointment")
        selected_department = st.selectbox("Select Department", [""] + department_names)
        appointment_date = st.date_input("Preferred Date")
        appointment_time = st.time_input("Preferred Time")
        # Doctor selection is complex (availability, specialization). Placeholder for now.
        # doctor_name = st.text_input("Preferred Doctor Name (Optional Placeholder)")
        submitted = st.form_submit_button("Request Appointment")

        if submitted:
            if selected_department and appointment_date and appointment_time:
                # Combine date and time into a datetime object
                appointment_datetime = datetime.datetime.combine(appointment_date, appointment_time)
                # In a real app, you'd check if a doctor is available in this department at this time.
                # For now, record the request with placeholder doctor info.
                doctor_placeholder = "Pending Doctor Assignment" # Placeholder
                success, message = book_appointment_with_blockchain(current_patient_id, doctor_placeholder, appointment_datetime, selected_department)
                if success:
                    st.success(message)
                else:
                    st.error(message)
            else:
                st.warning("Please select a department and choose a date and time.")


    st.subheader("Test Results")
    st.write("Here are your available test results:")

    # Retrieve test results for the patient
    test_results = get_patient_test_results(current_patient_id)

    if test_results:
        for i, result in enumerate(test_results):
            st.write(f"--- Result {i+1} ---")
            st.write(f"Appointment ID: {result.get('appointment_id', 'N/A')}")
            st.write(f"Technician ID: {result.get('technician_id', 'N/A')}")
            st.write(f"Upload Timestamp: {result.get('timestamp', 'N/A')}")
            st.write(f"Document Hash: {result.get('document_hash', 'N/A')}")

            storage_ref = result.get('storage_ref') # Get the storage reference (e.g., file path)

            if storage_ref and os.path.exists(storage_ref):
                 try:
                    with open(storage_ref, "rb") as file:
                        st.download_button(
                            label=f"Download Result {i+1}",
                            data=file,
                            file_name=os.path.basename(storage_ref),
                            mime="application/pdf",
                            key=f"download_{i}_{result.get('record_id', i)}" # Unique key
                        )
                 except Exception as e:
                    st.error(f"Error downloading file: {e}")
                    st.write("Cannot download this result.")

            else:
                st.warning(f"File not found for Result {i+1}. Storage reference: {storage_ref}")
                st.write("Cannot view or download this result.")
            st.write("-----------------")
    else:
        st.info("No test results found for you.")


# Doctor Interface
def show_doctor_dashboard():
    st.header("Doctor Dashboard")
    current_doctor_username = st.session_state.get('username', 'Unknown Doctor')
    st.write(f"Welcome, Dr. {current_doctor_username}! Here you can view patient records, add remarks, order tests, and manage appointments.")

    st.subheader("Patient Records")
    # Placeholder for searching/viewing patient records
    patient_search_term = st.text_input("Enter Patient Username or ID (Placeholder)")
    search_button = st.button("Search Patient")

    # Store selected patient ID in session state
    if 'selected_patient_id_doctor' not in st.session_state:
        st.session_state['selected_patient_id_doctor'] = None

    if search_button and patient_search_term:
        # In a real app, search your database or blockchain records for patients matching the term
        # For placeholder: allow "patient123" or "patient_with_remarks" to show example data
        found_patients = []
        if patient_search_term.lower() == "patient123":
            found_patients = [{"id": "patient123", "username": "patient123", "details": "Example Patient Data"}]
        elif patient_search_term.lower() == "patient_with_remarks":
             found_patients = [{"id": "patient_with_remarks", "username": "patient_with_remarks", "details": "Patient with Remarks Example"}]
        else:
             st.info(f"No patient found matching '{patient_search_term}' (placeholder search). Try 'patient123' or 'patient_with_remarks'.")


        if found_patients:
            st.write("Search Results (Placeholder):")
            patient_options = {f"{p['username']} (ID: {p['id']})": p['id'] for p in found_patients}
            selected_patient_display = st.selectbox("Select a patient:", [""] + list(patient_options.keys()))
            if selected_patient_display:
                 st.session_state['selected_patient_id_doctor'] = patient_options[selected_patient_display]
                 st.success(f"Selected patient: {selected_patient_display}")
            else:
                 st.session_state['selected_patient_id_doctor'] = None


    # Display selected patient's record details
    if st.session_state['selected_patient_id_doctor']:
        selected_patient_id = st.session_state['selected_patient_id_doctor']
        st.subheader(f"Record for Patient: {selected_patient_id}")
        st.write("Displaying patient's health records (Placeholder):")

        # Retrieve and display all record types for this patient
        patient_full_records = get_patient_records_from_blockchain(selected_patient_id)

        if patient_full_records:
             st.write("Full Record History:")
             for rec in patient_full_records:
                  st.json(rec) # Display raw record data from placeholder function
        else:
             st.info(f"No records found for patient {selected_patient_id} (placeholder retrieval).")


        st.subheader("Add Remarks / Order Tests")
        # Form for adding remarks and ordering tests for the selected patient
        db_session = next(get_session())
        departments = get_all_departments(db_session)
        technician_departments = [dept.name for dept in departments]
        db_session.close() # Close the session

        with st.form(f"doctor_actions_form_{selected_patient_id}"): # Unique key per patient
            st.write(f"Add remarks or order tests for Patient: **{selected_patient_id}**")
            remarks = st.text_area("Add Remarks (Optional)")
            test_order = st.text_input("Order Test (e.g., Blood Work, X-Ray) (Optional)")
            selected_technician_department = st.selectbox("Select Technician Department (for Test Order)", [""] + technician_departments)

            submitted = st.form_submit_button("Submit Actions")

            if submitted:
                if remarks or test_order:
                     success, message = doctor_add_remarks_or_order_tests_with_blockchain(
                        selected_patient_id,
                        current_doctor_username,
                        remarks if remarks else None,
                        test_order if test_order else None,
                        selected_technician_department if test_order else None # Only include dept if test is ordered
                    )
                     if success:
                         st.success(message)
                         # Optionally refresh the patient record display
                     else:
                         st.error(message)
                else:
                     st.warning("Please add remarks or order a test.")


    st.subheader("Manage Appointments")
    # Placeholder for managing doctor's appointments
    st.write("Display and manage your upcoming appointments here.")
    st.write("Placeholder: List of appointments requested for your department.")


# Staff/Technician Interface
def show_technician_dashboard():
    st.header("Staff/Technician Dashboard")
    current_technician_id = st.session_state.get('username', 'Unknown Technician') # Assuming technician login stores ID in username
    st.write(f"Welcome, {current_technician_id}! Here you can upload test results.")

    st.subheader("Upload Test Results")
    # Form for uploading test results and linking to patient/appointment
    with st.form("upload_results_form"):
        st.write("Upload a test result document (e.g., PDF).")
        uploaded_file = st.file_uploader("Choose a PDF file", type="pdf")
        patient_id_link = st.text_input("Link to Patient Username/ID")
        appointment_id_link = st.text_input("Link to Appointment ID (Optional)")
        submitted = st.form_submit_button("Upload and Link Result")

        if submitted:
            if uploaded_file is not None and patient_id_link:
                # Step 2: Securely store the file
                file_path = save_uploaded_file(uploaded_file)

                if file_path:
                    # Step 3: Calculate the hash
                    file_hash = calculate_file_hash(file_path)

                    if file_hash:
                        # Step 4 & 5: Link and record on blockchain
                        transaction_hash = record_test_result_on_blockchain(
                            patient_id_link,
                            appointment_id_link,
                            file_hash,
                            file_path, # Storing file_path as a placeholder storage_ref - REPLACE WITH SECURE REF
                            current_technician_id # Include technician ID
                        )
                        st.success(f"File '{uploaded_file.name}' uploaded, hashed, and linked to Patient ID '{patient_id_link}'.")
                        st.write(f"Document Hash: {file_hash}")
                        st.write(f"Blockchain Transaction Hash (Placeholder): {transaction_hash}")
                        # In a real app, you'd also want to associate this storage_ref with the record on the blockchain or a secure database
                    else:
                        st.error("Failed to calculate file hash.")
                else:
                    st.error("Failed to save the uploaded file.")
            elif not uploaded_file:
                st.warning("Please upload a PDF file.")
            elif not patient_id_link:
                 st.warning("Please enter the Patient Username/ID.")

# Admin Interface
def show_admin_dashboard():
    st.header("Admin Dashboard")
    st.write(f"Welcome, Admin {st.session_state.get('username', 'Admin')}! Here you can manage users and system settings.")

    # Use SQLAlchemy session
    db_session = next(get_session())

    # --- Manage Users ---
    st.subheader("Manage Users")

    # Add New User Form
    st.write("#### Add New User")
    with st.form(key="add_user_form"):
        new_username = st.text_input("Username")
        new_password = st.text_input("Password", type="password")
        new_role = st.selectbox("Role", ["Patient", "Doctor", "Staff/Technician", "Admin"])
        add_submitted = st.form_submit_button("Add User")

        if add_submitted:
            if new_username and new_password and new_role:
                success, message = add_user_by_admin(db_session, new_username, new_password, new_role)
                if success:
                    st.success(message)
                    st.experimental_rerun() # Refresh to show updated list
                else:
                    st.error(message)
            else:
                st.warning("Please fill in all fields.")

    # Display existing users
    st.write("#### Existing Users")
    users = get_all_users(db_session)
    if users:
        user_data = [{"ID": user.id, "Username": user.username, "Role": user.role} for user in users]
        # Use st.dataframe for a potentially interactive table
        st.dataframe(user_data, use_container_width=True)

        # Select user for editing/deletion
        user_ids = [user.id for user in users]
        # Add a default empty option
        selected_user_id = st.selectbox("Select User ID to Edit/Delete", [""] + user_ids, format_func=lambda x: str(x) if x != "" else "Select a user")

        if selected_user_id != "": # Check if a user is actually selected
            selected_user = get_user_by_id(db_session, selected_user_id)
            if selected_user:
                st.write(f"Selected User: **{selected_user.username}** (Role: {selected_user.role})")

                # Edit User Form
                st.write("#### Edit User")
                with st.form(key=f"edit_user_form_{selected_user_id}"): # Unique key
                    edit_username = st.text_input("New Username", value=selected_user.username)
                    edit_password = st.text_input("New Password (Leave blank to keep current)", type="password")
                    edit_role = st.selectbox("New Role", ["Patient", "Doctor", "Staff/Technician", "Admin"], index=["Patient", "Doctor", "Staff/Technician", "Admin"].index(selected_user.role))
                    edit_submitted = st.form_submit_button("Update User")

                    if edit_submitted:
                        # Only pass password if it was entered
                        password_to_pass = edit_password if edit_password else None
                        success, message = edit_user_by_admin(db_session, selected_user_id, edit_username, password_to_pass, edit_role)
                        if success:
                            st.success(message)
                            st.experimental_rerun() # Refresh to show updated list
                        else:
                            st.error(message)

                # Delete User Button
                st.write("#### Delete User")
                if st.button(f"Delete User: {selected_user.username}", key=f"delete_user_{selected_user_id}"): # Unique key
                    # Add a confirmation step for deletion
                    if st.warning(f"Are you sure you want to delete user '{selected_user.username}'?"):
                         if st.button("Confirm Deletion", key=f"confirm_delete_{selected_user_id}"): # Unique key for confirm
                            success, message = delete_user_by_admin(db_session, selected_user_id)
                            if success:
                                st.success(message)
                                st.experimental_rerun() # Refresh to show updated list
                            else:
                                st.error(message)
    else:
        st.info("No users found.")


    st.markdown("---") # Separator

    # --- Manage Departments ---
    st.subheader("Manage Departments")

    # Add New Department Form
    st.write("#### Add New Department")
    with st.form(key="add_department_form"):
        new_dept_name = st.text_input("Department Name")
        add_dept_submitted = st.form_submit_button("Add Department")

        if add_dept_submitted:
            if new_dept_name:
                success, message = add_department_by_admin(db_session, new_dept_name)
                if success:
                    st.success(message)
                    st.experimental_rerun() # Refresh
                else:
                    st.error(message)
            else:
                st.warning("Department name cannot be empty.")

    # Display existing departments
    st.write("#### Existing Departments")
    departments = get_all_departments(db_session)
    if departments:
        dept_data = [{"ID": dept.id, "Name": dept.name} for dept in departments]
        st.dataframe(dept_data, use_container_width=True)

        # Select department for editing/deletion
        dept_ids = [dept.id for dept in departments]
         # Add a default empty option
        selected_dept_id = st.selectbox("Select Department ID to Edit/Delete", [""] + dept_ids, format_func=lambda x: str(x) if x != "" else "Select a department")

        if selected_dept_id != "": # Check if a department is actually selected
            selected_dept = get_department_by_id(db_session, selected_dept_id)
            if selected_dept:
                st.write(f"Selected Department: **{selected_dept.name}**")

                # Edit Department Form
                st.subheader("Edit Department")
                with st.form(key=f"edit_department_form_{selected_dept_id}"): # Unique key
                    edit_dept_name = st.text_input("New Department Name", value=selected_dept.name)
                    edit_dept_submitted = st.form_submit_button("Update Department")

                    if edit_dept_submitted:
                        if edit_dept_name:
                            success, message = edit_department_by_admin(db_session, selected_dept_id, edit_dept_name)
                            if success:
                                st.success(message)
                                st.experimental_rerun() # Refresh
                            else:
                                st.error(message)
                        else:
                             st.warning("Department name cannot be empty.")


                # Delete Department Button
                st.write("#### Delete Department")
                if st.button(f"Delete Department: {selected_dept.name}", key=f"delete_dept_{selected_dept_id}"): # Unique key
                    # Add a confirmation step
                    if st.warning(f"Are you sure you want to delete department '{selected_dept.name}'?"):
                        if st.button("Confirm Deletion", key=f"confirm_delete_dept_{selected_dept_id}"): # Unique key for confirm
                            success, message = delete_department_by_admin(db_session, selected_dept_id)
                            if success:
                                st.success(message)
                                st.experimental_rerun() # Refresh
                            else:
                                st.error(message)

    else:
        st.info("No departments found.")


    # Close the session
    db_session.close()


# --- Main Application Flow ---

st.set_page_config(page_title="EHR Blockchain App", layout="wide")

st.title("Electronic Health Records powered by Blockchain")

# Initialize session state for login status and user info
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'user_role' not in st.session_state:
    st.session_state['user_role'] = None
if 'username' not in st.session_state:
    st.session_state['username'] = None

# --- Sidebar for navigation or login ---
with st.sidebar:
    if not st.session_state['logged_in']:
        st.subheader("Login or Register")
        login_or_register = st.radio("Choose an action:", ["Login", "Register", "Technician Login"])

        if login_or_register == "Login":
            st.header("User Login")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.button("Login"):
                success, role, message = login_user(username, password)
                if success:
                    st.session_state['logged_in'] = True
                    st.session_state['user_role'] = role
                    st.session_state['username'] = username
                    st.success(message)
                    st.experimental_rerun() # Rerun to show appropriate interface
                else:
                    st.error(message)

        elif login_or_register == "Register":
            st.header("User Registration")
            new_username = st.text_input("New Username")
            new_password = st.text_input("New Password", type="password")
            role = st.selectbox("Select Role", ["Patient", "Doctor", "Admin"]) # Technicians are not registered this way
            if st.button("Register"):
                if new_username and new_password and role:
                    success, message = create_user_account_with_blockchain(new_username, new_password, role)
                    if success:
                        st.success(message)
                         # Clear form fields after successful registration (optional)
                        st.experimental_rerun()
                    else:
                        st.error(message)
                else:
                    st.warning("Please fill in all fields.")


        elif login_or_register == "Technician Login":
            st.header("Technician Login")
            technician_id = st.text_input("Technician ID")
            secure_token = st.text_input("Secure Token", type="password") # REPLACE WITH SECURE METHOD
            if st.button("Technician Login"):
                success, message = technician_login(technician_id, secure_token)
                if success:
                    st.session_state['logged_in'] = True
                    st.session_state['user_role'] = "Staff/Technician" # Assign the technician role
                    st.session_state['username'] = technician_id # Store technician ID as username
                    st.success(message)
                    st.experimental_rerun() # Rerun to show appropriate interface
                else:
                    st.error(message)

    else:
        st.write(f"Welcome, {st.session_state['username']} ({st.session_state['user_role']})")
        if st.button("Logout"):
            st.session_state['logged_in'] = False
            st.session_state['user_role'] = None
            st.session_state['username'] = None
            st.experimental_rerun() # Rerun to show login interface

# --- Main Content Area ---
if st.session_state['logged_in']:
    # Display content based on user role
    if st.session_state['user_role'] == "Patient":
        show_patient_dashboard()

    elif st.session_state['user_role'] == "Doctor":
        show_doctor_dashboard()

    elif st.session_state['user_role'] == "Staff/Technician":
        show_technician_dashboard()

    elif st.session_state['user_role'] == "Admin":
        show_admin_dashboard()

else:
    st.info("Please log in or register to access the application.")
    st.write("Choose 'Login', 'Register', or 'Technician Login' from the sidebar.")
