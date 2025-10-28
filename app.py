"""
app.py
Blockchain-based Electronic Health Record (EHR) - Single-file Streamlit app

Features:
- Roles: Patient, Doctor, Technician (dept-login), Admin
- Patient/Doctor/Admin account creation and login
- Technician login via department + password (created by Admin)
- Appointment requests, doctor accept/reject
- Doctor remarks/diagnosis (private), prescribe tests and assign to technician department
- Technician sees test requests for their department (cannot see doctor's remarks)
- Technician uploads PDF results; patients can download their PDF
- Basic blockchain ledger (local JSON) that stores events (immutable log)
- Local JSON files used to persist data: users.json, appointments.json, tests.json, departments.json, blockchain.json
- Uploaded files saved to ./uploads/ ; their hash stored in blockchain and test record

Note: This is a prototype for educational/demo purposes, not production-grade security.
"""

import streamlit as st
import uuid
import json
import os
from datetime import datetime
import hashlib
import pandas as pd
import bcrypt

# -----------------------
# Config / Paths
# -----------------------
DATA_DIR = "data"
UPLOAD_DIR = "uploads"

USERS_FILE = os.path.join(DATA_DIR, "users.json")          # stores patients, doctors, admins
APPOINTMENTS_FILE = os.path.join(DATA_DIR, "appointments.json")
TESTS_FILE = os.path.join(DATA_DIR, "tests.json")
DEPARTMENTS_FILE = os.path.join(DATA_DIR, "departments.json")
BLOCKCHAIN_FILE = os.path.join(DATA_DIR, "blockchain.json")

# Ensure directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# -----------------------
# Utility functions for file operations and simple blockchain
# -----------------------
def read_json(path, default):
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump(default, f, indent=2)
        return default
    with open(path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return default

def write_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)

# Initialize files with default structures if missing
users = read_json(USERS_FILE, {"patients": [], "doctors": [], "admins": []})
appointments = read_json(APPOINTMENTS_FILE, {"appointments": []})
tests_db = read_json(TESTS_FILE, {"tests": []})
departments_db = read_json(DEPARTMENTS_FILE, {"departments": []})  # list of {"name": "..", "password_hash": ".."}
blockchain = read_json(BLOCKCHAIN_FILE, {"chain": []})

def hash_password(plaintext: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(plaintext.encode(), salt).decode()

def check_password(plaintext: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plaintext.encode(), hashed.encode())
    except Exception:
        return False

def add_block(action: str, actor: str, patient_id: str = None, extra: dict = None):
    """
    Append an event to the simple blockchain JSON
    """
    block = {
        "index": len(blockchain["chain"]) + 1,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "action": action,
        "actor": actor,
        "patient_id": patient_id,
        "extra": extra or {}
    }
    # naive previous hash
    prev_hash = blockchain["chain"][-1]["hash"] if blockchain["chain"] else "0"
    block_string = json.dumps(block, sort_keys=True)
    block_hash = hashlib.sha256((block_string + prev_hash).encode()).hexdigest()
    block["hash"] = block_hash
    block["prev_hash"] = prev_hash
    blockchain["chain"].append(block)
    write_json(BLOCKCHAIN_FILE, blockchain)

def generate_patient_id():
    return "PAT" + uuid.uuid4().hex[:8].upper()

def generate_doctor_id():
    return "DOC" + uuid.uuid4().hex[:8].upper()

def save_state_files():
    write_json(USERS_FILE, users)
    write_json(APPOINTMENTS_FILE, appointments)
    write_json(TESTS_FILE, tests_db)
    write_json(DEPARTMENTS_FILE, departments_db)
    write_json(BLOCKCHAIN_FILE, blockchain)

def hash_file_bytes(bytes_data) -> str:
    return hashlib.sha256(bytes_data).hexdigest()

# -----------------------
# Streamlit App UI helpers
# -----------------------
st.set_page_config(page_title="Blockchain EHR", layout="wide")

st.title("🔗 Blockchain-based Electronic Health Record (EHR)")

menu_col1, menu_col2 = st.columns([1, 2])
with menu_col1:
    role = st.selectbox("Select role", ["Patient", "Doctor", "Technician", "Admin"])

with menu_col2:
    st.markdown("**Quick actions:**")
    st.write("- Patients/Doctors: create account then login")
    st.write("- Technicians: login with department name & password (set by Admin)")
    st.write("- Admin: create doctors & technician departments")

# Create a simple session management
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user = None
    st.session_state.role = None

# -----------------------
# Authentication flows
# -----------------------
def patient_register_form():
    st.header("Patient - Create Account")
    with st.form("patient_signup"):
        name = st.text_input("Full name", key="pname")
        age = st.number_input("Age", min_value=0, max_value=120, step=1, key="page")
        sex = st.selectbox("Sex", ["Female", "Male", "Other"], key="psex")
        email = st.text_input("Email", key="pemail")
        contact = st.text_input("Contact number", key="pcontact")
        password = st.text_input("Password", type="password", key="ppass")
        submitted = st.form_submit_button("Create Account")
    if submitted:
        # check email uniqueness
        if any(u["email"].lower() == email.lower() for u in users["patients"]):
            st.error("An account with this email already exists (patient).")
            return
        patient_id = generate_patient_id()
        hashed = hash_password(password)
        patient = {
            "id": patient_id,
            "name": name,
            "age": age,
            "sex": sex,
            "email": email.lower(),
            "contact": contact,
            "password_hash": hashed,
            "created_at": datetime.utcnow().isoformat()
        }
        users["patients"].append(patient)
        save_state_files()
        add_block("PatientCreated", f"Patient:{name}", patient_id, {"email": email})
        st.success(f"Account created. Your Patient ID is **{patient_id}**. Please login.")

def doctor_register_form():
    st.header("Doctor - Create Account")
    with st.form("doctor_signup"):
        name = st.text_input("Full name", key="dname")
        age = st.number_input("Age", min_value=18, max_value=120, step=1, key="dage")
        sex = st.selectbox("Sex", ["Female", "Male", "Other"], key="dsex")
        email = st.text_input("Email", key="demail")
        contact = st.text_input("Contact number", key="dcontact")
        specialization = st.text_input("Department / Specialization (e.g. Cardiology)", key="dspec")
        password = st.text_input("Password", type="password", key="dpass")
        submitted = st.form_submit_button("Create Account")
    if submitted:
        if any(u["email"].lower() == email.lower() for u in users["doctors"]):
            st.error("An account with this email already exists (doctor).")
            return
        doctor_id = generate_doctor_id()
        hashed = hash_password(password)
        doctor = {
            "id": doctor_id,
            "name": name,
            "age": age,
            "sex": sex,
            "email": email.lower(),
            "contact": contact,
            "specialization": specialization,
            "password_hash": hashed,
            "created_at": datetime.utcnow().isoformat()
        }
        users["doctors"].append(doctor)
        save_state_files()
        # ensure department exists
        dept_names = [d["name"].lower() for d in departments_db.get("departments", [])]
        if specialization.lower() not in dept_names:
            departments_db.setdefault("departments", []).append({"name": specialization, "password_hash": ""})
            save_state_files()
        add_block("DoctorCreated", f"Doctor:{name}", None, {"email": email, "specialization": specialization})
        st.success(f"Doctor account created. Your Doctor ID is **{doctor_id}**. Please login.")

def admin_create_form():
    st.header("Admin - Create Account (one-time or additional)")
    with st.form("admin_signup"):
        name = st.text_input("Full name", key="aname")
        email = st.text_input("Email", key="aemail")
        password = st.text_input("Password", type="password", key="apass")
        submitted = st.form_submit_button("Create Admin")
    if submitted:
        if any(a["email"].lower() == email.lower() for a in users["admins"]):
            st.error("An admin account with this email already exists.")
            return
        admin = {
            "id": "ADM" + uuid.uuid4().hex[:8].upper(),
            "name": name,
            "email": email.lower(),
            "password_hash": hash_password(password),
            "created_at": datetime.utcnow().isoformat()
        }
        users["admins"].append(admin)
        save_state_files()
        add_block("AdminCreated", f"Admin:{name}", None, {"email": email})
        st.success("Admin account created. You can login now.")

def login_patient():
    st.header("Patient Login")
    with st.form("patient_login"):
        email = st.text_input("Email", key="login_p_email")
        password = st.text_input("Password", type="password", key="login_p_pass")
        submitted = st.form_submit_button("Login")
    if submitted:
        pat = next((p for p in users["patients"] if p["email"].lower() == email.lower()), None)
        if pat and check_password(password, pat["password_hash"]):
            st.session_state.logged_in = True
            st.session_state.user = pat
            st.session_state.role = "Patient"
            add_block("Login", f"Patient:{pat['name']}", pat["id"])
            st.success("Logged in.")
        else:
            st.error("Invalid credentials.")

def login_doctor():
    st.header("Doctor Login")
    with st.form("doctor_login"):
        email = st.text_input("Email", key="login_d_email")
        password = st.text_input("Password", type="password", key="login_d_pass")
        submitted = st.form_submit_button("Login")
    if submitted:
        doc = next((d for d in users["doctors"] if d["email"].lower() == email.lower()), None)
        if doc and check_password(password, doc["password_hash"]):
            st.session_state.logged_in = True
            st.session_state.user = doc
            st.session_state.role = "Doctor"
            add_block("Login", f"Doctor:{doc['name']}", None, {"email": email})
            st.success("Logged in.")
        else:
            st.error("Invalid credentials.")

def login_admin():
    st.header("Admin Login")
    with st.form("admin_login"):
        email = st.text_input("Admin Email", key="login_a_email")
        password = st.text_input("Password", type="password", key="login_a_pass")
        submitted = st.form_submit_button("Login")
    if submitted:
        adm = next((a for a in users["admins"] if a["email"].lower() == email.lower()), None)
        if adm and check_password(password, adm["password_hash"]):
            st.session_state.logged_in = True
            st.session_state.user = adm
            st.session_state.role = "Admin"
            add_block("Login", f"Admin:{adm['name']}")
            st.success("Logged in.")
        else:
            st.error("Invalid admin credentials.")

def login_technician():
    st.header("Technician Login (Department)")
    dept_names = [d["name"] for d in departments_db.get("departments", [])]
    if not dept_names:
        st.warning("No technician departments configured yet. Ask Admin to add departments.")
        return
    with st.form("tech_login"):
        dept = st.selectbox("Department", dept_names, key="tech_dept")
        password = st.text_input("Department Password", type="password", key="tech_pass")
        submitted = st.form_submit_button("Login")
    if submitted:
        dept_rec = next((d for d in departments_db.get("departments", []) if d["name"] == dept), None)
        if dept_rec:
            pw_hash = dept_rec.get("password_hash", "")
            if pw_hash and check_password(password, pw_hash):
                st.session_state.logged_in = True
                st.session_state.user = {"department": dept}
                st.session_state.role = "Technician"
                add_block("Login", f"TechnicianDept:{dept}")
                st.success(f"Logged in as technician for: {dept}")
            else:
                st.error("Invalid department password.")
        else:
            st.error("Department not found.")

# -----------------------
# Role-specific dashboards
# -----------------------
def patient_dashboard(user):
    st.sidebar.title("Patient Menu")
    choice = st.sidebar.radio("Go to", ["Profile", "Book Appointment", "My Appointments", "View Test Results", "Logout"])

    if choice == "Profile":
        st.header("Profile")
        st.write(f"**Patient ID:** {user['id']}")
        st.write(f"**Name:** {user['name']}")
        st.write(f"**Age:** {user['age']}")
        st.write(f"**Sex:** {user['sex']}")
        st.write(f"**Email:** {user['email']}")
        st.write(f"**Contact:** {user['contact']}")
        st.write(f"**Registered on:** {user.get('created_at','-')}")
    elif choice == "Book Appointment":
        st.header("Book an Appointment")
        with st.form("book_appointment"):
            dept_names = [d["name"] for d in departments_db.get("departments", [])] or ["General medicine"]
            dept = st.selectbox("Department", dept_names)
            date = st.date_input("Select date")
            notes = st.text_area("Any notes (optional)")
            submitted = st.form_submit_button("Request Appointment")
        if submitted:
            appt_id = "APPT" + uuid.uuid4().hex[:8].upper()
            appointment = {
                "id": appt_id,
                "patient_id": user["id"],
                "patient_name": user["name"],
                "department": dept,
                "date": str(date),
                "notes": notes,
                "status": "Pending",
                "doctor_id": None,
                "doctor_name": None,
                "created_at": datetime.utcnow().isoformat()
            }
            appointments["appointments"].append(appointment)
            save_state_files()
            add_block("AppointmentRequested", f"Patient:{user['name']}", user["id"], {"appointment_id": appt_id, "department": dept})
            st.success("Appointment requested. You will be notified when a doctor accepts.")
    elif choice == "My Appointments":
        st.header("My Appointments")
        my = [a for a in appointments["appointments"] if a["patient_id"] == user["id"]]
        if not my:
            st.info("No appointments found.")
        else:
            df = pd.DataFrame(my)
            st.dataframe(df[["id", "department", "date", "status", "doctor_name"]])
    elif choice == "View Test Results":
        st.header("Test Results")
        my_tests = [t for t in tests_db["tests"] if t["patient_id"] == user["id"] and t.get("result_file")]
        if not my_tests:
            st.info("No results available yet.")
        else:
            for t in my_tests:
                st.markdown(f"**Test ID:** {t['id']}  — **Test(s):** {', '.join(t['tests'])}")
                st.write(f"Assigned by Doctor: {t['doctor_name']} (Dept: {t['assigned_dept']})")
                if "result_file" in t and t["result_file"]:
                    file_path = t["result_file"]
                    # read bytes for download
                    try:
                        with open(file_path, "rb") as f:
                            data = f.read()
                        st.download_button(label="Download Result PDF", data=data, file_name=os.path.basename(file_path))
                    except FileNotFoundError:
                        st.error("Result file not found on server.")
    elif choice == "Logout":
        st.session_state.logged_in = False
        st.session_state.user = None
        st.session_state.role = None
        st.success("Logged out.")
        st.experimental_rerun()

def doctor_dashboard(user):
    st.sidebar.title("Doctor Menu")
    choice = st.sidebar.radio("Go to", ["Pending Appointments", "Accepted Appointments", "My Records", "Logout"])

    # Helper: my specialization
    specialization = user.get("specialization", "")

    if choice == "Pending Appointments":
        st.header("Pending Appointment Requests")
        pending = [a for a in appointments["appointments"] if a["department"].lower() == specialization.lower() and a["status"] == "Pending"]
        if not pending:
            st.info("No pending appointments in your department.")
        else:
            for appt in pending:
                with st.expander(f"Appointment {appt['id']} — {appt['patient_name']} on {appt['date']}"):
                    st.write("Patient Notes:", appt.get("notes", "-"))
                    if st.button(f"Accept {appt['id']}", key=f"accept_{appt['id']}"):
                        appt["status"] = "Accepted"
                        appt["doctor_id"] = user["id"]
                        appt["doctor_name"] = user["name"]
                        save_state_files()
                        add_block("AppointmentAccepted", f"Doctor:{user['name']}", appt["patient_id"], {"appointment_id": appt["id"]})
                        st.success("Accepted.")
                        st.experimental_rerun()
                    if st.button(f"Reject {appt['id']}", key=f"reject_{appt['id']}"):
                        appt["status"] = "Rejected"
                        save_state_files()
                        add_block("AppointmentRejected", f"Doctor:{user['name']}", appt["patient_id"], {"appointment_id": appt["id"]})
                        st.warning("Rejected.")
                        st.experimental_rerun()
    elif choice == "Accepted Appointments":
        st.header("Accepted Appointments")
        accepted = [a for a in appointments["appointments"] if a["doctor_id"] == user["id"] and a["status"] == "Accepted"]
        if not accepted:
            st.info("No accepted appointments.")
        else:
            for appt in accepted:
                with st.expander(f"{appt['id']} — {appt['patient_name']} on {appt['date']}"):
                    st.write("Patient ID:", appt["patient_id"])
                    # Show patient details
                    pat = next((p for p in users["patients"] if p["id"] == appt["patient_id"]), None)
                    if pat:
                        st.write("Name:", pat["name"])
                        st.write("Age:", pat["age"])
                        st.write("Sex:", pat["sex"])
                        st.write("Contact:", pat["contact"])
                        st.write("Email:", pat["email"])
                    # Remarks / diagnosis
                    st.subheader("Write Remarks / Diagnosis (private)")
                    diag = st.text_area("Write remarks / diagnosis here", key=f"diag_{appt['id']}")
                    if st.button(f"Save Remarks for {appt['id']}", key=f"save_diag_{appt['id']}"):
                        # store as a separate record in tests_db as 'consultation' or attach to appointment
                        appt.setdefault("remarks", []).append({
                            "doctor_id": user["id"],
                            "doctor_name": user["name"],
                            "text": diag,
                            "timestamp": datetime.utcnow().isoformat()
                        })
                        save_state_files()
                        add_block("DoctorRemarks", f"Doctor:{user['name']}", appt["patient_id"], {"appointment_id": appt["id"]})
                        st.success("Remarks saved (visible to patient and admin but hidden from technicians).")
                    # Prescribe tests
                    st.subheader("Prescribe Tests & Assign to Technician Department")
                    test_input = st.text_input("Comma-separated test names (e.g. Vitamin B12, CBC)", key=f"tests_{appt['id']}")
                    dept_names = [d["name"] for d in departments_db.get("departments", [])] or ["Pathology"]
                    assign_dept = st.selectbox("Select Technician Department", dept_names, key=f"assign_dept_{appt['id']}")
                    if st.button(f"Send Tests for {appt['id']}", key=f"send_tests_{appt['id']}"):
                        if not test_input.strip():
                            st.error("Enter at least one test.")
                        else:
                            test_list = [t.strip() for t in test_input.split(",") if t.strip()]
                            test_id = "TEST" + uuid.uuid4().hex[:8].upper()
                            test_record = {
                                "id": test_id,
                                "appointment_id": appt["id"],
                                "patient_id": appt["patient_id"],
                                "patient_name": appt["patient_name"],
                                "doctor_id": user["id"],
                                "doctor_name": user["name"],
                                "tests": test_list,
                                "assigned_dept": assign_dept,
                                "status": "Requested",
                                "result_file": None,
                                "created_at": datetime.utcnow().isoformat()
                            }
                            tests_db["tests"].append(test_record)
                            save_state_files()
                            add_block("TestsAssigned", f"Doctor:{user['name']}", appt["patient_id"], {"test_id": test_id, "tests": test_list, "dept": assign_dept})
                            st.success("Test request sent to technicians.")
    elif choice == "My Records":
        st.header("Patients & History")
        my_appts = [a for a in appointments["appointments"] if a["doctor_id"] == user["id"]]
        if not my_appts:
            st.info("You have no records yet.")
        else:
            df = pd.DataFrame(my_appts)
            st.dataframe(df[["id", "patient_name", "department", "date", "status"]])
    elif choice == "Logout":
        st.session_state.logged_in = False
        st.session_state.user = None
        st.session_state.role = None
        st.success("Logged out.")
        st.experimental_rerun()

def technician_dashboard(user):
    dept = user["department"]
    st.sidebar.title(f"Technician - {dept}")
    choice = st.sidebar.radio("Go to", ["Pending Requests", "Upload Result", "Logout"])

    if choice == "Pending Requests":
        st.header(f"Pending Test Requests for {dept}")
        pending = [t for t in tests_db["tests"] if t["assigned_dept"].lower() == dept.lower() and t["status"] == "Requested"]
        if not pending:
            st.info("No pending test requests.")
        else:
            for t in pending:
                with st.expander(f"{t['id']} — {t['patient_name']}"):
                    st.write("Patient ID:", t["patient_id"])
                    st.write("Tests requested:", ", ".join(t["tests"]))
                    st.write("Requesting doctor:", t["doctor_name"])
                    # Technician CANNOT see doctor's remarks or diagnosis
                    if st.button(f"Start Upload for {t['id']}", key=f"start_{t['id']}"):
                        st.session_state.current_test = t["id"]
                        st.experimental_rerun()

    elif choice == "Upload Result":
        st.header(f"Upload Test Result (Department: {dept})")
        # List tests assigned to this dept with status Requested
        available = [t for t in tests_db["tests"] if t["assigned_dept"].lower() == dept.lower() and t["status"] == "Requested"]
        if not available:
            st.info("No tests waiting to be processed.")
        else:
            tid = st.selectbox("Select Test Request", [t["id"] for t in available])
            test_rec = next((t for t in tests_db["tests"] if t["id"] == tid), None)
            if test_rec:
                st.write("Patient Name:", test_rec["patient_name"])
                st.write("Patient ID:", test_rec["patient_id"])
                st.write("Doctor:", test_rec["doctor_name"])
                st.write("Tests:", ", ".join(test_rec["tests"]))
                uploaded_file = st.file_uploader("Upload result PDF", type=["pdf"])
                if uploaded_file:
                    # save file to uploads with unique name
                    raw = uploaded_file.read()
                    file_hash = hash_file_bytes(raw)
                    filename = f"{test_rec['id']}_{file_hash[:10]}.pdf"
                    path = os.path.join(UPLOAD_DIR, filename)
                    with open(path, "wb") as f:
                        f.write(raw)
                    # update test record
                    test_rec["result_file"] = path
                    test_rec["status"] = "Completed"
                    test_rec["completed_at"] = datetime.utcnow().isoformat()
                    save_state_files()
                    add_block("ResultUploaded", f"TechnicianDept:{dept}", test_rec["patient_id"], {"test_id": test_rec["id"], "file_hash": file_hash})
                    st.success("Result uploaded. Patient will be able to download the PDF.")
    elif choice == "Logout":
        st.session_state.logged_in = False
        st.session_state.user = None
        st.session_state.role = None
        st.success("Logged out.")
        st.experimental_rerun()

def admin_dashboard(user):
    st.sidebar.title("Admin Menu")
    choice = st.sidebar.radio("Go to", ["Manage Doctors", "Manage Technicians", "Manage Departments", "View Blockchain Log", "Logout"])

    if choice == "Manage Doctors":
        st.header("Doctors")
        df = pd.DataFrame(users.get("doctors", []))
        if not df.empty:
            st.dataframe(df[["id", "name", "email", "specialization", "contact"]])
        else:
            st.info("No doctors yet.")
        st.subheader("Add Doctor (Admin)")
        with st.form("admin_add_doc"):
            name = st.text_input("Name", key="adm_doc_name")
            email = st.text_input("Email", key="adm_doc_email")
            specialization = st.text_input("Specialization", key="adm_doc_spec")
            password = st.text_input("Password", key="adm_doc_pass")
            submitted = st.form_submit_button("Add Doctor")
        if submitted:
            if any(d["email"].lower() == email.lower() for d in users["doctors"]):
                st.error("Doctor with this email exists.")
            else:
                doc = {
                    "id": generate_doctor_id(),
                    "name": name,
                    "email": email.lower(),
                    "specialization": specialization,
                    "password_hash": hash_password(password),
                    "created_at": datetime.utcnow().isoformat(),
                    "contact": ""
                }
                users["doctors"].append(doc)
                # ensure dept exists
                dept_names = [d["name"].lower() for d in departments_db.get("departments", [])]
                if specialization.lower() not in dept_names:
                    departments_db.setdefault("departments", []).append({"name": specialization, "password_hash": ""})
                save_state_files()
                add_block("DoctorAddedByAdmin", f"Admin:{user['name']}", None, {"doctor_email": email, "specialization": specialization})
                st.success("Doctor added. Provide credentials manually to the doctor.")

    elif choice == "Manage Technicians":
        st.header("Technician Departments")
        df = pd.DataFrame(departments_db.get("departments", []))
        if not df.empty:
            # don't display password hashes (for security), show as masked
            df_display = df.copy()
            df_display["password_set"] = df_display["password_hash"].apply(lambda x: bool(x))
            st.dataframe(df_display[["name", "password_set"]])
        else:
            st.info("No technician departments yet.")
        st.subheader("Add / Update Technician Department")
        with st.form("admin_add_tech"):
            name = st.text_input("Department Name", key="adm_tech_name")
            password = st.text_input("Department Password (share with technicians)", key="adm_tech_pass")
            submitted = st.form_submit_button("Create / Update Department")
        if submitted:
            existing = next((d for d in departments_db.get("departments", []) if d["name"].lower() == name.lower()), None)
            if existing:
                existing["password_hash"] = hash_password(password) if password else existing.get("password_hash","")
                st.success("Department updated.")
            else:
                departments_db.setdefault("departments", []).append({"name": name, "password_hash": hash_password(password)})
                st.success("Department created.")
            save_state_files()
            add_block("TechnicianDeptConfigured", f"Admin:{user['name']}", None, {"dept": name})
    elif choice == "Manage Departments":
        st.header("Hospital Departments (for appointments)")
        dept_names = [d["name"] for d in departments_db.get("departments", [])]
        st.write("Current departments:", ", ".join(dept_names) if dept_names else "None")
        with st.form("admin_add_dept"):
            new_dept = st.text_input("Add department name", key="adm_dept_name")
            submitted = st.form_submit_button("Add Department")
        if submitted and new_dept.strip():
            if any(d["name"].lower() == new_dept.lower() for d in departments_db.get("departments", [])):
                st.error("Department already exists.")
            else:
                departments_db.setdefault("departments", []).append({"name": new_dept, "password_hash": ""})
                save_state_files()
                add_block("DepartmentAdded", f"Admin:{user['name']}", None, {"dept": new_dept})
                st.success("Department added.")
    elif choice == "View Blockchain Log":
        st.header("Blockchain Ledger (Event Log)")
        chain = blockchain.get("chain", [])
        if not chain:
            st.info("Blockchain empty.")
        else:
            df = pd.DataFrame(chain)
            display_cols = ["index", "timestamp", "action", "actor", "patient_id"]
            st.dataframe(df[display_cols])
            if st.button("Show Raw Blockchain JSON"):
                st.json(chain)
    elif choice == "Logout":
        st.session_state.logged_in = False
        st.session_state.user = None
        st.session_state.role = None
        st.success("Logged out.")
        st.experimental_rerun()

# -----------------------
# Main app control flow
# -----------------------
# When not logged in, show registration/login forms based on role
if not st.session_state.logged_in:
    if role == "Patient":
        col1, col2 = st.columns(2)
        with col1:
            patient_register_form()
        with col2:
            login_patient()
    elif role == "Doctor":
        col1, col2 = st.columns(2)
        with col1:
            doctor_register_form()
        with col2:
            login_doctor()
    elif role == "Technician":
        st.info("Technicians are created by Admin. Login below.")
        login_technician()
    elif role == "Admin":
        col1, col2 = st.columns(2)
        with col1:
            admin_create_form()
        with col2:
            login_admin()
else:
    # logged in user
    if st.session_state.role == "Patient":
        patient_dashboard(st.session_state.user)
    elif st.session_state.role == "Doctor":
        doctor_dashboard(st.session_state.user)
    elif st.session_state.role == "Technician":
        technician_dashboard(st.session_state.user)
    elif st.session_state.role == "Admin":
        admin_dashboard(st.session_state.user)

# Save files at end to persist any changes
save_state_files()
