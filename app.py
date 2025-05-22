import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import json
import os
import time
import base64
import secrets
import datetime

DATA_FILE = "secure_data.json"
ATTEMPTS_FILE = "attempts.json"
LOCKOUT_DURATION = 60  # in seconds

#-------------load------------
def load_json(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return json.load(f)
    return {}

def save_json(data, file_path):
    with open(file_path, "w") as f:
        json.dump(data, f)

stored_data = load_json(DATA_FILE)
failed_attempts = load_json(ATTEMPTS_FILE)

if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
if "authorized" not in st.session_state:
    st.session_state.authorized = True

fernet = Fernet(st.session_state.fernet_key)

def hash_passkey(passkey, salt=None):
    if not salt:
        salt = secrets.token_bytes(16)
    hashed = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)
    return base64.b64encode(salt + hashed).decode()

def verify_passkey(passkey, stored_hash):
    decoded = base64.b64decode(stored_hash.encode())
    salt, hashed = decoded[:16], decoded[16:]
    new_hash = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)
    return hashed == new_hash


def insert_data(user_id, text, passkey):
    encrypted_text = fernet.encrypt(text.encode()).decode()
    hashed_passkey = hash_passkey(passkey)
    stored_data[user_id] = {
        "encrypted_text": encrypted_text,
        "passkey": hashed_passkey
    }
    save_json(stored_data, DATA_FILE)
    st.success(f"✅ Data stored securely for user: **{user_id}**")


def retrieve_data(user_id, passkey):
    if user_id not in stored_data:
        st.error("❌ No data found for this user.")
        return

    user_attempts = failed_attempts.get(user_id, {"count": 0, "last_fail": None})
    if user_attempts["count"] >= 3:
        if user_attempts["last_fail"]:
            elapsed = (datetime.datetime.now() - datetime.datetime.fromisoformat(user_attempts["last_fail"])).total_seconds()
            if elapsed < LOCKOUT_DURATION:
                st.session_state.authorized = False
                st.warning("🔒 Too many failed attempts. Please wait before retrying.")
                return
            else:
                failed_attempts[user_id] = {"count": 0, "last_fail": None}
                save_json(failed_attempts, ATTEMPTS_FILE)

    if verify_passkey(passkey, stored_data[user_id]["passkey"]):
        try:
            decrypted = fernet.decrypt(stored_data[user_id]["encrypted_text"].encode()).decode()
            st.success(f"✅ Decrypted Data: \n\n```{decrypted}```")
            failed_attempts[user_id] = {"count": 0, "last_fail": None}
            save_json(failed_attempts, ATTEMPTS_FILE)
        except Exception:
            st.error("❌ Decryption failed. Possibly incorrect key.")
    else:
        user_attempts["count"] += 1
        user_attempts["last_fail"] = datetime.datetime.now().isoformat()
        failed_attempts[user_id] = user_attempts
        save_json(failed_attempts, ATTEMPTS_FILE)
        attempts_left = 3 - user_attempts["count"]
        st.error(f"❌ Incorrect passkey. Attempts left: {max(attempts_left, 0)}")

#--------------- Admin login------------------
def login_page():
    st.title("🔐 Admin Login")

    st.markdown("Please reauthorize access after too many failed attempts.")
    with st.form("admin_login", clear_on_submit=False):
        username = st.text_input("👤 Username")
        password = st.text_input("🔑 Password", type="password")
        login_btn = st.form_submit_button("🔓 Login")

    if login_btn:
        if username == "admin" and password == "admin123":
            st.session_state.authorized = True
            failed_attempts.clear()
            save_json(failed_attempts, ATTEMPTS_FILE)
            st.success("✅ Login successful! Redirecting...")
            time.sleep(1)
            st.experimental_rerun()
        else:
            st.error("❌ Invalid credentials. Please try again.")

#------------- Main App-----------------------
def main():
    st.set_page_config(page_title="🔐 Secure Data Vault", page_icon="🔒", layout="centered")

    if not st.session_state.get("authorized", True):
        login_page()
        return

    st.sidebar.title("🔐 Secure Data Vault")
    menu = st.sidebar.radio("📂 Navigate", ["🏠 Home", "📝 Insert Data", "🔍 Retrieve Data", "🔐 Admin Login"])

    if menu == "🏠 Home":
        st.title("🔒 Secure Data Encryption System")
        st.markdown("""
        Welcome to your personal encryption vault.  
        - 🔐 Store your sensitive data securely.  
        - 🔑 Retrieve it with a strong passkey.  
        - 🚫 After 3 wrong attempts, admin login is required.  
        ---
        """)

    elif menu == "📝 Insert Data":
        st.title("📥 Store Secure Data")
        with st.form("insert_form"):
            user_id = st.text_input("🆔 User ID")
            data = st.text_area("🧾 Data to Encrypt")
            passkey = st.text_input("🔑 Set a Passkey", type="password")
            submit = st.form_submit_button("💾 Store")

        if submit:
            if user_id and data and passkey:
                insert_data(user_id, data, passkey)
            else:
                st.warning("⚠️ Please fill out all fields.")

    elif menu == "🔍 Retrieve Data":
        st.title("🔓 Retrieve Your Encrypted Data")
        with st.form("retrieve_form"):
            user_id = st.text_input("🆔 User ID")
            passkey = st.text_input("🔑 Enter Passkey", type="password")
            submit = st.form_submit_button("🔍 Decrypt")

        if submit:
            if user_id and passkey:
                retrieve_data(user_id, passkey)
            else:
                st.warning("⚠️ Please fill out all fields.")

    elif menu == "🔐 Admin Login":
        login_page()

    st.divider()
    st.caption("🔒 Built with ❤️ using Streamlit & Cryptography")

if __name__ == "__main__":
    main()
