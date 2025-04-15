# Description: This is a simple example of how to use the Fernet symmetric encryption algorithm from the cryptography library in Python. The code generates a key, encrypts a message, and then decrypts it back to its original form. The encrypted message is printed in binary format, and the decrypted message is printed as a string.

# import streamlit as st
# #Fernet gurentees that a msg cannot be encrypted without its key
# from cryptography.fernet import Fernet

# #key shoulb be saved
# key = Fernet.generate_key()
# f = Fernet(key)

# #Converting the msg in binary is important
# msg = b'My message'

# Encrypt_msg = f.encrypt(msg)

# print(f'{msg}\n{Encrypt_msg}')

# Decrypt_msg = f.decrypt(Encrypt_msg)
# final_decrypted_msg = Decrypt_msg.decode('utf-8')

# print(final_decrypted_msg)

import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import base64
import json
import os

# File paths
KEY_FILE = "fernet.key"
DATA_FILE = "data.json"

# Function to generate or load encryption key
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        return key

# Load or generate the key
KEY = load_or_create_key()
cipher = Fernet(KEY)

# Load stored data or initialize empty dict
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

# Save stored data
def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

stored_data = load_data()

# Initialize session state for failed attempts
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    if encrypted_text in stored_data:
        if stored_data[encrypted_text]["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            stored_data[encrypted_text] = {"passkey": hashed_passkey}
            save_data(stored_data)
            st.success(f"✅ Data stored securely!\n\n**Encrypted Data:** {encrypted_text}")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)
            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                remaining_attempts = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining_attempts}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")