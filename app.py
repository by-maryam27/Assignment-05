# app.py
import streamlit as st
import hashlib
import json
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os

st.set_page_config(page_title="🛡️ Secure Data Encryption", layout="centered")

# ------------------- Theme Compatible CSS -------------------
st.markdown("""
    <style>
    html, body, [class*="css"] {
        font-family: 'Segoe UI', sans-serif;
    }

    .title {
        font-size: 38px;
        font-weight: 700;
        margin-bottom: 10px;
    }

    .subtitle {
        font-size: 20px;
        margin-bottom: 25px;
    }

    .stButton>button {
        background-color: #0984e3;
        color: white;
        font-size: 16px;
        font-weight: 600;
        border: none;
        border-radius: 8px;
        padding: 10px 20px;
        transition: background-color 0.3s ease;
    }

    .stButton>button:hover {
        background-color: #74b9ff;
        color: black;
    }

    .card {
        padding: 30px 25px;
        border-radius: 12px;
        margin-bottom: 25px;
        box-shadow: 0 6px 18px rgba(0, 0, 0, 0.06);
    }

    /* Light Theme */
    @media (prefers-color-scheme: light) {
        .card {
            background-color: #ffffff;
            color: #2d3436;
        }
        .title, .subtitle {
            color: #2d3436;
        }
    }

    /* Dark Theme */
    @media (prefers-color-scheme: dark) {
        .card {
            background-color: #2c2c2e;
            color: #f1f2f6;
        }
        .title, .subtitle {
            color: #f1f2f6;
        }
    }
    </style>
""", unsafe_allow_html=True)

# ------------------- Utility Functions -------------------
def generate_key(passkey: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ------------------- Files -------------------
DATA_FILE = "data.json"
USERS_FILE = "users.json"
LOCKOUT_DURATION = 60  # seconds

# Load or create files
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

if os.path.exists(USERS_FILE):
    with open(USERS_FILE, "r") as f:
        users = json.load(f)
else:
    users = {}

# ------------------- Session State -------------------
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None

# ------------------- Navigation -------------------
st.sidebar.image("https://cdn-icons-png.flaticon.com/512/3064/3064197.png", width=100)
st.sidebar.markdown("## 🔐 Navigation")
menu = ["Home", "Login", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.radio("", menu)

# ------------------- Pages -------------------
if choice == "Home":
    st.markdown('<div class="title">🔐 Secure Encryption App</div>', unsafe_allow_html=True)
    st.markdown('<div class="subtitle">Built with Streamlit | PBKDF2 | Multi-User | JSON Encrypted Storage</div>', unsafe_allow_html=True)

    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("""
        <div class="card">
            <ul style="font-size: 17px; line-height: 2;">
                <li>🔒 Secure Password Hashing</li>
                <li>🛡️ AES Encryption with PBKDF2</li>
                <li>👥 Separate storage per user</li>
                <li>📁 Data stored in <code>data.json</code></li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.image("https://cdn-icons-png.flaticon.com/512/3107/3107367.png", width=180)

elif choice == "Login":
    st.markdown('<div class="title">🔑 Login or Register</div>', unsafe_allow_html=True)
    with st.container():
        with st.form(key="login_form"):
            username = st.text_input("👤 Username")
            password = st.text_input("🔒 Password", type="password")
            submit = st.form_submit_button("🔓 Login / Register")

            if submit and username and password:
                hashed = hash_password(password)
                if username in users:
                    if users[username]["password"] == hashed:
                        st.session_state.current_user = username
                        st.success("✅ Logged in successfully!")
                        st.session_state.failed_attempts = 0
                    else:
                        st.error("❌ Incorrect password!")
                else:
                    salt = os.urandom(16)
                    users[username] = {"password": hashed, "salt": base64.b64encode(salt).decode()}
                    with open(USERS_FILE, "w") as f:
                        json.dump(users, f)
                    st.success("✅ Registered & Logged in!")
                    st.session_state.current_user = username

elif choice == "Store Data":
    if not st.session_state.current_user:
        st.warning("🔒 Please login first.")
    else:
        st.markdown('<div class="title">📂 Store Your Secret Data</div>', unsafe_allow_html=True)
        with st.container():
            with st.form("store_form"):
                text = st.text_area("📝 Enter your secret text")
                passkey = st.text_input("🛡️ Create a passkey", type="password")
                save = st.form_submit_button("🔐 Encrypt & Save")

                if save and text and passkey:
                    salt = base64.b64decode(users[st.session_state.current_user]["salt"])
                    key = generate_key(passkey, salt)
                    f = Fernet(key)
                    encrypted_text = f.encrypt(text.encode()).decode()
                    stored_data[st.session_state.current_user] = stored_data.get(st.session_state.current_user, [])
                    stored_data[st.session_state.current_user].append(encrypted_text)

                    with open(DATA_FILE, "w") as f:
                        json.dump(stored_data, f)

                    st.success("✅ Your data has been encrypted and saved.")

elif choice == "Retrieve Data":
    if not st.session_state.current_user:
        st.warning("🔒 Please login first.")
    else:
        st.markdown('<div class="title">🔍 Retrieve Your Data</div>', unsafe_allow_html=True)

        if st.session_state.lockout_time and time.time() - st.session_state.lockout_time < LOCKOUT_DURATION:
            st.error("⏱️ You are locked out. Please wait before trying again.")
        else:
            entries = stored_data.get(st.session_state.current_user, [])
            if not entries:
                st.info("ℹ️ No encrypted data stored yet.")
            else:
                with st.form("decrypt_form"):
                    encrypted_text = st.selectbox("🔐 Select Encrypted Entry", entries)
                    passkey = st.text_input("🔑 Enter Your Passkey", type="password")
                    decrypt = st.form_submit_button("🔓 Decrypt")

                    if decrypt:
                        salt = base64.b64decode(users[st.session_state.current_user]["salt"])
                        key = generate_key(passkey, salt)
                        f = Fernet(key)
                        try:
                            decrypted = f.decrypt(encrypted_text.encode()).decode()
                            st.success(f"✅ Decrypted Data:\n\n📜 {decrypted}")
                            st.session_state.failed_attempts = 0
                        except:
                            st.session_state.failed_attempts += 1
                            attempts_left = 3 - st.session_state.failed_attempts
                            st.error(f"❌ Wrong passkey! Attempts left: {attempts_left}")

                            if st.session_state.failed_attempts >= 3:
                                st.session_state.lockout_time = time.time()
                                st.error("🔒 Too many Failed attempts! Please wait before trying again.")

elif choice == "Logout":
    st.session_state.current_user = None
    st.success("🚪 You have been logged out.")
