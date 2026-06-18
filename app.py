# app.py
import streamlit as st
from pathlib import Path
import json, time, base64
from hashlib import sha256
import pandas as pd
from model_interface import predict_from_bytes  # uses model_artifacts/
from collections import Counter

DATA_DIR = Path.cwd() / "qm_handler_data"
DATA_DIR.mkdir(exist_ok=True)
HISTORY_FILE = DATA_DIR / "history.json"
SAFE_FILE = DATA_DIR / "safe.json"
USERS_FILE = DATA_DIR / "users.json"

# load / init
def load_json(path, default):
    if path.exists():
        try:
            return json.loads(path.read_text())
        except:
            return default
    return default

history = load_json(HISTORY_FILE, [])
safe_list = load_json(SAFE_FILE, [])
users = load_json(USERS_FILE, {"admin": {"password": "admin123"}})

# auth helpers
def login_user(u,p):
    if u in users and users[u]["password"]==p:
        st.session_state["logged_in"]=True
        st.session_state["username"]=u
        return True
    return False

def logout():
    for k in ("logged_in","username"):
        if k in st.session_state: del st.session_state[k]

# small UI
st.set_page_config(page_title="Quantum Malware Handler", layout="wide")
if not st.session_state.get("logged_in", False):
    st.title("🔐 Login")
    uname = st.text_input("Username")
    pwd = st.text_input("Password", type="password")
    if st.button("Login"):
        if login_user(uname,pwd):
            st.experimental_rerun()
        else:
            st.error("Invalid credentials")
    st.write("Demo user: admin/admin123")
    st.stop()

# main page
st.sidebar.write(f"Signed in as **{st.session_state['username']}**")
if st.sidebar.button("Logout"):
    logout(); st.experimental_rerun()

st.title("⚛️ Quantum Malware Handler — UI")
st.markdown("Upload a binary to analyze with the QML model. *Research use only.*")

col1, col2 = st.columns([3,1])
with col1:
    uploaded = st.file_uploader("Upload binary", type=None)
    label = st.text_input("Label (optional)")
    analyze = st.button("Run QML Analysis")
with col2:
    st.metric("History entries", len(history))
    st.metric("Safe entries", len(safe_list))

if uploaded:
    b = uploaded.read()
    size = len(b)
    sha = sha256(b).hexdigest()
    st.write(f"Filename: {uploaded.name} — Size: {size} bytes — SHA256: `{sha}`")
    # quick metadata
    def entropy(bytestr):
        if not bytestr: return 0.0
        c=Counter(bytestr); L=len(bytestr)
        import math
        s=0
        for v in c.values():
            p=v/L; s-=p*math.log2(p)
        return s
    st.write(f"Entropy: {entropy(b):.4f}")

    if analyze:
        try:
            label_pred, score = predict_from_bytes(b, uploaded.name)
            entry = {
                "timestamp": time.time(),
                "human_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "label_given": label or uploaded.name,
                "filename": uploaded.name,
                "sha256": sha,
                "size": size,
                "predicted": label_pred,
                "confidence": float(score)
            }
            history.insert(0, entry)
            # keep history length manageable
            history[:] = history[:1000]
            (HISTORY_FILE).write_text(json.dumps(history, indent=2))
            if label_pred.lower().startswith("malware"):
                st.error(f"🚨 Predicted: {label_pred} (score {score:.3f})")
            else:
                st.success(f"🟢 Predicted: {label_pred} (score {score:.3f})")
            st.json(entry)
        except Exception as e:
            st.exception(e)

    st.write("---")
    if st.button("Add to Safe / Benign"):
        entry = {
            "timestamp": time.time(),
            "human_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "label": label or uploaded.name,
            "filename": uploaded.name,
            "sha256": sha,
            "size": size
        }
        if not any(x.get("sha256")==sha for x in safe_list):
            safe_list.insert(0, entry)
            SAFE_FILE.write_text(json.dumps(safe_list, indent=2))
            st.success("Added to Safe list")
        else:
            st.info("Already in safe list")

st.markdown("---")
st.header("History")
if history:
    df = pd.DataFrame(history)
    st.dataframe(df[["human_time","filename","predicted","confidence","sha256"]].head(200))
    if st.button("Export History CSV"):
        csv = df.to_csv(index=False)
        b64 = base64.b64encode(csv.encode()).decode()
        href = f'<a href="data:file/csv;base64,{b64}" download="history.csv">Download</a>'
        st.markdown(href, unsafe_allow_html=True)
else:
    st.info("No history yet.")
