# attacker_app.py
import streamlit as st
import pandas as pd
import random
import firebase_admin
from firebase_admin import credentials, db

# Firebase setup
if not firebase_admin._apps:
    cred = credentials.Certificate(st.secrets["firebase_key"])
    firebase_admin.initialize_app(cred, {
        "databaseURL": st.secrets["firebase_url"]
    })

# Streamlit UI
st.set_page_config(layout="wide", page_title="Attacker Dashboard", page_icon="💣")
st.title("💣 Attacker")
st.markdown("---")
st.markdown("Upload your attack dataset")

# Upload data
uploaded_file = st.file_uploader("📤 Upload your attack payload (.csv or .json)", type=["csv", "json"])
df_uploaded = None

if uploaded_file:
    try:
        if uploaded_file.name.endswith(".csv"):
            df_uploaded = pd.read_csv(uploaded_file)
        else:
            df_uploaded = pd.read_json(uploaded_file)
        st.success("✅ File uploaded successfully")
    except Exception as e:
        st.error(f"❌ Failed to load file: {e}")

# Send row to Firebase
def push_to_firebase(row_dict):
    ref = db.reference("attack_payload")
    ref.set(row_dict)

if df_uploaded is not None:
    if st.button("🚀 Launch Attack"):
        row = df_uploaded.sample(1).reset_index(drop=True)
        row_dict = row.to_dict(orient="records")[0]
        push_to_firebase(row_dict)
        st.success("🎯 Attack pushed to Firebase")
