import streamlit as st
import pandas as pd
import random
import requests
import base64

# GitHub settings (use Streamlit secrets for security)
GITHUB_TOKEN = st.secrets["GITHUB_TOKEN"]
REPO_OWNER = "Pushkarani-Pujari"
REPO_NAME = "ids-detector"
FILE_PATH_IN_REPO = "detector_dashboard/attack_payload.csv"

GITHUB_API_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH_IN_REPO}"

# Page setup
st.set_page_config(layout="wide", page_title="Attacker Dashboard", page_icon="💣")
st.title("💣 Attacker")
st.markdown("---")
st.markdown("Simulate an attack by uploading a payload and launching one row at a time.")

uploaded_file = st.file_uploader("📤 Upload your attack payload (.csv or .json)", type=["csv", "json"])
df_uploaded = None

if uploaded_file is not None:
    try:
        if uploaded_file.name.endswith(".csv"):
            df_uploaded = pd.read_csv(uploaded_file)
        else:
            df_uploaded = pd.read_json(uploaded_file)
        st.success("✅ File uploaded")
    except Exception as e:
        st.error(f"❌ Failed to read file: {e}")

def push_to_github(file_content: str, commit_msg="Update attack payload"):
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    # Get SHA of the existing file if it exists
    get_resp = requests.get(GITHUB_API_URL, headers=headers)
    sha = get_resp.json().get("sha") if get_resp.status_code == 200 else None

    encoded_content = base64.b64encode(file_content.encode()).decode()

    data = {
        "message": commit_msg,
        "content": encoded_content,
        "branch": "main"
    }
    if sha:
        data["sha"] = sha

    response = requests.put(GITHUB_API_URL, json=data, headers=headers)
    return response.status_code == 200 or response.status_code == 201

if df_uploaded is not None:
    if st.button("🚀 Launch Attack"):
        try:
            row = df_uploaded.sample(1)
            csv_str = row.to_csv(index=False)
            success = push_to_github(csv_str, "🚨 Launch attack payload")

            if success:
                st.success("🎯 Attack Launched and Uploaded to GitHub!")
            else:
                st.error("❌ Failed to push to GitHub.")
        except Exception as e:
            st.error(f"❌ Error launching attack: {e}")
