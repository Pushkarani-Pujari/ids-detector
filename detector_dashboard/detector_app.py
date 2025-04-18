import streamlit as st
import pandas as pd
import numpy as np
import joblib
import time
from datetime import datetime
import plotly.graph_objects as go
import requests
from io import StringIO
from streamlit_autorefresh import st_autorefresh

# GitHub CSV URL
CSV_URL_RAW = "https://raw.githubusercontent.com/Pushkarani-Pujari/ids-detector/main/detector_dashboard/attack_payload.csv"
CSV_URL_API = "https://api.github.com/repos/Pushkarani-Pujari/ids-detector/contents/detector_dashboard/attack_payload.csv"

# Streamlit page setup
st.set_page_config(layout="wide", page_title="Detector Dashboard", page_icon="🛡️")
st.markdown("<h1 style='color:lightblue'>🛡️ Intrusion Detection System</h1>", unsafe_allow_html=True)
st.markdown("---")

# Load model and selected features
model = joblib.load("models/random_forest_ids_model.pkl")
selected_features = joblib.load("models/rf_features.pkl")

# Refresh control
refresh_interval_ms = st.sidebar.slider("🔄 Refresh interval (ms)", 500, 5000, 1500, step=100)
st.sidebar.info("Auto-refresh is active")
st_autorefresh(interval=refresh_interval_ms, key="refresh")

# Helper functions
def get_threat_score(severity):
    return {"High": 90, "Medium": 60, "Low": 30}.get(severity, 10)

def label_attack_type(label):
    label = str(label).strip().lower()
    if label == "benign":
        return "BENIGN"
    known_attacks = [
        "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris",
        "FTP-Patator", "Heartbleed", "Infiltration", "PortScan", "SSH-Patator",
        "Web Attack-Brute Force", "Web Attack-Sql Injection", "Web Attack-XSS", "BOT"
    ]
    for atk in known_attacks:
        if atk.lower() in label:
            return atk
    return "Other"

def clear_github_file():
    headers = {
        "Authorization": f"token {st.secrets['GITHUB_TOKEN']}",
        "Accept": "application/vnd.github.v3+json"
    }
    get_resp = requests.get(CSV_URL_API, headers=headers)
    if get_resp.status_code == 200:
        sha = get_resp.json()["sha"]
        payload = {
            "message": "🧹 Clear detected attack row",
            "content": "",
            "sha": sha,
            "branch": "main"
        }
        response = requests.put(CSV_URL_API, json=payload, headers=headers)
        return response.status_code in [200, 201]
    return False

# Process attack payload
try:
    response = requests.get(CSV_URL_RAW)
    if response.status_code == 200:
        if not response.text.strip():
            with st.spinner("⏳ Waiting for attack..."):
                st.info("📭 No new attack launched yet")
        else:
            df = pd.read_csv(StringIO(response.text))
            df = df.iloc[[0]]  # Only process first row
            df.columns = [col.strip() for col in df.columns]

            # Prepare input for prediction
            df_detect = df.select_dtypes(include=[np.number])
            for col in selected_features:
                if col not in df_detect.columns:
                    df_detect[col] = 0.0
            df_detect = df_detect[selected_features]
            df_detect.replace([np.inf, -np.inf], 0, inplace=True)
            df_detect.fillna(0.0, inplace=True)

            # Predict
            start = time.time()
            prediction = model.predict(df_detect)[0]
            duration = time.time() - start

            df['Prediction'] = prediction
            df['Timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            df['Attack_Type'] = df['Label'].apply(label_attack_type)
            df['Severity'] = df['Attack_Type'].apply(
                lambda x: "High" if x in ["Heartbleed", "Infiltration", "DDoS", "BOT"]
                else "Medium" if x in ["PortScan", "FTP-Patator", "SSH-Patator"]
                else "Low" if x.startswith("Web Attack") or "dos" in x.lower()
                else "None"
            )

            # Display detection
            st.success("✅ Attack Detected")
            col1, col2, col3 = st.columns(3)
            col1.metric("🚨 Type", df['Attack_Type'].iloc[0])
            col2.metric("⏱️ Time", f"{duration:.2f} sec")
            col3.metric("🧭 Severity", df['Severity'].iloc[0])

            threat_score = get_threat_score(df['Severity'].iloc[0])
            fig = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=threat_score,
                title={"text": "Threat Score"},
                delta={"reference": 50},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": "darkred"},
                    "steps": [
                        {"range": [0, 30], "color": "#2a9d8f"},
                        {"range": [30, 60], "color": "#f4a261"},
                        {"range": [60, 90], "color": "#e76f51"},
                        {"range": [90, 100], "color": "#e63946"},
                    ]
                }
            ))
            st.plotly_chart(fig, use_container_width=True)

            with st.expander("🔍 Full Attack Details"):
                st.dataframe(df)

            # Clear the file to simulate one-by-one real-time detection
            cleared = clear_github_file()
            if cleared:
                st.success("🧹 Cleared detected attack from payload")
            else:
                st.warning("⚠️ Failed to clear GitHub file after detection")

            # Optional: Give GitHub a moment to sync
            time.sleep(1)

    else:
        st.warning(f"⚠️ GitHub returned {response.status_code} when fetching file.")

except Exception as e:
    st.error(f"❌ Error: {e}")
