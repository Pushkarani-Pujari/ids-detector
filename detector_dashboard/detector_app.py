import streamlit as st
import pandas as pd
import numpy as np
import joblib
import time
from datetime import datetime
import plotly.graph_objects as go
import requests

# ------------------- CONFIGURATION -------------------
# Replace with your actual GitHub raw CSV file URL (make sure it's PUBLIC)
RAW_GITHUB_CSV_URL = "https://raw.githubusercontent.com/Pushkarani-Pujari/ids-detector/main/detector_dashboard/attack_payload.csv"

MODEL_PATH = "models/random_forest_ids_model.pkl"
FEATURES_PATH = "models/rf_features.pkl"

# ------------------- PAGE SETTINGS -------------------
st.set_page_config(page_title="Detector Dashboard", layout="wide", page_icon="🛡️")
st.markdown("<h1 style='color:lightblue'>🛡️ Intrusion Detection System</h1>", unsafe_allow_html=True)
st.markdown("This dashboard continuously scans for incoming attacks from a GitHub file.")
st.markdown("---")

# ------------------- SIDEBAR REFRESH -------------------
refresh_interval_ms = st.sidebar.slider("🔄 Refresh interval (ms)", 500, 5000, 1000, step=100)
st.sidebar.info("The dashboard will auto-refresh based on this interval.")

# ------------------- LOAD MODEL -------------------
@st.cache_resource
def load_model_and_features():
    model = joblib.load(MODEL_PATH)
    features = joblib.load(FEATURES_PATH)
    return model, features

model, selected_features = load_model_and_features()

# ------------------- HELPER FUNCTIONS -------------------
def get_threat_score(severity):
    return {"High": 90, "Medium": 60, "Low": 30}.get(severity, 10)

def label_attack_type(label):
    label_clean = str(label).strip().lower()
    if label_clean == "benign":
        return "BENIGN"
    for atk in [
        "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris",
        "FTP-Patator", "Heartbleed", "Infiltration", "PortScan", "SSH-Patator",
        "Web Attack-Brute Force", "Web Attack-Sql Injection", "Web Attack-XSS", "BOT"
    ]:
        if atk.lower() in label_clean:
            return atk
    return "Other"

def fetch_remote_csv(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return pd.read_csv(pd.compat.StringIO(response.text))
        else:
            return None
    except Exception as e:
        return None

# ------------------- MAIN LOGIC -------------------
df_all = fetch_remote_csv(RAW_GITHUB_CSV_URL)

if df_all is None or df_all.empty:
    st.info("📭 No new attack records to detect.")
else:
    start = time.time()
    df = df_all.iloc[[0]]  # take only the first attack record

    # Ensure clean column names
    df.columns = [col.strip() for col in df.columns]
    df_detect = df.select_dtypes(include=[np.number])

    # Add missing features as zeros
    for col in selected_features:
        if col not in df_detect.columns:
            df_detect[col] = 0.0
    df_detect = df_detect[selected_features]
    df_detect.replace([np.inf, -np.inf], 0, inplace=True)
    df_detect.fillna(0.0, inplace=True)

    # Predict and enrich
    prediction = model.predict(df_detect)[0]
    df['Prediction'] = prediction
    df['Timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    df['Attack_Type'] = df['Label'].apply(label_attack_type)
    df['Severity'] = df['Attack_Type'].apply(
        lambda x: "High" if x in ["Heartbleed", "Infiltration", "DDoS", "BOT"]
        else "Medium" if x in ["PortScan", "FTP-Patator", "SSH-Patator"]
        else "Low" if x.startswith("Web Attack") or "DoS" in x
        else "None"
    )

    duration = time.time() - start

    # ------------------- METRICS DISPLAY -------------------
    st.success("✅ Attack Detected")
    col1, col2, col3 = st.columns(3)
    col1.metric("🚨 Detected", df['Attack_Type'].iloc[0])
    col2.metric("⏱️ Detection Time", f"{duration:.2f} seconds")
    col3.metric("🧭 Severity", df['Severity'].iloc[0])

    # ------------------- GAUGE CHART -------------------
    threat_score = get_threat_score(df['Severity'].iloc[0])
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=threat_score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Threat Score", 'font': {"size": 24}},
        delta={'reference': 50, 'increasing': {'color': "red"}, 'decreasing': {'color': "green"}},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': "darkred"},
            'steps': [
                {'range': [0, 30], 'color': "#2a9d8f"},
                {'range': [30, 60], 'color': "#f4a261"},
                {'range': [60, 90], 'color': "#e76f51"},
                {'range': [90, 100], 'color': "#e63946"},
            ],
            'threshold': {
                'line': {'color': "black", 'width': 4},
                'thickness': 0.75,
                'value': threat_score
            }
        }
    ))
    st.plotly_chart(fig_gauge, use_container_width=True)

    with st.expander("🔍 View Full Attack Details"):
        st.dataframe(df, use_container_width=True)

# ------------------- AUTO-REFRESH -------------------
time.sleep(refresh_interval_ms / 1000)
st.experimental_rerun()
