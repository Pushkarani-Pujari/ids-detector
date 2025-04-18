

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import time
from datetime import datetime
import plotly.graph_objects as go
import os

# Shared path between attacker and detector
SHARED_PATH = "../shared_data/attack_payload.csv"

# Page config
st.set_page_config(layout="wide", page_title="Detector Dashboard", page_icon="🛡️")
st.markdown("<h1 style='color:lightblue'>🛡️ Intrusion Detection System</h1>", unsafe_allow_html=True)
st.markdown("This dashboard continuously scans for incoming attacks.")
st.markdown("---")

# Load model and features
model = joblib.load("../models/random_forest_ids_model.pkl")
selected_features = joblib.load("../models/rf_features.pkl")

def get_threat_score(severity):
    if severity == "High":
        return 90
    elif severity == "Medium":
        return 60
    elif severity == "Low":
        return 30
    else:
        return 10

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

# Set refresh rate (ms)
refresh_interval_ms = st.sidebar.slider("🔄 Refresh interval (ms)", 500, 5000, 1000, step=100)
st.sidebar.info("The dashboard will auto-refresh based on this interval.")

# Main Logic
if os.path.exists(SHARED_PATH):
    try:
        df_all = pd.read_csv(SHARED_PATH)

        if df_all.empty:
            st.info("📭 No new attack records to detect.")
            os.remove(SHARED_PATH)
        else:
            start = time.time()
            df = df_all.iloc[[0]]
            os.remove(SHARED_PATH)

            df.columns = [col.strip() for col in df.columns]
            df_detect = df.select_dtypes(include=[np.number])

            for col in selected_features:
                if col not in df_detect.columns:
                    df_detect[col] = 0.0
            df_detect = df_detect[selected_features]
            df_detect.replace([np.inf, -np.inf], 0, inplace=True)
            df_detect.fillna(0.0, inplace=True)

            predictions = model.predict(df_detect)
            df['Prediction'] = predictions
            df['Timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            df['Attack_Type'] = df['Label'].apply(label_attack_type)
            df['Severity'] = df['Attack_Type'].apply(
                lambda x: "High" if x in ["Heartbleed", "Infiltration", "DDoS", "BOT"]
                else "Medium" if x in ["PortScan", "FTP-Patator", "SSH-Patator"]
                else "Low" if x.startswith("Web Attack") or "DoS" in x
                else "None"
            )

            duration = time.time() - start

            st.success("✅ Attack Detected")
            col1, col2, col3 = st.columns(3)
            col1.metric("🚨 Detected", df['Attack_Type'].iloc[0])
            col2.metric("⏱️ Detection Time", f"{duration:.2f} seconds")
            col3.metric("🧭 Severity", df['Severity'].iloc[0])

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

    except Exception as e:
        st.error(f"❌ Detection failed: {e}")
else:
    st.warning("⚠️ No attack detected...")

# Auto-refresh after sleep
time.sleep(refresh_interval_ms / 1000)
st.experimental_rerun()

