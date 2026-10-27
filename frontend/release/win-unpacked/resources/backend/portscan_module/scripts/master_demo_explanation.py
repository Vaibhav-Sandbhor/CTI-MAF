import os
import subprocess
import joblib
import pandas as pd
from feature_engineering import parse_nmap, calculate_features

# -------------------------------
# CONFIG
# -------------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
NMAP_OUTPUT_DIR = os.path.join(PROJECT_ROOT, "nmap_scans")
XML_FILE = os.path.join(NMAP_OUTPUT_DIR, "scan_master.xml")
MODEL_FILE = os.path.join(PROJECT_ROOT, "model", "rf_model.pkl")

# -------------------------------
# STEP 1: RUN NMAP SCAN
# -------------------------------
print("🔹 Running Nmap scan on localhost...")
os.makedirs(NMAP_OUTPUT_DIR, exist_ok=True)

try:
    subprocess.run([
        "nmap", "-sS", "-sV", "-T4", "localhost",
        "-oX", XML_FILE
    ], check=True)
    print(f"✅ Nmap scan complete. Output saved: {XML_FILE}\n")
except Exception as e:
    print("❌ Nmap scan failed. Make sure Nmap is installed and in PATH.")
    print("Error:", e)
    exit()

# -------------------------------
# STEP 2: PARSE XML AND EXTRACT FEATURES
# -------------------------------
hosts = parse_nmap(XML_FILE)
all_features = []
ips = []
host_services = []

for host in hosts:
    features = calculate_features(host)
    all_features.append([
        features["open_ports_count"],
        features["service_count"],
        features["avg_cvss"],
        features["uncommon_ports"],
        features["os_flag"]
    ])
    ips.append(host["ip"])
    host_services.append(host["services"])

X_new = pd.DataFrame(all_features, columns=[
    "open_ports_count",
    "service_count",
    "avg_cvss",
    "uncommon_ports",
    "os_flag"
])

# -------------------------------
# STEP 3: LOAD MODEL AND PREDICT RISK
# -------------------------------
if not os.path.exists(MODEL_FILE):
    print("❌ Trained model not found. Run train_model.py first.")
    exit()

model = joblib.load(MODEL_FILE)
predictions = model.predict(X_new)

# -------------------------------
# STEP 4: PRINT DETAILED REPORT
# -------------------------------
print("\n=== MASTER RISK PREDICTION REPORT (WITH EXPLANATION) ===\n")

for ip, features, services, risk in zip(ips, all_features, host_services, predictions):
    open_ports_count, service_count, avg_cvss, uncommon_ports, os_flag = features
    os_name = "Windows" if os_flag == 1 else "Linux/Other"

    print(f"Host: {ip}")
    print(f" - OS: {os_name}")
    print(f" - Open Ports Count: {open_ports_count}")
    print(f" - Services Detected: {services}")
    print(f" - Average CVSS: {avg_cvss}")
    print(f" - Uncommon Ports Flag: {'Yes' if uncommon_ports==1 else 'No'}")
    print(f" - Predicted Risk: {risk}")

    # Explain why
    explanation = []
    if avg_cvss >= 7:
        explanation.append("Average CVSS is high (≥7)")
    if uncommon_ports == 1:
        explanation.append("Uncommon ports detected")
    if os_flag == 1:
        explanation.append("OS is Windows (more vulnerable services)")

    print(f" - Explanation: {', '.join(explanation) if explanation else 'No specific risk factors'}")
    print("-"*60)

print("\n✅ Master demo with explanations complete.")
