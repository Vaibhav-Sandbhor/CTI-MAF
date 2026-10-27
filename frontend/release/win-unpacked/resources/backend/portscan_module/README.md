🔐 AI Port Scan Risk Intelligence Engine v2.0

🚀 Production-Ready AI-Powered Network Risk Assessment Platform
🧠 Explainable Machine Learning + FastAPI Backend + Drift Monitoring

🌟 Overview

The AI Port Scan Risk Intelligence Engine transforms raw Nmap scan data into actionable security intelligence using advanced machine learning, hybrid risk scoring, and explainable AI.

Unlike traditional scanners that only list open ports, this system:

Predicts host-level risk using ML (XGBoost + Calibration)

Explains why a system is risky using SHAP

Combines ML predictions with port intelligence database

Detects data drift in real time

Supports automated retraining pipelines

Provides production-ready FastAPI backend

This is not just a script — this is a structured, deployable security intelligence engine.

🏗 Architecture (v2.0)
                Nmap XML Scan
                      ↓
         Feature Engineering (9 Features)
                      ↓
        XGBoost Model + Probability Calibration
                      ↓
        SHAP Explainability + Hybrid Risk Logic
                      ↓
       ┌──────────────┼──────────────┐
       ↓              ↓              ↓
   Dashboard       Full Report       Admin
  (Frontend)      (Technical)     (Backend Only)
🧠 Machine Learning Stack
🔹 Model

XGBoost Classifier

Hyperparameter tuned

Class-weight balanced

5-fold cross validation

🔹 Probability Calibration

CalibratedClassifierCV

Reliable confidence scoring

Reduced Brier score

🔹 Explainability

SHAP TreeExplainer

Feature contribution breakdown

Risk impact direction

🔹 Hybrid Scoring

ML prediction

Port intelligence override logic

Severity amplification rules

📊 Feature Engineering (9 Core Features)
Feature	Purpose
open_ports_count	Attack surface size
service_count	Service diversity
avg_cvss	Vulnerability severity
uncommon_ports	Suspicious port usage
os_flag	OS risk profiling
port_severity_score	Aggregated port risk
high_risk_port_count	Critical exposure
service_entropy	Service randomness
cvss_variance	Vulnerability spread
⚙️ FastAPI Backend (Production Ready)
API Endpoints
Method	Endpoint	Purpose
POST	/scan	Analyze Nmap XML (Dashboard view)
GET	/report/{scan_id}	Detailed technical report
GET	/admin/status	Backend metrics (API key required)
GET	/health	Health check
GET	/docs	Swagger UI
🚀 Quick Start
1️⃣ Install Dependencies
pip install -r requirements.txt
pip install -r requirements_api.txt
2️⃣ Start API Server
python api.py

API runs on:

http://localhost:8000

Swagger UI:

http://localhost:8000/docs
3️⃣ Analyze a Scan
curl -X POST "http://localhost:8000/scan" \
  -F "xml_file=@nmap_scans/sample_scan.xml"
🔎 What Makes This Different?

✔ Not just port listing
✔ ML-based risk classification
✔ Explainable AI decisions
✔ Hybrid port + ML consensus
✔ Drift detection monitoring
✔ Auto-retraining capability
✔ Clean API separation
✔ Production deployment ready

📈 Model Performance (Test Set)

Accuracy: ~84–90% (depending on dataset realism)

Weighted F1: ~0.84+

Calibrated confidence reliability

Lower Brier Score after calibration

🛡 Security Intelligence Capabilities

Detects high-risk exposure (SMB, RDP, DB ports)

CVE mapping with real-world examples

MITRE ATT&CK tactic mapping

Risk justification reasoning

Host-level security score (0–100)

🔄 Drift Detection & Retraining

Monitors distribution shift in:

open_ports_count

avg_cvss

service_count

Uses KS-test + statistical drift %

Auto-retraining trigger logic

Logs operational metrics

📦 Project Structure
AI_PortScan_Analyzer/
│
├── api.py
├── scripts/
│   ├── predict_risk.py
│   ├── train_model.py
│   ├── drift_detection.py
│   ├── retrain_pipeline.py
│
├── data/
│   ├── port_knowledge.py
│   ├── generate_dataset.py
│
├── model/
├── logs/
├── requirements.txt
├── requirements_api.txt
└── README.md
🏷 Versioning
v1.0

Console-based ML risk predictor

v2.0

FastAPI backend

XGBoost integration

Probability calibration

SHAP explainability

Hybrid scoring engine

Drift monitoring

Auto-retraining pipeline

🎯 Use Cases

SOC dashboards

Vulnerability assessment automation

Security analytics research

AI-driven cybersecurity education

Resume / portfolio demonstration

🔐 Security Design

No model internals exposed to dashboard

Admin endpoint protected via API key

No raw scan data persisted

Temporary files cleaned automatically

Structured error handling

⭐ Why This Project Matters

This project demonstrates:

Applied Machine Learning

Explainable AI

Cybersecurity domain knowledge

Backend engineering

API architecture design

Model monitoring & retraining strategy

This is not a toy script — it is a structured AI-driven security platform.

🏁 Status

✅ Production-Structured
✅ Version 2.0
✅ Explainable AI Enabled
✅ Drift Monitoring Integrated