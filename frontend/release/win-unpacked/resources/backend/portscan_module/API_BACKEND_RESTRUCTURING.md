# 🚀 AI PORT SCAN RISK INTELLIGENCE ENGINE - BACKEND RESTRUCTURING

**Version 2.0.0 - Production-Ready with Clean API Separation**

---

## 📋 QUICK START

### Installation Dependencies

```bash
# Install FastAPI and API dependencies
pip install -r requirements_api.txt

# Or manually:
pip install fastapi uvicorn python-multipart pydantic
```

### Start the API Server

```bash
# From project root
python api.py

# Or with uvicorn directly
uvicorn api:app --reload --host 0.0.0.0 --port 8000
```

API will be available at: `http://localhost:8000`

---

## 🏗️ ARCHITECTURE OVERVIEW

### Three Clean Views - Complete Separation of Concerns

```
┌─────────────────────────────────────────────────────┐
│         UNIFIED ANALYSIS ENGINE                      │
│    (scripts/predict_risk.py - analyze_scan())       │
├─────────────────────────────────────────────────────┤
│ ✓ Keep all ML logic unchanged                       │
│ ✓ No print statements in logic                       │
│ ✓ Return structured JSON dicts                       │
│ ✓ SHAP calculated once, used by multiple views      │
└─────────────────────────────────────────────────────┘
                           │
                           ↓
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    Dashboard View    Report View        Admin View
    (Frontend Safe)   (Technical Users) (Backend Ops)
         │                 │                 │
    No SHAP         Full SHAP            Model Version
    No Drift        Port Details         Training Info
    No Internals    Feature Analysis     Drift Status
         │                 │                 │
    GET /scan       GET /report/{id}   GET /admin/status
    (Dashboard)     (Report)           (Admin-only)
```

---

## 📡 API ENDPOINTS

### 1️⃣ **POST /scan** - Dashboard View (Frontend Safe)

**Purpose:** Minimal, user-friendly risk summary for dashboards

**Request:**
```bash
curl -X POST "http://localhost:8000/scan" \
  -F "xml_file=@nmap_scans/scan_master.xml" \
  -F "return_report=false"
```

**Response (Dashboard Only):**
```json
{
  "scan_id": "a1b2c3d4",
  "timestamp": "2026-02-24T15:30:45.123456",
  "status": "success",
  "message": "Scanned 1 host(s)",
  "dashboard": [
    {
      "host": "127.0.0.1",
      "final_risk": "Critical",
      "risk_score": 92.5,
      "confidence": 95.0,
      "security_score": 45,
      "risk_tier": "Critical",
      "open_ports": [135, 445, 902, 912],
      "critical_port_count": 1,
      "high_port_count": 1,
      "total_ports": 4,
      "active_services": ["msrpc", "microsoft-ds", "vmware-auth"],
      "operating_system": "Windows 10",
      "recommendations": [
        "CRITICAL: Patch/disable 1 critical port(s) immediately",
        "Close unnecessary ports (currently 4 open)",
        "Address high CVSS vulnerabilities (avg: 7.09)"
      ]
    }
  ]
}
```

**Key Features:**
- ✅ No SHAP values (not needed for frontend)
- ✅ No model internals/drift data
- ✅ Actionable recommendations only
- ✅ Suitable for executive dashboards
- ✅ Small payload (fast loading)

---

### 2️⃣ **GET /report/{scan_id}** - Detailed Report (Technical Users)

**Purpose:** Full technical analysis with SHAP explainability

**Request:**
```bash
curl -X GET "http://localhost:8000/report/a1b2c3d4"
```

**Response (Full Report with SHAP):**
```json
{
  "scan_id": "a1b2c3d4",
  "status": "success",
  "report": [
    {
      "host": "127.0.0.1",
      "operating_system": "Windows 10",
      "active_services": ["msrpc", "microsoft-ds", "vmware-auth"],
      "ml_prediction": {
        "predicted_risk": "Critical",
        "confidence": 95.0,
        "algorithm": "XGBoost (with probability calibration)"
      },
      "hybrid_logic": {
        "ml_risk": "Critical",
        "port_intelligence_risk": "Critical",
        "escalation_applied": false,
        "final_risk": "Critical",
        "final_risk_score": 92.5
      },
      "port_analysis": [
        {
          "port": 445,
          "service": "microsoft-ds",
          "risk_level": "Critical",
          "cvss_score": 9.8,
          "cve_examples": ["CVE-2017-0144"],
          "exploitability": "High",
          "mitigation_priority": "Critical"
        },
        {
          "port": 135,
          "service": "msrpc",
          "risk_level": "High",
          "cvss_score": 7.8,
          "cve_examples": ["CVE-2017-0143"],
          "exploitability": "High",
          "mitigation_priority": "High"
        }
      ],
      "feature_analysis": {
        "features": {
          "open_ports_count": 4.0,
          "service_count": 3.0,
          "avg_cvss": 7.09,
          "uncommon_ports": 2.0,
          "os_flag": 1.0,
          "port_severity_score": 50.0,
          "high_risk_port_count": 1.0,
          "service_entropy": 0.95,
          "cvss_variance": 1.13
        },
        "human_explanations": [
          "High vulnerability score (CVSS 7.09), indicating severe security weaknesses",
          "Non-standard ports open - may indicate hidden or misconfigured services",
          "Windows OS detected - primary ransomware/malware target"
        ]
      },
      "explainability": {
        "top_features": [
          {
            "feature": "port_severity_score",
            "shap_value": -1.31,
            "impact": "decreases_risk"
          },
          {
            "feature": "service_count",
            "shap_value": -1.07,
            "impact": "decreases_risk"
          },
          {
            "feature": "open_ports_count",
            "shap_value": -0.84,
            "impact": "decreases_risk"
          },
          {
            "feature": "uncommon_ports",
            "shap_value": 0.43,
            "impact": "increases_risk"
          },
          {
            "feature": "avg_cvss",
            "shap_value": 0.13,
            "impact": "increases_risk"
          }
        ],
        "all_features": [...]
      },
      "security_score": {
        "security_score": 45,
        "risk_tier": "Critical",
        "ports_score": 10,
        "cvss_score": 0,
        "critical_score": 15,
        "os_score": 8,
        "service_score": 8,
        "improvements": [
          "CRITICAL: Patch/disable 1 critical port(s) immediately",
          "Close unnecessary ports (currently 4 open)",
          "Address high CVSS vulnerabilities (avg: 7.09)"
        ]
      },
      "justification": "Final risk level Critical assigned based on ML prediction (Critical, 95.0% confidence), port intelligence database analysis, critical ports detected (1), and CVSS average (7.09). ML prediction confirmed by port analysis."
    }
  ]
}
```

**Key Features:**
- ✅ Full SHAP feature importance (all 9 features)
- ✅ Port-by-port vulnerability details
- ✅ Detailed justification for risk assignment
- ✅ ML algorithm details
- ✅ Suitable for security analysts/SOC teams
- ✅ For pattern matching and anomaly detection

---

### 3️⃣ **GET /admin/status** - Admin Metrics (Backend Only)

**Purpose:** Backend operational metrics (NOT for frontend!)

**Request:**
```bash
curl -X GET "http://localhost:8000/admin/status?api_key=admin-secret-key-change-me"
```

**Response (Backend Metrics Only):**
```json
{
  "model_metadata": {
    "model_type": "XGBoost",
    "model_file": "model_20260224_xgboost.pkl",
    "calibration_enabled": true,
    "feature_count": 9,
    "feature_names": [
      "open_ports_count",
      "service_count",
      "avg_cvss",
      "uncommon_ports",
      "os_flag",
      "port_severity_score",
      "high_risk_port_count",
      "service_entropy",
      "cvss_variance"
    ]
  },
  "training_info": {
    "model_version": "1.0",
    "last_retrain_date": "2026-02-24",
    "training_samples": 1200,
    "model_classes": ["Low", "Medium", "High", "Critical"]
  },
  "operational_metrics": {
    "new_samples_processed": 1,
    "timestamp": "2026-02-24T15:30:45.123456",
    "drift_status": "Not checked (run drift_detection.py separately)",
    "log_file": "data/new_scan_logs.csv"
  }
}
```

**Security Note:**
- ⚠️  Requires admin API key (check `ADMIN_API_KEY` environment variable)
- ⚠️  Never expose in frontend
- ⚠️  Backend/DevOps use only

---

## 🔄 WORKFLOW EXAMPLES

### Example 1: Frontend Dashboard Integration

```python
# Frontend would call:
POST /scan  →  Returns minimal dashboard view
                (no SHAP, no internals, fast loading)

# Display:
├─ Host IP: 127.0.0.1
├─ Risk Level: 🔴 Critical
├─ Risk Score: 92.5%
├─ Security Score: 45/100
├─ Open Ports: 135, 445, 902, 912
└─ Top Recommendations: [
    "CRITICAL: Patch/disable 1 critical port(s)",
    "Close unnecessary ports (currently 4 open)",
    "Address high CVSS vulnerabilities..."
  ]
```

### Example 2: Security Team Analysis

```python
# Security analyst would call:
POST /scan (with return_report=true)  →  Returns both dashboard + report
            OR
GET /report/{scan_id}  →  Returns full technical report

# Analyze:
├─ SHAP feature importance
├─ ML algorithm details
├─ Port vulnerability breakdown
├─ Feature impact (increases/decreases risk)
└─ Justification for risk assignment
```

### Example 3: DevOps/Backend Monitoring

```python
# DevOps team would call:
GET /admin/status?api_key=***

# Monitor:
├─ Model version
├─ Training date
├─ Calibration status
├─ New samples processed
├─ Drift status
└─ Log file location
```

---

## 🎯 DESIGN PRINCIPLES

### 1. **Backend ML Logic Untouched**
```python
# ALL existing ML logic preserved in scripts/predict_risk.py
├─ Feature engineering (calculate_features)
├─ XGBoost model with CalibratedClassifierCV
├─ SHAP explainability (TreeExplainer)
├─ Hybrid port-based risk scoring
└─ Host security score calculation
```

### 2. **Modular Organization**

**scripts/predict_risk.py** (Backend Engine)
- `analyze_scan(xml_path)` - Main function returning {dashboard, report, admin}
- No print statements (only return dicts)
- All ML logic intact

**api.py** (Frontend/API Layer)
- Three endpoints with different security levels
- Dashboard: minimal, frontend-safe
- Report: technical, includes SHAP
- Admin: backend-only, requires auth

**scripts/drift_detection.py** (Separate)
- Unchanged - runs independently
- NOT triggered during normal scans
- Generates drift alerts for retraining

**scripts/retrain_pipeline.py** (Separate)
- Unchanged - runs independently
- NOT triggered during normal scans
- Manual/scheduled retraining only

### 3. **Clean Separation**

```
What's Hidden from Frontend:
├─ SHAP values (report only)
├─ Drift detection status (admin only)
├─ Model internals (admin only)
├─ Training date (admin only)
└─ Calibration details (admin only)

What's Always Available:
├─ Final risk level
├─ Confidence score
├─ Security score
├─ Recommendations
├─ Actionable guidance
└─ Port details (basic)
```

---

## 📊 RESPONSE DATA FLOW

### Dashboard View (POST /scan)
```
User/Frontend
     ↓
  POST /scan
     ↓
analyze_scan() generates:
  ├─ dashboard: [minimal}
  ├─ report: {full}
  └─ admin: {backend}
     ↓
API returns dashboard only
     ↓
Frontend display
```

### Report View (GET /report/{scan_id})
```
Security Analyst
     ↓
GET /report/{scan_id}
     ↓
Returns cached report + SHAP
     ↓
Full technical analysis
```

### Admin View (GET /admin/status)
```
DevOps/Backend
     ↓
GET /admin/status?api_key=***
     ↓
Returns admin metrics
     ↓
Monitor model and processing
```

---

## 🔐 SECURITY CONSIDERATIONS

### Frontend Safe Views
- ✅ No sensitive model internals exposed
- ✅ No drift/retraining signals
- ✅ No admin information
- ✅ CORS enabled (configure in production)
- ✅ Suitable for public-facing dashboards

### Technical Views
- ✅ SHAP values included for explainability
- ✅ Port vulnerability details included
- ✅ Suitable for internal security teams
- ✅ No admin/backend info exposed

### Admin Views
- ⚠️  Requires API authentication
- ⚠️  Backend-only information
- ⚠️  Never expose to frontend
- ⚠️  Set ADMIN_API_KEY environment variable

```bash
# Set admin API key
export ADMIN_API_KEY="your-secure-key"
```

---

## 🚀 DEPLOYMENT GUIDE

### Development
```bash
python api.py
# Runs on http://localhost:8000
```

### Production (using gunicorn)
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 api:app
```

### Production (using systemd)
```ini
[Unit]
Description=AI Port Scan Risk Intelligence Engine
After=network.target

[Service]
Type=notify
User=www-data
WorkingDirectory=/path/to/project
Environment=ADMIN_API_KEY=your-secure-key
ExecStart=/usr/bin/gunicorn -w 4 -b 0.0.0.0:8000 api:app
Restart=always

[Install]
WantedBy=multi-user.target
```

### Docker (Optional)
```dockerfile
FROM python:3.10
WORKDIR /app
COPY requirements.txt requirements_api.txt ./
RUN pip install -r requirements.txt -r requirements_api.txt
COPY . .
ENV ADMIN_API_KEY=your-secure-key
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## 🧪 TESTING

### Test Dashboard Endpoint
```bash
curl -X POST "http://localhost:8000/scan" \
  -F "xml_file=@nmap_scans/scan_master.xml" | jq .
```

### Test Report Endpoint
```bash
# First get scan_id from POST /scan response
SCAN_ID="a1b2c3d4"
curl -X GET "http://localhost:8000/report/$SCAN_ID" | jq .
```

### Test Admin Endpoint
```bash
curl -X GET "http://localhost:8000/admin/status?api_key=admin-secret-key-change-me" | jq .
```

### List All Scans
```bash
curl -X GET "http://localhost:8000/scans" | jq .
```

### Get Scan Summary
```bash
SCAN_ID="a1b2c3d4"
curl -X GET "http://localhost:8000/scans/$SCAN_ID/summary" | jq .
```

---

## 📚 INTERACTIVE API DOCUMENTATION

Once server is running:
- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc
- **OpenAPI JSON:** http://localhost:8000/openapi.json

---

## ✅ VERIFICATION CHECKLIST

- [x] ML logic untouched in scripts/predict_risk.py
- [x] No print statements in logic functions (only dict returns)
- [x] Three clean views: dashboard, report, admin
- [x] Dashboard excludes SHAP/drift/internals
- [x] Report includes full SHAP explainability
- [x] Admin requires authentication
- [x] CORS configured for frontend integration
- [x] Drift detection script separate (not in API flow)
- [x] Retraining script separate (not in API flow)
- [x] All ML algorithms preserved
- [x] Production-ready error handling
- [x] API documentation auto-generated

---

## 📝 MIGRATION NOTES

### What Changed
- ✅ New: `api.py` with FastAPI backend
- ✅ Modified: `scripts/predict_risk.py` - refactored to `analyze_scan()` function
- ✅ Added: `requirements_api.txt` for API dependencies
- ✅ NEW: Three separate views (dashboard, report, admin)
- ✅ NEW: Structured JSON returns (no print statements)

### What's the Same
- ✅ All ML algorithms
- ✅ SHAP explainability
- ✅ Port intelligence database
- ✅ Feature engineering
- ✅ Drift detection script (separate)
- ✅ Retraining pipeline (separate)
- ✅ Model training logic

### Backward Compatibility
```python
# Old code (console):
python scripts/predict_risk.py

# Still works! Returns console summary, then exits.
# New: Use via API:
POST /scan → Get structured JSON dashboard
GET /report/{id} → Get technical report
```

---

## 🎯 NEXT STEPS

1. **Install FastAPI dependencies:**
   ```bash
   pip install -r requirements_api.txt
   ```

2. **Start API server:**
   ```bash
   python api.py
   ```

3. **Test endpoints:**
   ```bash
   curl -X POST "http://localhost:8000/scan" -F "xml_file=@nmap_scans/scan_master.xml"
   ```

4. **Integrate with frontend:**
   - Dashboard calls: `POST /scan`
   - Security team calls: `GET /report/{scan_id}`
   - Backend monitoring: `GET /admin/status?api_key=***`

5. **Configure for production:**
   - Change `ADMIN_API_KEY`
   - Set CORS origins
   - Use gunicorn/systemd
   - Enable HTTPS

---

**Version:** 2.0.0  
**Date:** 2026-02-24  
**Status:** Production-Ready  
**ML Logic:** Preserved ✅  
**API Structure:** Clean & Modular ✅  
**Frontend Ready:** Yes ✅
