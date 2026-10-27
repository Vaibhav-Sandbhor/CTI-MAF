# 🚀 QUICK REFERENCE - API INTEGRATION GUIDE

## 5-MINUTE SETUP

```bash
# 1. Install dependencies
pip install -r requirements_api.txt

# 2. Start server
python api.py

# 3. Test it
curl -X POST "http://localhost:8000/scan" -F "xml_file=@nmap_scans/scan_master.xml"
```

---

## ENDPOINT SUMMARY

| Method | Endpoint | Purpose | Auth | Returns |
|--------|----------|---------|------|---------|
| POST | `/scan` | Analyze Nmap XML | No | Dashboard (minimal) |
| GET | `/report/{scan_id}` | Get full report with SHAP | No | Report (full technical) |
| GET | `/admin/status` | Backend metrics | API Key | Admin metrics only |
| GET | `/health` | Health check | No | Status |
| GET | `/scans` | List all scans | No | Scan list |
| GET | `/scans/{scan_id}/summary` | Summary stats | No | Summary |
| GET | `/docs` | API documentation | No | Swagger UI |

---

## COMMON USE CASES

### Frontend Dashboard
```python
import requests

# 1. Submit scan
response = requests.post(
    "http://localhost:8000/scan",
    files={"xml_file": open("scan.xml", "rb")}
)
scan_data = response.json()
scan_id = scan_data["scan_id"]
dashboard = scan_data["dashboard"]

# 2. Display dashboard info
for host in dashboard:
    print(f"Host: {host['host']}")
    print(f"Risk: {host['final_risk']} ({host['risk_score']}%)")
    print(f"Recommendations: {host['recommendations']}")
```

### Security Analysis
```python
import requests

# 1. Submit scan + get report
response = requests.post(
    "http://localhost:8000/scan",
    files={"xml_file": open("scan.xml", "rb")},
    data={"return_report": "true"}
)
result = response.json()
report = result["report"]

# 2. Analyze SHAP values
for host_report in report:
    print(f"Host: {host_report['host']}")
    print("Feature Importance (SHAP):")
    for feat in host_report["explainability"]["top_features"]:
        print(f"  {feat['feature']}: {feat['shap_value']:.2f} ({feat['impact']})")
```

### Backend Monitoring
```python
import requests

# Get admin metrics
response = requests.get(
    "http://localhost:8000/admin/status",
    params={"api_key": "your-admin-key"}
)
admin_data = response.json()

print(f"Model: {admin_data['model_metadata']['model_type']}")
print(f"Training: {admin_data['training_info']['last_retrain_date']}")
print(f"Samples processed: {admin_data['operational_metrics']['new_samples_processed']}")
```

---

## RESPONSE STRUCTURE

### Dashboard (POST /scan)
```json
{
  "scan_id": "uuid",
  "timestamp": "ISO8601",
  "status": "success",
  "dashboard": [
    {
      "host": "IP",
      "final_risk": "risk_level",
      "risk_score": 0-100,
      "confidence": 0-100,
      "security_score": 0-100,
      "open_ports": [list],
      "recommendations": [list]
    }
  ]
}
```

### Report (GET /report/{scan_id})
```json
{
  "scan_id": "uuid",
  "status": "success",
  "report": [
    {
      "host": "IP",
      "ml_prediction": {...},
      "port_analysis": [...],
      "explainability": {
        "top_features": [
          {
            "feature": "name",
            "shap_value": float,
            "impact": "increases/decreases_risk"
          }
        ]
      }
    }
  ]
}
```

### Admin (GET /admin/status?api_key=***)
```json
{
  "model_metadata": {...},
  "training_info": {...},
  "operational_metrics": {...}
}
```

---

## ENVIRONMENT VARIABLES

```bash
# Required for admin endpoint
export ADMIN_API_KEY="your-secure-key"

# Optional CORS configuration (default: all origins)
export CORS_ORIGINS="http://localhost:3000,https://yourdomain.com"
```

---

## ERROR HANDLING

```python
import requests

try:
    response = requests.post(
        "http://localhost:8000/scan",
        files={"xml_file": open("scan.xml", "rb")}
    )
    response.raise_for_status()
    data = response.json()
    
except requests.exceptions.FileNotFoundError:
    print("XML file not found")
except requests.exceptions.HTTPError as e:
    print(f"HTTP Error: {e.response.status_code}")
    if e.response.status_code == 404:
        print("Scan not found")
except Exception as e:
    print(f"Error: {e}")
```

---

## PRODUCTION DEPLOYMENT

### Using Gunicorn
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 api:app
```

### Using Systemd
```ini
[Unit]
Description=Port Scan Intelligence API

[Service]
Type=notify
User=www-data
WorkingDirectory=/path/to/project
Environment=ADMIN_API_KEY=secure-key
ExecStart=/usr/bin/gunicorn -w 4 -b 0.0.0.0:8000 api:app
Restart=always

[Install]
WantedBy=multi-user.target
```

### Using Docker
```bash
docker run -p 8000:8000 \
  -e ADMIN_API_KEY=your-key \
  -v $(pwd)/nmap_scans:/app/nmap_scans \
  port-scan-intelligence:latest
```

---

## WHAT CHANGED

### Updated Files
- ✅ `scripts/predict_risk.py` - Now returns `analyze_scan()` instead of printing
- ✅ `api.py` - NEW FastAPI backend
- ✅ `requirements_api.txt` - NEW dependencies

### Unchanged Files
- ✓ All ML training logic
- ✓ Feature engineering
- ✓ Port intelligence database
- ✓ SHAP explainability
- ✓ Drift detection script (separate)
- ✓ Retraining pipeline (separate)

---

## QUICK INTEGRATION CHECKLIST

- [ ] Install `requirements_api.txt`
- [ ] Set `ADMIN_API_KEY` environment variable
- [ ] Start API: `python api.py`
- [ ] Test POST /scan endpoint
- [ ] Test GET /report/{scan_id} endpoint
- [ ] Test GET /admin/status endpoint
- [ ] Configure CORS for your domain
- [ ] Deploy with gunicorn/systemd
- [ ] Monitor admin metrics
- [ ] Configure log file location

---

**Status:** ✅ Production Ready  
**Version:** 2.0.0  
**Updated:** 2026-02-24
