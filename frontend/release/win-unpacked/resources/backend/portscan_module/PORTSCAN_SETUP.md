# 🔍 AI Port Scanner Setup & Troubleshooting

## Quick Start

```bash
# 1. Prerequisites - Install Nmap
# Windows: Download from https://nmap.org/download.html (default install to C:\Program Files (x86)\Nmap\)
# macOS: brew install nmap
# Linux: sudo apt install nmap

# 2. Install dependencies
pip install -r requirements_api.txt

# 3. Start the API server on port 8001
python api.py

# 4. Test health check
curl http://localhost:8001/health
```

## Port Configuration

⚠️ **IMPORTANT:** The frontend expects the Port Scanner API on **port 8001**.

- Edit `api.py` main section if you need a different port:
  ```python
  if __name__ == "__main__":
      import uvicorn
      uvicorn.run(app, host="0.0.0.0", port=8001)  # Change here
  ```

## Nmap Installation

### Windows

1. Download installer: https://nmap.org/download.html
2. Run installer (choose full install)
3. Default path: `C:\Program Files (x86)\Nmap\nmap.exe`
4. Verify installation:
   ```bash
   nmap --version
   ```

### macOS

```bash
brew install nmap
which nmap  # Verify location
```

### Linux

```bash
sudo apt update
sudo apt install nmap
which nmap
```

## API Endpoints

### 1. Health Check (Verify setup)

```bash
curl http://localhost:8001/health
```

**Expected Response:**
```json
{
  "status": "healthy",
  "timestamp": "2026-03-02T14:35:00...",
  "service": "AI Port Scan Risk Intelligence Engine",
  "nmap": {
    "status": "available",
    "version": "Nmap version 7.x.x",
    "path": "C:\\Program Files (x86)\\Nmap\\nmap.exe"
  }
}
```

### 2. Scan Target (Main endpoint)

```bash
curl -X POST http://localhost:8001/scan/target \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1"}'
```

### 3. Upload Nmap XML

```bash
curl -X POST http://localhost:8001/scan \
  -F "xml_file=@nmap_output.xml"
```

## Scan Options Explained

The API now uses **fast, optimized scanning**:

```
-sS            = SYN scan (fast TCP scanning, no version probe)
--open         = Only show OPEN ports
-T5            = Insane timing (fastest)
--top-ports 1000 = Scan only 1000 most common ports
--min-rate 5000  = Send 5000+ packets/second
```

Why not `-sV` (version detection)? 
- Too slow (probes each open port to identify services)
- Takes 60+ seconds per target
- Causes 408 timeouts

## Troubleshooting

### Issue: "Cannot reach AI Port Scanner at http://127.0.0.1:8001"

**Check 1: Is the server running?**
```bash
curl http://localhost:8001/health
```

If no response, start the server:
```bash
cd AI_PortScan_Analyzer/AI_PortScan_Analyzer
python api.py
```

**Check 2: Port already in use?**
```bash
# Windows
netstat -ano | findstr :8001

# Mac/Linux
lsof -i :8001
```

If 8001 is in use, change the port in `api.py` and update frontend:
1. Edit `api.py` main block (port setting)
2. Edit `frontend/src/servives/api.js`:
   ```javascript
   const PORTSCAN_BASE = "http://127.0.0.1:8001";  // Change 8001 here
   ```

### Issue: "Nmap not found" in health check

**Check path:** Is Nmap in the default location?

```python
# In api.py
_NMAP = r"C:\Program Files (x86)\Nmap\nmap.exe"  # Windows
_NMAP = "/usr/bin/nmap"  # Linux
_NMAP = "/usr/local/bin/nmap"  # macOS
```

**Fix:** Update the path in `api.py` line ~26:
```python
# Nmap path — handles both Windows and Linux
_NMAP = r"C:\Program Files (x86)\Nmap\nmap.exe" if os.name == "nt" else "nmap"
if not os.path.exists(_NMAP):
    _NMAP = "nmap"  # fall back to PATH
```

### Issue: Scan still times out after 30 seconds

**Possible causes:**
1. **Target is down/unreachable** → Try `127.0.0.1` first
2. **Network congested** → Retry or wait
3. **Firewall blocking Nmap** → Disable temporarily to test
4. **Nmap slow on this system** → Increase timeout in code (not recommended)

**Test with localhost first:**
```bash
curl -X POST http://localhost:8001/scan/target \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1"}'
```

### Issue: XGBoost/sklearn version warnings

These are non-critical warnings about model serialization:

```
InconsistentVersionWarning: Trying to unpickle estimator XX from version 1.6.1 when using version 1.8.0
```

**Fix (optional):** Retrain the model with current scikit-learn:
```bash
cd AI_PortScan_Analyzer/AI_PortScan_Analyzer
python scripts/train_xgboost.py  # If this script exists
```

Or suppress warnings (not recommended for production).

## Performance Tips

### For Faster Scanning

The current config scans **~1000 common ports** in **<30 seconds**.

To make it even faster (less thorough):
```python
# In api.py, modify the subprocess.run call
[
    _NMAP,
    "-sS",
    "--open",
    "-T5",
    "--top-ports", "100",     # ← Change from 1000 to 100
    "--min-rate", "10000",    # ← Increase packet rate
    "-oX", xml_path,
    target
]
```

### For More Thorough Scanning (20+ seconds)

To scan more ports:
```python
[
    _NMAP,
    "-sS",
    "--open",
    "-T4",                    # ← Use T4 instead of T5
    "-p-",                    # ← All ports (0-65535) - slow!
    "-oX", xml_path,
    target
]
```

⚠️ Full port scans will exceed 30-second timeout. Increase timeout value first.

## Docker Deployment

If running in Docker, ensure Nmap is installed:

```dockerfile
FROM python:3.10

RUN apt-get update && apt-get install -y nmap

WORKDIR /app
COPY . .
RUN pip install -r requirements_api.txt

EXPOSE 8001
CMD ["python", "api.py"]
```

## See Also

- [Frontend Configuration](../../frontend/README.md)
- [Main API Server](../api_server.py)
- [Nmap Documentation](https://nmap.org/docs.html)
