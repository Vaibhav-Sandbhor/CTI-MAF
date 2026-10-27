"""
FastAPI Backend for AI Port Scan Risk Intelligence Engine

Three Clean API Views:
  1. POST /scan - Returns dashboard only (frontend safe, minimal)
  2. GET /report/{scan_id} - Returns detailed report (technical users, includes SHAP)
  3. GET /admin/status - Returns admin/operational metrics (backend only)

All SHAP, drift detection, and model internals hidden from frontend.
No print statements - structured JSON responses only.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import os
import json
import uuid
import subprocess
import tempfile
from datetime import datetime
import sys

# Import the refactored analysis engine
from scripts.predict_risk import analyze_scan

# Import modular backend components
# Add backend to path for imports
backend_path = os.path.join(os.path.dirname(__file__), "backend")
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

try:
    from scanner import NmapScanner
    from service_mapper import map_service_name, get_attack_vectors_for_port
    from explainable_ai import ExplainableAI
    from risk_analyzer import RiskAnalyzer
    from report_generator import DeepReportGenerator
    BACKEND_MODULES_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  Warning: Could not import backend modules: {e}")
    print("Falling back to legacy analysis engine only")
    BACKEND_MODULES_AVAILABLE = False

# Nmap path — handles both Windows and Linux
_NMAP = r"C:\Program Files (x86)\Nmap\nmap.exe" if os.name == "nt" else "nmap"
if not os.path.exists(_NMAP):
    _NMAP = "nmap"  # fall back to PATH

# ============================================================================
# FASTAPI APP SETUP
# ============================================================================

app = FastAPI(
    title="AI Port Scan Risk Intelligence Engine",
    description="Production-ready port scan analysis with ML risk scoring",
    version="2.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust to specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# DATA MODELS
# ============================================================================

class DashboardResponse(BaseModel):
    """Frontend-safe minimal risk assessment"""
    host: str
    final_risk: str
    risk_score: float
    confidence: float
    security_score: int
    risk_tier: str
    open_ports: List[int]
    critical_port_count: int
    high_port_count: int
    total_ports: int
    active_services: List[str]
    operating_system: str
    recommendations: List[str]


class FeatureImportance(BaseModel):
    """SHAP feature importance"""
    feature: str
    shap_value: float
    impact: str  # "increases_risk" or "decreases_risk"


class PortDetail(BaseModel):
    """Detailed port vulnerability information"""
    port: int
    service: str
    risk_level: str
    cvss_score: str
    cve_examples: List[str]
    exploitability: str
    mitigation_priority: str


class ReportResponse(BaseModel):
    """Detailed technical report with SHAP explainability"""
    host: str
    operating_system: str
    active_services: List[str]
    ml_prediction: Dict[str, Any]
    hybrid_logic: Dict[str, Any]
    port_analysis: List[PortDetail]
    feature_analysis: Dict[str, Any]
    explainability: Dict[str, Any]
    security_score: Dict[str, Any]
    justification: str


class AdminResponse(BaseModel):
    """Backend operational metrics - NOT for frontend"""
    model_metadata: Dict[str, Any]
    training_info: Dict[str, Any]
    operational_metrics: Dict[str, Any]


class ScanResultResponse(BaseModel):
    """Unified response for dashboard endpoint"""
    scan_id: str
    timestamp: str
    dashboard: List[DashboardResponse]
    status: str
    message: str


class ReportResultResponse(BaseModel):
    """Unified response for report endpoint"""
    scan_id: str
    report: List[ReportResponse]
    status: str


class TargetScanRequest(BaseModel):
    """Request body for IP-based scan"""
    target: str


# ============================================================================
# IN-MEMORY STORAGE (For demo - use database in production)
# ============================================================================

scan_cache: Dict[str, Dict] = {}


# ============================================================================
# HEALTH CHECK ENDPOINT
# ============================================================================

@app.get("/health", tags=["Health"])
async def health_check():
    """System health check endpoint - verifies Nmap is available"""
    nmap_status = "unavailable"
    nmap_version = ""
    
    try:
        result = subprocess.run(
            [_NMAP, "-V"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            nmap_status = "available"
            nmap_version = result.stdout.split('\n')[0] if result.stdout else "unknown"
    except Exception as e:
        nmap_status = f"error: {str(e)}"
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "AI Port Scan Risk Intelligence Engine",
        "nmap": {
            "status": nmap_status,
            "version": nmap_version,
            "path": _NMAP
        }
    }


# ============================================================================
# ENDPOINT 1: POST /scan - DASHBOARD ONLY (Frontend Safe)
# ============================================================================

@app.post("/scan", tags=["Scanning"], response_model=ScanResultResponse)
async def scan_ports(
    xml_file: UploadFile = File(..., description="Nmap XML output file"),
    return_report: bool = Query(False, description="Also return detailed report")
):
    """
    Scan Nmap XML output and return risk assessment.
    
    **Parameters:**
    - xml_file: Nmap XML scan file
    - return_report: Optional - also return full technical report
    
    **Returns:**
    - Dashboard view (always): Minimal, frontend-safe metrics
    - Report view (if return_report=true): Full technical analysis
    
    **Security:** No SHAP details or drift info in dashboard view.
    """
    
    try:
        # Generate scan ID
        scan_id = str(uuid.uuid4())[:8]
        
        # Save uploaded file to temp directory (Windows compatible)
        temp_dir = tempfile.gettempdir()
        temp_file = os.path.join(temp_dir, f"nmap_scan_{scan_id}.xml")
        
        try:
            contents = await xml_file.read()
            with open(temp_file, "wb") as f:
                f.write(contents)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"File upload failed: {str(e)}")
        
        # Run analysis engine
        results = analyze_scan(temp_file)
        
        if results["error"]:
            raise HTTPException(status_code=400, detail=f"Analysis failed: {results['error']}")
        
        # Cache full results
        scan_cache[scan_id] = {
            "timestamp": datetime.now().isoformat(),
            "dashboard": results["dashboard"],
            "report": results["report"],
            "admin": results["admin"]
        }
        
        # Build response
        response_data = {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "dashboard": results["dashboard"],
            "status": "success",
            "message": f"Scanned {len(results['dashboard'])} host(s)"
        }
        
        # Include report if requested
        if return_report:
            response_data["report"] = results["report"]
        
        # Clean up temp file
        try:
            os.remove(temp_file)
        except:
            pass
        
        return response_data
    
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_detail = f"{str(e)}\n{traceback.format_exc()}"
        raise HTTPException(status_code=500, detail=error_detail)


# ============================================================================
# ENDPOINT 1b: POST /scan/target  — IP / hostname scan (frontend button)
# ============================================================================

@app.post("/scan/target", tags=["Scanning"])
async def scan_target(request: TargetScanRequest):
    """
    Run Nmap on a target IP/hostname, analyse with ML, return full results.
    
    Uses FAST scan flags for speed:
    - -sS: SYN scan (fast, accurate)
    - -T5: Fastest timing
    - --top-ports 1000: 1000 most common ports
    - --min-rate 5000: High packet rate
    
    Note: Does NOT use -sV, -O, -A to maintain speed (<30s for local networks)
    Body: { "target": "192.168.1.1" }
    """
    target = request.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target IP/hostname is required.")

    scan_id = str(uuid.uuid4())[:8]
    
    # Create temp directory and file path that works on Windows
    temp_dir = tempfile.gettempdir()
    xml_path = os.path.join(temp_dir, f"nmap_scan_{scan_id}.xml")

    try:
        # Run Nmap with FAST scan options (no version/OS detection for speed)
        # -sS: SYN scan (fast, no full connection, no version probe)
        # -T5: Insane timing (fastest, parallel scanning)
        # --top-ports 1000: Focus on 1000 most common ports
        # --min-rate 5000: Send minimum 5000 packets/sec
        # --open: Only show open ports (faster processing)
        proc = subprocess.run(
            [
                _NMAP,
                "-sS",                    # SYN scan (FAST)
                "--open",                 # Only open ports (faster)
                "-T5",                    # Insane timing (FASTEST)
                "--top-ports", "1000",    # 1000 most common ports
                "--min-rate", "5000",     # High packet rate
                "-oX", xml_path,          # XML output
                target
            ],
            capture_output=True, 
            text=True, 
            timeout=30,  # Quick scans should complete in <30s
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        
        if proc.returncode != 0:
            stderr = proc.stderr.strip() if proc.stderr else 'non-zero exit'
            raise HTTPException(
                status_code=400,
                detail=f"Nmap error: {stderr}"
            )

        # Check if XML file was created
        if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0:
            raise HTTPException(
                status_code=400,
                detail="Nmap did not generate output file. Check target is valid."
            )

        # Analyze the scan results
        results = analyze_scan(xml_path)
        
        if results.get("error"):
            raise HTTPException(status_code=400, detail=results["error"])

        if not results.get("dashboard"):
            raise HTTPException(
                status_code=404,
                detail=f"No hosts found for '{target}'. Check target is reachable."
            )

        scan_cache[scan_id] = {
            "timestamp": datetime.now().isoformat(),
            "dashboard": results["dashboard"],
            "report":    results["report"],
            "admin":     results.get("admin"),
        }

        return {
            "scan_id":   scan_id,
            "timestamp": datetime.now().isoformat(),
            "dashboard": results["dashboard"],
            "report":    results["report"],
            "status":    "success",
            "message":   f"Scanned {len(results['dashboard'])} host(s)",
        }

    except HTTPException:
        raise
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Nmap scan timed out after 30 seconds. Target may be unreachable or network congested. Try scanning localhost (127.0.0.1) first to verify Nmap is working.")
    except Exception as e:
        import traceback
        error_detail = f"{str(e)}\n{traceback.format_exc()}"
        raise HTTPException(status_code=500, detail=error_detail)
    finally:
        # Clean up temp file
        try:
            if os.path.exists(xml_path):
                os.remove(xml_path)
        except Exception:
            pass


# ============================================================================
# ENDPOINT 2: GET /report/{scan_id}  — detailed report
# ============================================================================

@app.get("/report/{scan_id}", tags=["Reporting"])
async def get_detailed_report(scan_id: str):
    """Return detailed port analysis + SHAP explainability for a cached scan."""
    if scan_id not in scan_cache:
        raise HTTPException(
            status_code=404,
            detail=f"Scan '{scan_id}' not found. Run POST /scan/target first."
        )
    cached = scan_cache[scan_id]
    return {
        "scan_id":   scan_id,
        "timestamp": cached["timestamp"],
        "report":    cached["report"],
        "status":    "success",
    }


# ============================================================================
# ENDPOINT 2b: POST /deep-report — comprehensive security assessment
# ============================================================================

@app.post("/deep-report", tags=["Reporting"])
async def generate_deep_report(request: TargetScanRequest):
    """
    Generate comprehensive deep report with system overview, attack scenarios,
    mitigation strategies, and overall risk assessment.
    
    Body: { "target": "192.168.1.1" }
    
    Returns:
    - System overview (OS, open ports, security score)
    - Port-wise analysis with pros/cons
    - Attack scenarios with likelihood and impact
    - Mitigation strategies (immediate, short-term, long-term)
    - Overall risk justification
    """
    target = request.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target IP/hostname is required.")

    scan_id = str(uuid.uuid4())[:8]
    temp_dir = tempfile.gettempdir()
    xml_path = os.path.join(temp_dir, f"nmap_scan_{scan_id}.xml")

    try:
        # STEP 1: Run advanced Nmap scan with version + OS detection
        # Uses full scan flags for comprehensive intelligence
        # IMPORTANT: This is slower than /scan/target; timeout is 60s
        
        # Run scan with -sS -sV -O -A for full intelligence
        proc = subprocess.run(
            [
                _NMAP,
                "-sS",                    # SYN scan (fast but effective)
                "-sV",                    # Service version detection
                "-O",                     # OS detection
                "-A",                     # Aggressive: enable version, script scanning, OS detection
                "-T5",                    # Fastest timing
                "--top-ports", "1000",    # 1000 most common ports
                "--min-rate", "5000",     # High packet rate
                "-oX", xml_path,          # XML output
                target
            ],
            capture_output=True,
            text=True,
            timeout=60,  # 60s timeout for comprehensive scan with -sV -O -A
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        
        if proc.returncode != 0:
            stderr = proc.stderr.strip() if proc.stderr else 'non-zero exit'
            raise HTTPException(status_code=400, detail=f"Nmap error: {stderr}")

        if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0:
            raise HTTPException(status_code=400, detail="Nmap did not generate output")

        # STEP 2: Analyze scan with ML engine
        results = analyze_scan(xml_path)
        
        if results.get("error"):
            raise HTTPException(status_code=400, detail=results["error"])

        if not results.get("dashboard"):
            raise HTTPException(status_code=404, detail=f"No hosts found for '{target}'")

        # Extract data
        dashboard = results["dashboard"][0] if results["dashboard"] else {}
        report = results["report"][0] if results["report"] else {}
        
        # STEP 3: Generate attack scenarios using ExplainableAI
        explainable_ai = ExplainableAI()
        ports_data = dashboard.get("open_ports", []) if isinstance(dashboard.get("open_ports", []), list) else []
        
        # Convert port numbers to detailed port data
        ports_list = []
        for port_num in ports_data:
            if isinstance(port_num, int):
                ports_list.append({"port": port_num, "service": "Unknown"})
        
        # Generate attack scenarios for most critical ports
        attack_scenarios = []
        port_analysis = report.get("port_analysis", [])
        critical_ports = [p for p in port_analysis if p.get("risk_level") == "CRITICAL"][:3]  # Top 3
        
        for port_info in critical_ports:
            scenarios = explainable_ai.explain_attack_scenarios(
                port=port_info.get("port", 0),
                service=port_info.get("service", "Unknown")
            )
            attack_scenarios.append(scenarios)
        
        # STEP 4: Calculate hybrid risk score
        port_analysis_data = report.get("port_analysis", [])
        risk_result = RiskAnalyzer.calculate_overall_risk(
            ml_score=dashboard.get("risk_score", 50),
            ml_confidence=dashboard.get("confidence", 0),
            port_analysis=port_analysis_data,
            ports_data=ports_list,
            dashboard=dashboard
        )
        
        # STEP 5: Generate comprehensive report
        deep_report = DeepReportGenerator.generate_deep_report(
            dashboard=dashboard,
            report=report,
            attack_scenarios=attack_scenarios,
            ports_data=ports_list
        )
        
        # Add risk analysis to report
        deep_report["overall_assessment"]["hybrid_risk_analysis"] = risk_result
        
        # Cache the results
        scan_cache[scan_id] = {
            "timestamp": datetime.now().isoformat(),
            "dashboard": results["dashboard"],
            "report": results["report"],
            "deep_report": deep_report,
            "admin": results.get("admin"),
        }

        return {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "deep_report": deep_report,
            "status": "success",
            "message": "Deep security assessment complete"
        }

    except HTTPException:
        raise
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Deep scan timed out after 60 seconds. Target may be unreachable or network heavily congested.")
    except Exception as e:
        import traceback
        error_detail = f"{str(e)}\n{traceback.format_exc()}"
        raise HTTPException(status_code=500, detail=error_detail)
    finally:
        try:
            if os.path.exists(xml_path):
                os.remove(xml_path)
        except:
            pass



# ============================================================================
# ENDPOINT 3: GET /admin/status - ADMIN METRICS (Backend Only)
# ============================================================================

@app.get("/admin/status", tags=["Admin"], response_model=AdminResponse)
async def get_admin_status(
    api_key: str = Query(..., description="Admin API key for backend access")
):
    """
    Get admin/operational metrics (BACKEND ONLY - NOT FOR FRONTEND).
    
    **Query Parameters:**
    - api_key: Authentication key (set via environment variable ADMIN_API_KEY)
    
    **Returns:**
    - Model metadata (type, version, calibration)
    - Training information (samples, date, classes)
    - Operational metrics (processed samples, drift status)
    
    **Security:** Requires admin API key. Do NOT expose in frontend.
    """
    
    # Simple authentication (enhance in production)
    admin_key = os.getenv("ADMIN_API_KEY", "admin-secret-key-change-me")
    if api_key != admin_key:
        raise HTTPException(status_code=403, detail="Invalid admin API key")
    
    # Get latest scan for metrics (if available)
    if scan_cache:
        latest_scan = list(scan_cache.values())[-1]
        admin_data = latest_scan.get("admin", {})
    else:
        admin_data = {
            "model_metadata": {
                "model_type": "XGBoost",
                "model_file": "model_*.pkl",
                "calibration_enabled": True,
                "feature_count": 9,
                "feature_names": [
                    "open_ports_count", "service_count", "avg_cvss",
                    "uncommon_ports", "os_flag", "port_severity_score",
                    "high_risk_port_count", "service_entropy", "cvss_variance"
                ]
            },
            "training_info": {
                "model_version": "1.0",
                "last_retrain_date": "2026-02-24",
                "training_samples": 1200,
                "model_classes": ["Low", "Medium", "High", "Critical"]
            },
            "operational_metrics": {
                "new_samples_processed": 0,
                "timestamp": datetime.now().isoformat(),
                "drift_status": "Not checked (run drift_detection.py separately)",
                "log_file": "data/new_scan_logs.csv"
            }
        }
    
    return admin_data


# ============================================================================
# AUXILIARY ENDPOINTS
# ============================================================================

@app.get("/scans", tags=["Utilities"])
async def list_scans():
    """List all cached scans with metadata"""
    scans_list = []
    for scan_id, data in scan_cache.items():
        scans_list.append({
            "scan_id": scan_id,
            "timestamp": data["timestamp"],
            "hosts_scanned": len(data["dashboard"]),
            "statuses": [h["final_risk"] for h in data["dashboard"]]
        })
    
    return {
        "total_scans": len(scans_list),
        "scans": scans_list
    }


@app.get("/scans/{scan_id}/summary", tags=["Utilities"])
async def get_scan_summary(scan_id: str):
    """Get summary statistics for a specific scan"""
    if scan_id not in scan_cache:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    data = scan_cache[scan_id]
    dashboard = data["dashboard"]
    
    # Calculate statistics
    critical_count = sum(1 for h in dashboard if h["final_risk"] == "Critical")
    high_count = sum(1 for h in dashboard if h["final_risk"] == "High")
    medium_count = sum(1 for h in dashboard if h["final_risk"] == "Medium")
    low_count = sum(1 for h in dashboard if h["final_risk"] == "Low")
    
    avg_security = sum(h["security_score"] for h in dashboard) / len(dashboard) if dashboard else 0
    total_ports = sum(h["total_ports"] for h in dashboard)
    
    return {
        "scan_id": scan_id,
        "timestamp": data["timestamp"],
        "hosts_scanned": len(dashboard),
        "risk_distribution": {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count
        },
        "average_security_score": round(avg_security, 2),
        "total_open_ports": total_ports,
        "critical_ports_total": sum(h["critical_port_count"] for h in dashboard),
        "high_ports_total": sum(h["high_port_count"] for h in dashboard)
    }


@app.get("/api/docs", tags=["Documentation"])
async def api_documentation():
    """API documentation and usage guide"""
    return {
        "title": "AI Port Scan Risk Intelligence Engine",
        "version": "2.1.0",
        "endpoints": {
            "POST /scan": "Submit Nmap XML file for analysis",
            "POST /scan/target": "Run Nmap scan on target IP/hostname (fast: -sS -sV -O -A)",
            "POST /deep-report": "Generate comprehensive security assessment with attack scenarios & mitigation",
            "GET /report/{scan_id}": "Get detailed technical report with SHAP explainability",
            "GET /admin/status": "Get backend operational metrics (admin only)",
            "GET /health": "System health check",
            "GET /scans": "List all cached scans",
            "GET /scans/{scan_id}/summary": "Get scan summary statistics"
        },
        "views": {
            "dashboard": "Frontend-safe minimal metrics (no SHAP, no internals)",
            "report": "Full technical analysis for security teams",
            "deep_report": "Comprehensive assessment with system overview, attack scenarios, mitigation",
            "admin": "Operational metrics for backend/infrastructure"
        },
        "nmap_flags": {
            "-sS": "SYN scan - Fast, accurate, stealthy",
            "-sV": "Service version detection",
            "-O": "OS fingerprinting",
            "-A": "Aggressive scan (version + scripts + timing)",
            "-T5": "Fastest timing template",
            "--top-ports": "Scan 1000 most common ports",
            "--min-rate": "5000 packets/second minimum"
        },
        "ml_logic_preserved": True,
        "modular_backend": True,
        "backend_modules": [
            "scanner.NmapScanner - Nmap execution and XML parsing",
            "service_mapper.ServiceMapper - Port intelligence database",
            "explainable_ai.ExplainableAI - Risk explanation and attack scenarios",
            "risk_analyzer.RiskAnalyzer - Hybrid scoring with escalation",
            "report_generator.DeepReportGenerator - Comprehensive report generation"
        ],
        "drift_detection": "Separate script (scripts/drift_detection.py)",
        "retraining": "Separate script (scripts/retrain_pipeline.py)"
    }


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status": "failed"}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"error": str(exc), "status": "error"}
    )


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting AI Port Scan Risk Intelligence Engine on http://0.0.0.0:8001")
    print("📖 API Documentation: http://localhost:8001/docs")
    print("💡 Frontend expects this service on http://127.0.0.1:8001")
    uvicorn.run(app, host="0.0.0.0", port=8001)
