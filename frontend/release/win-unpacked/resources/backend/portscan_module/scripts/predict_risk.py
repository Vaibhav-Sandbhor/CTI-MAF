"""
AI PORT SCAN RISK INTELLIGENCE ENGINE - BACKEND ENGINE
Refactored for clean separation: Dashboard View | Detailed Report | Admin Status
All output is structured JSON (no print statements in logic)
"""
import os
import sys
import joblib
import csv
import shap
import textwrap
import platform
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn.calibration import CalibratedClassifierCV

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from feature_engineering import parse_nmap, calculate_features

# Add data directory for port knowledge
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "data"))
from port_knowledge import PORT_KNOWLEDGE, get_port_info, RISK_PRIORITY

# ============================================================================
# CONFIG & INITIALIZATION
# ============================================================================
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODEL_DIR = os.path.join(PROJECT_ROOT, "model")
LOG_FILE = os.path.join(PROJECT_ROOT, "data", "new_scan_logs.csv")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")

if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)

# Load model on module import
MODEL_FILE = None
model = None
label_encoder = None

def _load_model():
    """Load the latest trained model"""
    global MODEL_FILE, model, label_encoder
    
    model_files = [f for f in os.listdir(MODEL_DIR) if f.endswith(".pkl")]
    if not model_files:
        raise FileNotFoundError("No trained model found in model directory")
    
    latest_model = sorted(model_files)[-1]
    MODEL_FILE = os.path.join(MODEL_DIR, latest_model)
    model = joblib.load(MODEL_FILE)
    
    encoder_file = os.path.join(MODEL_DIR, "label_encoder.pkl")
    if os.path.exists(encoder_file):
        label_encoder = joblib.load(encoder_file)

try:
    _load_model()
except FileNotFoundError as e:
    print(f"WARNING: {e}")


FALLBACK_SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    135: "RPC",
    139: "SMB",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    5000: "HTTP-Alt",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-Alt",
    8001: "HTTP-Alt",
    8080: "HTTP-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def _resolve_os_name(os_info, ip):
    if os_info and str(os_info).strip().lower() != "unknown":
        return os_info
    if str(ip) in {"127.0.0.1", "::1", "localhost"}:
        return f"{platform.system()} (Local Host)"
    return "Unknown"


def _infer_risk_level(port):
    if port in {23, 445, 6379, 9200, 27017}:
        return "Critical"
    if port in {21, 22, 25, 53, 80, 135, 139, 1433, 3306, 3389, 5432, 5900}:
        return "High"
    if port in {443, 465, 5000, 8000, 8001, 8080}:
        return "Medium"
    return "Low"


def _cvss_from_risk(risk_level):
    return {
        "Critical": 9.0,
        "High": 7.5,
        "Medium": 5.0,
        "Low": 2.5,
    }.get(risk_level, 2.5)


def _exploitability_from_cvss(cvss_score):
    if cvss_score >= 9:
        return "Critical"
    if cvss_score >= 7:
        return "High"
    if cvss_score >= 4:
        return "Medium"
    return "Low"


def _priority_from_risk(risk_level):
    return {
        "Critical": "Critical",
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
    }.get(risk_level, "Low")

# ============================================================================
# HELPER FUNCTIONS (No print statements)
# ============================================================================

def generate_human_explanation(feature_dict):
    """Generate human-readable risk factor explanations"""
    explanations = []
    
    open_ports = feature_dict["open_ports_count"]
    service_count = feature_dict["service_count"]
    avg_cvss = feature_dict["avg_cvss"]
    uncommon_ports = feature_dict["uncommon_ports"]
    os_flag = feature_dict["os_flag"]
    
    if avg_cvss >= 7:
        explanations.append(
            f"High vulnerability score (CVSS {avg_cvss:.2f}), indicating severe security weaknesses"
        )
    
    if open_ports >= 10:
        explanations.append(
            f"{int(open_ports)} open ports detected - expanded attack surface"
        )
    
    if service_count >= 8:
        explanations.append(
            f"Multiple active services ({int(service_count)}) increase exploitation exposure"
        )
    
    if uncommon_ports >= 1:
        explanations.append(
            "Non-standard ports open - may indicate hidden or misconfigured services"
        )
    
    if os_flag == 1:
        explanations.append(
            "Windows OS detected - primary ransomware/malware target"
        )
    
    if not explanations:
        explanations.append("No major high-risk indicators detected")
    
    return explanations


def calculate_host_security_score(feature_dict, critical_ports_count, high_ports_count, final_risk_level):
    
    base_score = 100  # Start with perfect score
    
    # 1. OPEN PORTS PENALTY (0-20 points) - 20% weight
    open_ports = feature_dict["open_ports_count"]
    if open_ports <= 1:
        ports_score = 20
    elif open_ports <= 3:
        ports_score = 15
    elif open_ports <= 5:
        ports_score = 10
    elif open_ports <= 8:
        ports_score = 5
    else:
        ports_score = 0
    
    # 2. CVSS/VULNERABILITY SCORE PENALTY (0-25 points) - 25% weight
    avg_cvss = feature_dict["avg_cvss"]
    if avg_cvss <= 3.0:
        cvss_score = 25
    elif avg_cvss <= 5.0:
        cvss_score = 18
    elif avg_cvss <= 7.0:
        cvss_score = 12
    elif avg_cvss <= 8.0:
        cvss_score = 6
    else:
        cvss_score = 0
    
    # 3. CRITICAL PORTS PENALTY (0-30 points) - 30% weight
    if critical_ports_count == 0:
        critical_score = 30
    elif critical_ports_count == 1:
        critical_score = 15
    elif critical_ports_count == 2:
        critical_score = 8
    else:
        critical_score = 0
    
    # 4. OS RISK PROFILE PENALTY (0-15 points) - 15% weight
    os_flag = feature_dict["os_flag"]
    if os_flag == 0:  # Non-Windows
        os_score = 15
    else:  # Windows (higher target for ransomware)
        os_score = 8
    
    # 5. SERVICE COMPLEXITY PENALTY (0-10 points) - 10% weight
    service_count = feature_dict["service_count"]
    uncommon_ports = feature_dict["uncommon_ports"]
    if service_count <= 2:
        service_score = 10
    elif service_count <= 4:
        service_score = 8
    elif service_count <= 6:
        service_score = 5
    else:
        service_score = 2 if uncommon_ports == 0 else 0
    
    # Calculate final security score
    security_score = 100 - (20 - ports_score) - (25 - cvss_score) - (30 - critical_score) - (15 - os_score) - (10 - service_score)
    security_score = max(0, min(100, security_score))
    
    # Determine risk tier
    if security_score >= 80:
        risk_tier = "Low"
        tier_emoji = "🟢"
    elif security_score >= 60:
        risk_tier = "Medium"
        tier_emoji = "🟡"
    elif security_score >= 40:
        risk_tier = "High"
        tier_emoji = "🟠"
    else:
        risk_tier = "Critical"
        tier_emoji = "🔴"
    
    # Generate improvement recommendations
    improvements = []
    if critical_ports_count > 0:
        improvements.append(f"CRITICAL: Patch/disable {critical_ports_count} critical port(s) immediately")
    if open_ports > 5:
        improvements.append(f"Close unnecessary ports (currently {int(open_ports)} open)")
    if avg_cvss > 7.0:
        improvements.append(f"Address high CVSS vulnerabilities (avg: {avg_cvss:.1f})")
    if os_flag == 1:
        improvements.append("Windows system: Increase Windows-specific hardening")
    if service_count > 6:
        improvements.append("Reduce service count and complexity")
    if high_ports_count > 0:
        improvements.append(f"Configure firewalls for {int(high_ports_count)} high-risk port(s)")
    
    if not improvements:
        improvements.append("Continue regular security monitoring and patching")
    
    return {
        "security_score": security_score,
        "risk_tier": risk_tier,
        "tier_emoji": tier_emoji,
        "ports_score": ports_score,
        "cvss_score": cvss_score,
        "critical_score": critical_score,
        "os_score": os_score,
        "service_score": service_score,
        "improvements": improvements
    }



def calculate_port_based_risk(open_ports):
    """Determine risk level from port database"""
    RISK_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    highest_risk = "Low"
    
    for port in open_ports:
        port_info = get_port_info(port)
        if port_info:
            port_risk = port_info["risk_level"]
            if RISK_RANK.get(port_risk, 0) > RISK_RANK.get(highest_risk, 0):
                highest_risk = port_risk
    
    return highest_risk


def _log_scan_results(feature_row_dict, prediction, probability):
    """Log scan results to CSV (internal utility)"""
    file_exists = os.path.exists(LOG_FILE)
    
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        
        if not file_exists:
            writer.writerow([
                "timestamp", "open_ports_count", "service_count", "avg_cvss",
                "uncommon_ports", "os_flag", "port_severity_score",
                "high_risk_port_count", "service_entropy", "cvss_variance",
                "predicted_label", "risk_score", "confidence"
            ])
        
        confidence = max(probability) if isinstance(probability, (list, np.ndarray)) else probability
        risk_score = confidence * 100
        
        writer.writerow([
            datetime.now(),
            feature_row_dict["open_ports_count"],
            feature_row_dict["service_count"],
            feature_row_dict["avg_cvss"],
            feature_row_dict["uncommon_ports"],
            feature_row_dict["os_flag"],
            feature_row_dict["port_severity_score"],
            feature_row_dict["high_risk_port_count"],
            feature_row_dict["service_entropy"],
            feature_row_dict["cvss_variance"],
            prediction,
            round(risk_score, 2),
            round(confidence, 3)
        ])


# ============================================================================
# MAIN ANALYSIS ENGINE - Returns Structured Views
# ============================================================================

def analyze_scan(xml_path):
    """
    Main analysis function - returns structured views (Dashboard, Report, Admin)
    
    Returns:
    {
        "dashboard": [...],     # List of frontend-safe minimal views
        "report": [...],        # List of detailed technical reports
        "admin": {...},         # Backend operational metrics
        "error": string (if any)
    }
    """
    
    if not model:
        return {
            "error": "Model not loaded. Please train the model first.",
            "dashboard": None,
            "report": None,
            "admin": None
        }
    
    try:
        # ===== PARSE NMAP & EXTRACT FEATURES =====
        hosts = parse_nmap(xml_path)
        
        all_features = []
        ips = []
        host_objects = []
        
        for host in hosts:
            features = calculate_features(host)
            feature_row = [
                features["open_ports_count"],
                features["service_count"],
                features["avg_cvss"],
                features["uncommon_ports"],
                features["os_flag"],
                features["port_severity_score"],
                features["high_risk_port_count"],
                features["service_entropy"],
                features["cvss_variance"]
            ]
            
            all_features.append(feature_row)
            ips.append(host["ip"])
            host_objects.append(host)
        
        X_new = pd.DataFrame(all_features, columns=[
            "open_ports_count", "service_count", "avg_cvss", "uncommon_ports",
            "os_flag", "port_severity_score", "high_risk_port_count",
            "service_entropy", "cvss_variance"
        ])
        
        # ===== PREDICTIONS =====
        predictions = model.predict(X_new)
        if label_encoder is not None:
            predictions = label_encoder.inverse_transform(predictions)
        
        probabilities = model.predict_proba(X_new)
        
        # ===== SHAP EXPLAINABILITY =====
        if isinstance(model, CalibratedClassifierCV):
            base_model = model.estimator
        else:
            base_model = model
        
        explainer = shap.TreeExplainer(base_model)
        shap_values = explainer.shap_values(X_new)
        
        # ===== BUILD RESPONSE STRUCTURES =====
        dashboard_list = []
        report_list = []
        
        for i, (ip, pred, prob) in enumerate(zip(ips, predictions, probabilities)):
            confidence = max(prob)
            ml_risk = pred
            risk_score = confidence * 100
            
            host_obj = host_objects[i]
            open_ports_list = host_obj["open_ports"]
            services_list = host_obj["services"]
            os_info = _resolve_os_name(host_obj.get("os"), ip)
            port_services = host_obj.get("port_services", {})
            
            # ===== HYBRID RISK SCORING =====
            RISK_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
            port_risk = calculate_port_based_risk(open_ports_list)
            
            if RISK_RANK.get(port_risk, 0) > RISK_RANK.get(ml_risk, 0):
                final_risk = port_risk
                risk_score = min(95, risk_score + 20)
            else:
                final_risk = ml_risk
            
            # ===== FEATURE DICTIONARY =====
            feature_dict = {
                "open_ports_count": X_new.iloc[i]["open_ports_count"],
                "service_count": X_new.iloc[i]["service_count"],
                "avg_cvss": X_new.iloc[i]["avg_cvss"],
                "uncommon_ports": X_new.iloc[i]["uncommon_ports"],
                "os_flag": X_new.iloc[i]["os_flag"],
                "port_severity_score": X_new.iloc[i]["port_severity_score"],
                "high_risk_port_count": X_new.iloc[i]["high_risk_port_count"],
                "service_entropy": X_new.iloc[i]["service_entropy"],
                "cvss_variance": X_new.iloc[i]["cvss_variance"]
            }
            
            # ===== CALCULATE PORT RISK METRICS =====
            port_risk_scores = []
            for port in open_ports_list:
                port_info = get_port_info(port)
                if port_info:
                    priority = RISK_PRIORITY.get(port_info["risk_level"], 0)
                    port_risk_scores.append((port, priority))
            
            critical_ports_count = len([p for p, s in port_risk_scores if s >= 100])
            high_ports_count = len([p for p, s in port_risk_scores if 75 <= s < 100])
            
            # ===== CALCULATE SECURITY SCORE =====
            security_score_data = calculate_host_security_score(
                feature_dict, critical_ports_count, high_ports_count, final_risk
            )
            
            # ------- DASHBOARD VIEW (Frontend Safe) -------
            dashboard = {
                "host": ip,
                "final_risk": final_risk,
                "risk_score": round(risk_score, 2),
                "confidence": round(confidence * 100, 2),
                "security_score": security_score_data["security_score"],
                "risk_tier": security_score_data["risk_tier"],
                "open_ports": sorted(open_ports_list),
                "critical_port_count": int(critical_ports_count),
                "high_port_count": int(high_ports_count),
                "total_ports": len(open_ports_list),
                "active_services": services_list,
                "operating_system": os_info,
                "recommendations": security_score_data["improvements"]
            }
            
            # ------- DETAILED REPORT VIEW (Technical Users) -------
            human_explanations = generate_human_explanation(feature_dict)
            
            # SHAP values for this host
            if isinstance(shap_values, list):
                class_index = list(model.classes_).index(ml_risk)
                host_shap = shap_values[class_index][i]
            else:
                host_shap = shap_values[i]
            
            # Build SHAP feature importance
            feature_importance = []
            for j, feature_name in enumerate(X_new.columns):
                shap_val = float(np.asarray(host_shap[j]).flatten()[0])
                feature_importance.append({
                    "feature": feature_name,
                    "shap_value": round(shap_val, 4),
                    "impact": "increases_risk" if shap_val > 0 else "decreases_risk"
                })
            
            feature_importance.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
            
            # Port details
            port_details = []
            for port in open_ports_list:
                port_info = get_port_info(port)
                if port_info:
                    port_details.append({
                        "port": port,
                        "service": port_info.get("service_name", "Unknown"),
                        "risk_level": port_info.get("risk_level", "Unknown"),
                        "cvss_score": port_info.get("cvss_score", "N/A"),
                        "cve_examples": port_info.get("cve_examples", []),
                        "exploitability": port_info.get("exploitability", "Unknown"),
                        "mitigation_priority": port_info.get("mitigation_priority", "Medium")
                    })
                else:
                    detected_service = port_services.get(port) or port_services.get(str(port))
                    if detected_service and str(detected_service).lower() != "unknown":
                        service_name = detected_service
                    else:
                        service_name = FALLBACK_SERVICE_NAMES.get(port, f"Port-{port}")

                    inferred_risk = _infer_risk_level(port)
                    inferred_cvss = _cvss_from_risk(inferred_risk)

                    port_details.append({
                        "port": port,
                        "service": service_name,
                        "risk_level": inferred_risk,
                        "cvss_score": inferred_cvss,
                        "cve_examples": [],
                        "exploitability": _exploitability_from_cvss(inferred_cvss),
                        "mitigation_priority": _priority_from_risk(inferred_risk)
                    })
            
            report = {
                "host": ip,
                "operating_system": os_info,
                "active_services": services_list,
                "ml_prediction": {
                    "predicted_risk": ml_risk,
                    "confidence": round(confidence * 100, 2),
                    "algorithm": "XGBoost (with probability calibration)"
                },
                "hybrid_logic": {
                    "ml_risk": ml_risk,
                    "port_intelligence_risk": port_risk,
                    "escalation_applied": RISK_RANK.get(port_risk, 0) > RISK_RANK.get(ml_risk, 0),
                    "final_risk": final_risk,
                    "final_risk_score": round(risk_score, 2)
                },
                "port_analysis": port_details,
                "feature_analysis": {
                    "features": feature_dict,
                    "human_explanations": human_explanations
                },
                "explainability": {
                    "top_features": feature_importance[:5],
                    "all_features": feature_importance
                },
                "security_score": security_score_data,
                "justification": f"Final risk level {final_risk} assigned based on ML prediction ({ml_risk}, {confidence*100:.1f}% confidence), port intelligence database analysis, critical ports detected ({critical_ports_count}), and CVSS average ({feature_dict['avg_cvss']:.2f}). {'Escalation applied due to port severity.' if RISK_RANK.get(port_risk, 0) > RISK_RANK.get(ml_risk, 0) else 'ML prediction confirmed by port analysis.'}"
            }
            
            dashboard_list.append(dashboard)
            report_list.append(report)
            
            # Log scan results
            _log_scan_results(feature_dict, ml_risk, prob)
        
        # ===== ADMIN VIEW (Backend Operational Metrics) =====
        admin_view = {
            "model_metadata": {
                "model_type": type(base_model).__name__,
                "model_file": os.path.basename(MODEL_FILE),
                "calibration_enabled": isinstance(model, CalibratedClassifierCV),
                "feature_count": len(X_new.columns),
                "feature_names": list(X_new.columns)
            },
            "training_info": {
                "model_version": "1.0",
                "last_retrain_date": "2026-02-24",
                "training_samples": 1200,
                "model_classes": list(model.classes_) if hasattr(model, 'classes_') else []
            },
            "operational_metrics": {
                "new_samples_processed": len(dashboard_list),
                "timestamp": datetime.now().isoformat(),
                "drift_status": "Not checked (run drift_detection.py separately)",
                "log_file": LOG_FILE
            }
        }
        
        # Return all three views
        return {
            "dashboard": dashboard_list,
            "report": report_list,
            "admin": admin_view,
            "error": None
        }
    
    except Exception as e:
        return {
            "error": str(e),
            "dashboard": None,
            "report": None,
            "admin": None
        }


# ============================================================================
# LEGACY: Console output for backward compatibility (if run as script)
# ============================================================================

if __name__ == "__main__":
    xml_file = os.path.join(PROJECT_ROOT, "nmap_scans", "scan_master.xml")
    
    results = analyze_scan(xml_file)
    
    if results["error"]:
        print(f"ERROR: {results['error']}")
    else:
        print("\n" + "="*70)
        print(" "*15 + "🔐 AI RISK INTELLIGENCE ENGINE 🔐")
        print(" "*10 + "Port Scan Risk Assessment & Exploitation Analysis")
        print("="*70)
        
        # Print dashboard summary for each host
        for dashboard in results["dashboard"]:
            print(f"\n{'─'*70}")
            print(f"HOST: {dashboard['host']}")
            print(f"{'─'*70}")
            print(f"Operating System: {dashboard['operating_system']}")
            print(f"Open Ports: {dashboard['open_ports']}")
            print(f"Active Services: {', '.join(dashboard['active_services']) if dashboard['active_services'] else 'Unknown'}")
            
            print(f"\nRisk Level: {dashboard['final_risk']}")
            print(f"Risk Score: {dashboard['risk_score']}%")
            print(f"Confidence: {dashboard['confidence']}%")
            print(f"Security Score: {dashboard['security_score']}/100 ({dashboard['risk_tier']})")
            
            print(f"\nCritical Ports: {dashboard['critical_port_count']}")
            print(f"High-Risk Ports: {dashboard['high_port_count']}")
            
            print(f"\nRecommendations:")
            for i, rec in enumerate(dashboard['recommendations'][:3], 1):
                print(f"  {i}. {rec}")
        
        print("\n" + "="*70)
        print("✅ ANALYSIS COMPLETE")
        print(f"📁 Detailed logs saved to: {LOG_FILE}")
        print("="*70 + "\n")