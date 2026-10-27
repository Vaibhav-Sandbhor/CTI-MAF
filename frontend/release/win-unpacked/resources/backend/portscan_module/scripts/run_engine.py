import subprocess
import sys
import os
import csv

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
XML_PATH = os.path.join(PROJECT_ROOT, "nmap_scans", "scan1.xml")
NEW_SCAN_LOGS = os.path.join(PROJECT_ROOT, "data", "new_scan_logs.csv")

def run_nmap():
    """Execute Nmap security scan"""
    print("🔍 Running Nmap scan...\n")
    try:
        subprocess.run(
            ["nmap", "-sS", "-sV", "-T4", "-oX", XML_PATH, "localhost"],
            check=True
        )
        print("✅ Nmap scan completed.\n")
        return True
    except Exception as e:
        print("❌ Nmap failed. Make sure Nmap is installed and added to PATH.")
        return False

def run_script(script_name, description):
    """Run a Python script component"""
    print(f"\n{description}")
    try:
        result = subprocess.run(
            [sys.executable, os.path.join("scripts", script_name)],
            cwd=PROJECT_ROOT,
            capture_output=False,
            text=True
        )
        return result.returncode == 0, result.returncode
    except Exception as e:
        print(f"❌ {script_name} failed: {e}")
        return False, -1

def count_samples_in_log(log_file):
    """Count number of samples (rows) in new_scan_logs.csv"""
    if not os.path.exists(log_file):
        return 0
    
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            rows = list(reader)
            # Subtract 1 for header row if it exists
            return max(0, len(rows) - 1) if len(rows) > 0 else 0
    except Exception as e:
        print(f"❌ Error counting samples: {e}")
        return 0

def check_retrain_eligibility(drift_detected, sample_count):
    """
    Determine if retraining should occur based on drift and sample count.
    Returns tuple: (should_retrain: bool, reason: str)
    """
    if not drift_detected:
        return False, "No drift detected"
    
    if sample_count < 200:
        return False, f"Insufficient samples ({sample_count}/200)"
    
    return True, f"Drift + sufficient samples ({sample_count}>=200)"

def main():
    print("\n" + "=" * 70)
    print("     🔐 AI PORT SCAN RISK INTELLIGENCE ENGINE 🔐")
    print("=" * 70)
    
    # Step 1: Nmap Security Scan
    if not run_nmap():
        return False
    
    # Step 2: Risk Prediction & Intelligence Analysis
    print("\n" + "=" * 70)
    print("🧠 STEP 1: Risk Prediction & Intelligence Analysis")
    print("=" * 70)
    success, _ = run_script("predict_risk.py", "Running predict_risk.py...")
    if not success:
        print("❌ Prediction failed")
        return False
    
    # Step 3: Drift Detection Analysis
    print("\n" + "=" * 70)
    print("📊 STEP 2: Data Distribution Drift Detection")
    print("=" * 70)
    success, exit_code = run_script("drift_detection.py", "Running drift_detection.py...")
    
    # Capture drift status: exit code 1 means drift detected, 0 means no drift
    drift_detected = (exit_code == 1)
    
    # ===== AUTO-RETRAIN DECISION ENGINE =====
    print("\n" + "=" * 70)
    print("🤖 AUTO-RETRAIN DECISION ENGINE")
    print("=" * 70)
    
    # Count samples in new_scan_logs.csv
    sample_count = count_samples_in_log(NEW_SCAN_LOGS)
    
    # Display decision information
    print(f"\n📊 Drift Status:            {'🔴 DETECTED' if drift_detected else '🟢 NO DRIFT'}")
    print(f"📈 New Samples Available:   {sample_count}/200")
    
    # Check eligibility for retraining
    should_retrain, reason = check_retrain_eligibility(drift_detected, sample_count)
    
    # Execute decision
    print(f"\n🔍 Eligibility Check: {reason}")
    
    if should_retrain:
        print("\n✅ AUTO-TRIGGERING RETRAINING...")
        print("=" * 70)
        success, _ = run_script("retrain_pipeline.py", "Running retrain_pipeline.py...")
        if not success:
            print("⚠️ Retraining encountered issues (non-critical)")
    elif drift_detected and sample_count < 200:
        print(f"\n⚠️  Drift detected but insufficient new samples for retraining.")
        print(f"   Waiting for more data: {sample_count}/200 samples")
    else:
        print(f"\n✓ No retraining required.")
    
    print("\n" + "=" * 70)
    print("✅ COMPLETE PIPELINE EXECUTION FINISHED")
    print("=" * 70)
    print("\n📊 Generated Output Files:")
    print(f"   • {os.path.join(PROJECT_ROOT, 'data', 'new_scan_logs.csv')} - Risk analysis logs")
    print(f"   • {os.path.join(PROJECT_ROOT, 'nmap_scans', 'scan1.xml')} - Latest Nmap scan")
    if os.path.exists(os.path.join(PROJECT_ROOT, "logs", "system.log")):
        print(f"   • {os.path.join(PROJECT_ROOT, 'logs', 'system.log')} - System operations log")
    if os.path.exists(os.path.join(PROJECT_ROOT, "logs", "drift_detection.log")):
        print(f"   • {os.path.join(PROJECT_ROOT, 'logs', 'drift_detection.log')} - Drift analysis details")
    print("\n" + "=" * 70 + "\n")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)