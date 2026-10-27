"""
ransomware_module
=================
Industry-grade Early Ransomware Detection System with Honeypot Integration.

Pipeline:
  1. honeypot/honeypot_simulator.py   -> honeypot/honeypot_log.csv
  2. utils/honeypot_feature_extractor.py -> data/live_input.csv
  3. inference/realtime_csv_monitor.py   -> output/predictions_log.csv + alerts.log

Quick start:
  python -m ransomware_module.scripts.build_dataset
  python -m ransomware_module.scripts.train_model
  python -m ransomware_module.honeypot.honeypot_simulator --mode simulate
  python -m ransomware_module.utils.honeypot_feature_extractor
  python -m ransomware_module.inference.realtime_csv_monitor
"""

__version__ = "1.0.0"
__author__ = "CyberSIEM Security Team"
