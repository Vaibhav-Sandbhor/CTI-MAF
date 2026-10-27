import os

print("[*] Ransomware Module Started")

os.system("python3 ransomware_module/main.py")
os.system("python3 ransomware_module/model/train_lstm.py")
os.system("python3 ransomware_module/model/predict_lstm.py")

print("[+] Ransomware Module Completed")
