#!/usr/bin/env python3
"""
Start script for CyberSIEM API Server (Electron wrapper)

This script is called by Electron instead of directly running api_server.py
to prevent duplicate server startup issues.
"""

import sys
import socket
import time

def is_port_in_use(port=8000, host="127.0.0.1"):
    """Check if a port is already in use"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            return result == 0
    except Exception as e:
        print(f"[Warning] Could not check port: {e}")
        return False

def main():
    import uvicorn
    from api_server import app

    HOST = "127.0.0.1"
    PORT = 8000

    print("=" * 60)
    print("[Electron] CyberSIEM API Server Starting...")
    print("=" * 60)
    print(f"   Host: {HOST}")
    print(f"   Port: {PORT}")
    print(f"   Docs: http://{HOST}:{PORT}/docs")
    print(f"   Health: http://{HOST}:{PORT}/health")
    print("=" * 60)

    # Check if port is already in use
    if is_port_in_use(PORT, HOST):
        print(f"\n⚠️  [Warning] Port {PORT} is already in use!")
        print("[Electron] Waiting for current process to finish...")
        for i in range(10):
            if not is_port_in_use(PORT, HOST):
                print(f"✅ Port {PORT} is now available")
                break
            print(f"[Electron] Waiting... ({i + 1}/10)")
            time.sleep(1)
        else:
            print(f"❌ [ERROR] Port {PORT} is still in use after timeout!")
            print("[Electron] Backend cannot start.")
            sys.exit(1)

    try:
        print("[Electron] Starting uvicorn server...\n")
        uvicorn.run(
            app,
            host=HOST,
            port=PORT,
            log_level="info",
            reload=False,  # Disable reload for stability with Electron
        )
    except Exception as e:
        print(f"\n❌ [ERROR] Failed to start server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
