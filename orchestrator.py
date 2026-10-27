#!/usr/bin/env python3
"""
CyberSIEM Orchestrator
Coordinates the startup and management of all security scanning agents.

This script is called by Electron's main process to start all agents
in parallel for comprehensive threat detection.

Usage:
    python orchestrator.py [all|ransomware|honeypot|portscan]
"""

import sys
import subprocess
import time
import signal
import logging
from pathlib import Path
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[Orchestrator] %(asctime)s - %(levelname)s - %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# Project root directory
PROJECT_ROOT = Path(__file__).parent

# Agent configurations
AGENTS: Dict[str, Dict] = {
    "ransomware": {
        "name": "Ransomware Detection Agent",
        "script": PROJECT_ROOT / "ransomware_module" / "scripts" / "run_ransomware_scan.py",
        "fallback": None,  # Will use API endpoint instead
        "enabled": True,
    },
    "honeypot": {
        "name": "Honeypot Monitoring Agent",
        "script": PROJECT_ROOT / "honeypot" / "honeypot_monitor.py",
        "fallback": None,
        "enabled": True,
    },
    "portscan": {
        "name": "Port Scanning Agent",
        "script": PROJECT_ROOT / "portscan_module" / "run_portscan.py",
        "fallback": None,
        "enabled": True,
    },
}

# Global process list for cleanup
running_processes: List[subprocess.Popen] = []
shutdown_requested = False


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global shutdown_requested
    logger.info("Shutdown signal received, stopping all agents...")
    shutdown_requested = True
    stop_all_agents()
    sys.exit(0)


def stop_all_agents():
    """Stop all running agent processes."""
    for proc in running_processes:
        if proc.poll() is None:  # Process is still running
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            except Exception as e:
                logger.error(f"Error stopping process: {e}")
    running_processes.clear()


def start_agent(agent_id: str, agent_config: Dict) -> Optional[subprocess.Popen]:
    """
    Start a single agent process.
    
    Args:
        agent_id: Identifier for the agent
        agent_config: Configuration dictionary for the agent
    
    Returns:
        Popen object if started successfully, None otherwise
    """
    if not agent_config.get("enabled", True):
        logger.info(f"⏭️  {agent_config['name']} is disabled, skipping")
        return None

    script_path = agent_config.get("script")
    
    # Check if script exists
    if script_path and not Path(script_path).exists():
        logger.warning(f"⚠️  Script not found: {script_path}")
        logger.info(f"   {agent_config['name']} will use API endpoints instead")
        return None

    try:
        logger.info(f"🚀 Starting {agent_config['name']}...")
        
        # Determine Python executable
        python_exe = sys.executable
        
        proc = subprocess.Popen(
            [python_exe, "-u", str(script_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(PROJECT_ROOT),
            env={**dict(__import__('os').environ), "PYTHONUNBUFFERED": "1"},
        )
        
        running_processes.append(proc)
        logger.info(f"✅ {agent_config['name']} started (PID: {proc.pid})")
        return proc
        
    except Exception as e:
        logger.error(f"❌ Failed to start {agent_config['name']}: {e}")
        return None


def monitor_agents(processes: List[subprocess.Popen], timeout: int = None):
    """
    Monitor running agents and log their output.
    
    Args:
        processes: List of running agent processes
        timeout: Optional timeout in seconds
    """
    start_time = time.time()
    
    while processes and not shutdown_requested:
        for proc in processes[:]:  # Iterate over copy
            # Check if process has output
            if proc.poll() is not None:
                # Process has exited
                stdout, stderr = proc.communicate()
                if stdout:
                    logger.info(f"Agent output: {stdout.decode().strip()}")
                if stderr:
                    logger.warning(f"Agent error: {stderr.decode().strip()}")
                processes.remove(proc)
        
        # Check timeout
        if timeout and (time.time() - start_time) > timeout:
            logger.info("Monitoring timeout reached")
            break
        
        time.sleep(0.5)


def run_orchestrator(scan_types: List[str] = None):
    """
    Main orchestrator function.
    
    Args:
        scan_types: List of scan types to run. If None or ["all"], runs all agents.
    """
    logger.info("=" * 60)
    logger.info("CyberSIEM Agent Orchestrator Starting")
    logger.info("=" * 60)
    
    # Determine which agents to start
    if not scan_types or "all" in scan_types:
        agents_to_start = list(AGENTS.keys())
    else:
        agents_to_start = [st for st in scan_types if st in AGENTS]
    
    if not agents_to_start:
        logger.error("No valid scan types specified")
        return
    
    logger.info(f"Starting agents: {', '.join(agents_to_start)}")
    
    # Start agents in parallel
    started_processes = []
    with ThreadPoolExecutor(max_workers=len(agents_to_start)) as executor:
        futures = {
            executor.submit(start_agent, agent_id, AGENTS[agent_id]): agent_id
            for agent_id in agents_to_start
        }
        
        for future in as_completed(futures):
            agent_id = futures[future]
            try:
                proc = future.result()
                if proc:
                    started_processes.append(proc)
            except Exception as e:
                logger.error(f"Error starting {agent_id}: {e}")
    
    if not started_processes:
        logger.info("No agent scripts found. The system will use API endpoints for scanning.")
        logger.info("Agents are managed by the FastAPI backend.")
        return
    
    logger.info(f"Started {len(started_processes)} agents")
    
    # Monitor agents
    try:
        monitor_agents(started_processes)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        stop_all_agents()
    
    logger.info("Orchestrator finished")


if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Parse command line arguments
    scan_types = sys.argv[1:] if len(sys.argv) > 1 else ["all"]
    
    # Run orchestrator
    run_orchestrator(scan_types)
