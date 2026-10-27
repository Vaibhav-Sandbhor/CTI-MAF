/**
 * Electron Preload Script
 * Securely exposes APIs from main process to renderer
 * 
 * SECURITY: contextIsolation=true, nodeIntegration=false
 */

const { contextBridge, ipcRenderer } = require("electron");

/**
 * Expose safe APIs to the renderer process
 * These are available via window.electronAPI in React
 */
contextBridge.exposeInMainWorld("electronAPI", {
  // ─────────────────────────────────────────────────────────────────────────
  // Scan Control
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Start ransomware scan
   * @param {string} mode - "simulation" or "system"
   */
  startRansomwareScan: (mode) => ipcRenderer.invoke("start-ransomware-scan", mode),

  /**
   * Start honeypot scan
   * @param {string} mode - "simulation" or "monitor"
   */
  startHoneypotScan: (mode) => ipcRenderer.invoke("start-honeypot-scan", mode),

  // ─────────────────────────────────────────────────────────────────────────
  // System Info
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Get system information
   */
  getSystemInfo: () => ipcRenderer.invoke("get-system-info"),

  /**
   * Check if backend is running
   */
  checkBackend: () => ipcRenderer.invoke("check-backend"),

  // ─────────────────────────────────────────────────────────────────────────
  // Native Dialogs
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Show native message dialog
   * @param {Object} options - Dialog options
   */
  showDialog: (options) => ipcRenderer.invoke("show-dialog", options),

  // ─────────────────────────────────────────────────────────────────────────
  // Elevated Execution (Linux/Kali)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Run command with elevated privileges
   * @param {string} command - Command to run
   * @param {string[]} args - Command arguments
   */
  runElevated: (command, args) => ipcRenderer.invoke("run-elevated", command, args),

  // ─────────────────────────────────────────────────────────────────────────
  // Event Listeners
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Listen for scan updates from main process
   * @param {Function} callback - Callback function
   */
  onScanUpdate: (callback) => {
    ipcRenderer.on("scan-update", (event, data) => callback(data));
  },

  /**
   * Remove scan update listener
   */
  removeScanUpdateListener: () => {
    ipcRenderer.removeAllListeners("scan-update");
  },

  // ─────────────────────────────────────────────────────────────────────────
  // Platform Detection
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Check if running in Electron
   */
  isElectron: true,

  /**
   * Get platform info
   */
  platform: process.platform,
});

// Notify that preload is ready
console.log("[Preload] electronAPI exposed to renderer");
