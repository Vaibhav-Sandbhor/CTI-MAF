/**
 * Electron Integration Utility
 * 
 * Provides a unified interface for both web and desktop modes.
 * When running in Electron, uses IPC; otherwise falls back to fetch API.
 */

/**
 * Check if running inside Electron
 */
export const isElectron = () => {
  return !!(window.electronAPI && window.electronAPI.isElectron);
};

/**
 * Get platform information
 */
export const getPlatform = () => {
  if (isElectron()) {
    return window.electronAPI.platform;
  }
  return "web";
};

/**
 * Get system information (Electron only)
 */
export const getSystemInfo = async () => {
  if (isElectron()) {
    return await window.electronAPI.getSystemInfo();
  }
  return {
    platform: "web",
    arch: navigator.platform,
    isDev: import.meta.env.DEV,
  };
};

/**
 * Check if backend is running
 */
export const checkBackendStatus = async () => {
  if (isElectron()) {
    return await window.electronAPI.checkBackend();
  }
  
  // Web mode: check via API
  try {
    const response = await fetch("/health");
    return { running: response.ok };
  } catch {
    return { running: false };
  }
};

/**
 * Show native dialog (Electron) or browser alert (web)
 */
export const showDialog = async (options) => {
  if (isElectron()) {
    return await window.electronAPI.showDialog(options);
  }
  
  // Fallback to browser dialog
  const { type, title, message, buttons } = options;
  
  if (type === "error") {
    alert(`${title}\n\n${message}`);
    return { response: 0 };
  }
  
  if (buttons && buttons.length > 0) {
    const confirmed = confirm(`${title}\n\n${message}`);
    return { response: confirmed ? 0 : 1 };
  }
  
  alert(`${title}\n\n${message}`);
  return { response: 0 };
};

/**
 * Subscribe to scan updates (Electron only)
 */
export const onScanUpdate = (callback) => {
  if (isElectron() && window.electronAPI.onScanUpdate) {
    window.electronAPI.onScanUpdate(callback);
    return () => window.electronAPI.removeScanUpdateListener();
  }
  return () => {}; // No-op for web
};

/**
 * Run command with elevated privileges (Linux/Kali only)
 */
export const runElevated = async (command, args = []) => {
  if (isElectron() && window.electronAPI.runElevated) {
    return await window.electronAPI.runElevated(command, args);
  }
  return { success: false, error: "Elevated execution only available in desktop mode" };
};

// Export all utilities
export default {
  isElectron,
  getPlatform,
  getSystemInfo,
  checkBackendStatus,
  showDialog,
  onScanUpdate,
  runElevated,
};
