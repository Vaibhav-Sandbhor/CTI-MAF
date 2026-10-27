/**
 * Electron Main Process
 * Handles window creation, Python backend spawning, and IPC communication
 */

const { app, BrowserWindow, ipcMain, dialog, Menu } = require("electron");
const path = require("path");
const { spawn } = require("child_process");
const http = require("http");

// Remove default menu bar for clean desktop app look
Menu.setApplicationMenu(null);

// Set application name for OS
app.setName("SentraX");

// Environment detection
const isDev = process.env.NODE_ENV === "development" || !app.isPackaged;

// Process references for cleanup
let pythonBackend = null;
let mainWindow = null;

// Configuration
const CONFIG = {
  BACKEND_PORT: 8000,
  BACKEND_HOST: "127.0.0.1",
  DEV_FRONTEND_URL: "http://localhost:5173",
  BACKEND_START_TIMEOUT: 30000,
  BACKEND_CHECK_INTERVAL: 500,
};

/**
 * Get the correct Python executable based on environment
 */
function getPythonExecutable() {
  const projectRoot = getProjectRoot();

  if (process.platform === "win32") {
    // Try venv first (development)
    const venvPython = path.join(projectRoot, "venv", "Scripts", "python.exe");
    try {
      if (require("fs").existsSync(venvPython)) {
        console.log("[Electron] Using venv Python:", venvPython);
        return venvPython;
      }
    } catch (err) {
      console.warn("[Electron] Could not check venv path:", err.message);
    }
    // Fallback to system Python
    console.log("[Electron] Using system Python");
    return "python";
  }

  // macOS/Linux
  const venvPython = path.join(projectRoot, "venv", "bin", "python3");
  try {
    if (require("fs").existsSync(venvPython)) {
      console.log("[Electron] Using venv Python:", venvPython);
      return venvPython;
    }
  } catch (err) {
    console.warn("[Electron] Could not check venv path:", err.message);
  }
  return "python3";
}

/**
 * Get the project root directory
 */
function getProjectRoot() {
  if (isDev) {
    return path.resolve(__dirname, "..", "..");
  }
  return path.join(process.resourcesPath, "backend");
}

/**
 * Wait for the backend server to be ready
 */
function waitForBackend(timeout = CONFIG.BACKEND_START_TIMEOUT) {
  return new Promise((resolve, reject) => {
    const startTime = Date.now();

    const checkServer = () => {
      const req = http.request(
        {
          hostname: CONFIG.BACKEND_HOST,
          port: CONFIG.BACKEND_PORT,
          path: "/health",
          method: "GET",
          timeout: 2000,
        },
        (res) => {
          if (res.statusCode === 200) {
            resolve(true);
          } else {
            retry();
          }
        }
      );

      req.on("error", () => retry());
      req.on("timeout", () => {
        req.destroy();
        retry();
      });
      req.end();
    };

    const retry = () => {
      if (Date.now() - startTime > timeout) {
        reject(new Error("Backend server failed to start within timeout"));
      } else {
        setTimeout(checkServer, CONFIG.BACKEND_CHECK_INTERVAL);
      }
    };

    checkServer();
  });
}

/**
 * Start the Python FastAPI backend
 */
function startPythonBackend() {
  return new Promise((resolve, reject) => {
    const projectRoot = getProjectRoot();
    const pythonExe = getPythonExecutable();

    // Try to use start_server.py first (handles port conflicts), fall back to api_server.py
    let backendScript = path.join(projectRoot, "start_server.py");
    const fs = require("fs");
    if (!fs.existsSync(backendScript)) {
      console.warn(`[Electron] start_server.py not found, using api_server.py`);
      backendScript = path.join(projectRoot, "api_server.py");
    }

    console.log(`[Electron] ========== BACKEND STARTUP ==========`);
    console.log(`[Electron] App packaged: ${app.isPackaged}`);
    console.log(`[Electron] Is development: ${isDev}`);
    console.log(`[Electron] Project root: ${projectRoot}`);
    console.log(`[Electron] Python executable: ${pythonExe}`);
    console.log(`[Electron] Backend script: ${backendScript}`);

    if (!fs.existsSync(backendScript)) {
      console.error(`[Electron] ERROR: Backend script not found at ${backendScript}`);
      reject(new Error(`Backend script not found`));
      return;
    }

    if (!fs.existsSync(pythonExe)) {
      console.warn(`[Electron] WARNING: Python executable not found at ${pythonExe}`);
    }

    console.log(`[Electron] Starting Python backend...`);

    // Build enhanced PATH with common locations
    let pathValue = process.env.PATH || "";

    // Add common Python locations for Windows
    if (process.platform === "win32") {
      const pythonPaths = [
        "C:\\Program Files\\Python311",
        "C:\\Program Files (x86)\\Python311",
        "C:\\Program Files\\Python310",
        "C:\\Program Files (x86)\\Python310",
        "C:\\Program Files\\Python39",
        "C:\\Program Files (x86)\\Python39",
      ];
      pathValue = [...pythonPaths, pathValue].join(";");
    }

    // Add common Nmap locations
    const nmapPaths = [
      "C:\\Program Files (x86)\\Nmap",
      "C:\\Program Files\\Nmap",
      "C:\\Nmap",
    ];
    pathValue = [...nmapPaths, ...pathValue.split(";")].join(";");

    pythonBackend = spawn(pythonExe, ["-u", backendScript], {
      cwd: projectRoot,
      env: {
        ...process.env,
        PYTHONUNBUFFERED: "1",
        PATH: pathValue,
      },
      stdio: ["pipe", "pipe", "pipe"],
      shell: process.platform === "win32",
    });

    pythonBackend.stdout.on("data", (data) => {
      console.log(`[Backend] ${data.toString().trim()}`);
    });

    pythonBackend.stderr.on("data", (data) => {
      console.error(`[Backend] ${data.toString().trim()}`);
    });

    pythonBackend.on("error", (err) => {
      console.error(`[Electron] Failed to start backend: ${err.message}`);
      console.error(`[Electron] This usually means: Python not found, or invalid python path`);
      reject(err);
    });

    pythonBackend.on("close", (code) => {
      console.log(`[Electron] Backend process exited with code ${code}`);
      pythonBackend = null;
    });

    if (pythonBackend && pythonBackend.pid) {
      console.log(`[Electron] Backend process spawned with PID: ${pythonBackend.pid}`);
    }

    waitForBackend()
      .then(() => {
        console.log(`[Electron] ✅ Backend server is ready on http://${CONFIG.BACKEND_HOST}:${CONFIG.BACKEND_PORT}`);
        console.log(`[Electron] ========== BACKEND READY =========`);
        resolve(true);
      })
      .catch((err) => {
        console.error(`[Electron] ❌ Backend failed to start within ${CONFIG.BACKEND_START_TIMEOUT}ms`);
        reject(err);
      });
  });
}

/**
 * Stop all Python processes
 */
function stopPythonProcesses() {
  if (pythonBackend) {
    console.log("[Electron] Stopping Python backend...");
    if (process.platform === "win32") {
      spawn("taskkill", ["/pid", pythonBackend.pid, "/f", "/t"]);
    } else {
      pythonBackend.kill("SIGTERM");
    }
    pythonBackend = null;
  }
}

/**
 * Create the main application window
 */
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1600,
    height: 1000,
    minWidth: 1200,
    minHeight: 768,
    icon: path.join(__dirname, "../public/icons/icon.ico"),
    title: "SentraX - Cyber Threat Intelligence",
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
      webSecurity: true,
    },
    backgroundColor: "#020617",
    show: false,
  });

  mainWindow.once("ready-to-show", () => {
    mainWindow.show();
  });

  if (isDev) {
    mainWindow.loadURL(CONFIG.DEV_FRONTEND_URL);
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, "..", "dist", "index.html"));
  }

  mainWindow.on("closed", () => {
    mainWindow = null;
  });

  return mainWindow;
}

/**
 * IPC Handlers
 */
function setupIPCHandlers() {
  // Start ransomware scan
  ipcMain.handle("start-ransomware-scan", async (event, mode) => {
    try {
      const endpoint = mode === "system" 
        ? "/api/ransomware/start-scan-system"
        : "/api/ransomware/start-simulation";
      
      const response = await fetch(`http://${CONFIG.BACKEND_HOST}:${CONFIG.BACKEND_PORT}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      return await response.json();
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  // Start honeypot scan
  ipcMain.handle("start-honeypot-scan", async (event, mode) => {
    try {
      const endpoint = mode === "monitor"
        ? "/api/honeypot/start-monitor"
        : "/api/honeypot/start-simulation";
      
      const response = await fetch(`http://${CONFIG.BACKEND_HOST}:${CONFIG.BACKEND_PORT}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      return await response.json();
    } catch (error) {
      return { success: false, error: error.message };
    }
  });

  // Get system info
  ipcMain.handle("get-system-info", async () => {
    return {
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
      electronVersion: process.versions.electron,
      isDev: isDev,
    };
  });

  // Show native dialog
  ipcMain.handle("show-dialog", async (event, options) => {
    return dialog.showMessageBox(mainWindow, options);
  });

  // Check backend status
  ipcMain.handle("check-backend", async () => {
    try {
      await waitForBackend(5000);
      return { running: true };
    } catch {
      return { running: false };
    }
  });

  // Run with elevated privileges (for system scans on Linux)
  ipcMain.handle("run-elevated", async (event, command, args) => {
    if (process.platform === "linux") {
      return new Promise((resolve, reject) => {
        const proc = spawn("pkexec", [command, ...args]);
        proc.on("close", (code) => {
          resolve({ success: code === 0 });
        });
        proc.on("error", (err) => {
          reject(err);
        });
      });
    }
    return { success: false, error: "Elevated execution not supported on this platform" };
  });
}

/**
 * Application lifecycle
 */
app.whenReady().then(async () => {
  console.log("[Electron] App is ready, starting backend...");

  try {
    await startPythonBackend();
    setupIPCHandlers();
    createWindow();

    app.on("activate", () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
      }
    });
  } catch (error) {
    console.error("[Electron] Failed to start application:", error);
    dialog.showErrorBox(
      "Startup Error",
      `Failed to start the application: ${error.message}\n\nMake sure Python and all dependencies are installed.`
    );
    app.quit();
  }
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("before-quit", () => {
  console.log("[Electron] Cleaning up before quit...");
  stopPythonProcesses();
});

process.on("uncaughtException", (error) => {
  console.error("[Electron] Uncaught exception:", error);
  stopPythonProcesses();
});
