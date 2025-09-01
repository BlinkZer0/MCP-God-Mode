"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.MCPGodModeDesktop = void 0;
const electron_1 = require("electron");
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const web_server_js_1 = require("../web-server.js");
const defaultDesktopConfig = {
    title: 'MCP God Mode - Ultimate System Management',
    width: 1400,
    height: 900,
    minWidth: 1200,
    minHeight: 800,
    webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
        preload: path.join(__dirname, 'preload.js')
    }
};
// Main process class
class MCPGodModeDesktop {
    mainWindow = null;
    webServer = null;
    config;
    constructor(config = defaultDesktopConfig) {
        this.config = config;
        this.setupApp();
    }
    setupApp() {
        // App event handlers
        electron_1.app.whenReady().then(() => {
            this.createMainWindow();
            this.setupMenu();
            this.setupIPC();
            this.startWebServer();
        });
        electron_1.app.on('window-all-closed', () => {
            if (process.platform !== 'darwin') {
                electron_1.app.quit();
            }
        });
        electron_1.app.on('activate', () => {
            if (electron_1.BrowserWindow.getAllWindows().length === 0) {
                this.createMainWindow();
            }
        });
        electron_1.app.on('before-quit', async () => {
            if (this.webServer) {
                await this.webServer.stop();
            }
        });
    }
    createMainWindow() {
        this.mainWindow = new electron_1.BrowserWindow({
            title: this.config.title,
            width: this.config.width,
            height: this.config.height,
            minWidth: this.config.minWidth,
            minHeight: this.config.minHeight,
            webPreferences: this.config.webPreferences,
            icon: path.join(__dirname, 'assets', 'icon.png'),
            show: false,
            titleBarStyle: 'default',
            autoHideMenuBar: false
        });
        // Load the web app
        this.mainWindow.loadURL('http://localhost:3000');
        // Show window when ready
        this.mainWindow.once('ready-to-show', () => {
            this.mainWindow?.show();
            // Open DevTools in development
            if (process.env.NODE_ENV === 'development') {
                this.mainWindow?.webContents.openDevTools();
            }
        });
        // Handle window closed
        this.mainWindow.on('closed', () => {
            this.mainWindow = null;
        });
        // Handle external links
        this.mainWindow.webContents.setWindowOpenHandler(({ url }) => {
            electron_1.shell.openExternal(url);
            return { action: 'deny' };
        });
    }
    setupMenu() {
        const template = [
            {
                label: 'File',
                submenu: [
                    {
                        label: 'New Workflow',
                        accelerator: 'CmdOrCtrl+N',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'new-workflow');
                        }
                    },
                    {
                        label: 'Open Workflow',
                        accelerator: 'CmdOrCtrl+O',
                        click: async () => {
                            const result = await electron_1.dialog.showOpenDialog(this.mainWindow, {
                                properties: ['openFile'],
                                filters: [
                                    { name: 'Workflow Files', extensions: ['json', 'yaml', 'yml'] },
                                    { name: 'All Files', extensions: ['*'] }
                                ]
                            });
                            if (!result.canceled && result.filePaths.length > 0) {
                                const filePath = result.filePaths[0];
                                const content = fs.readFileSync(filePath, 'utf-8');
                                this.mainWindow?.webContents.send('menu-action', 'open-workflow', { filePath, content });
                            }
                        }
                    },
                    {
                        label: 'Save Workflow',
                        accelerator: 'CmdOrCtrl+S',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'save-workflow');
                        }
                    },
                    { type: 'separator' },
                    {
                        label: 'Import Plugin',
                        click: async () => {
                            const result = await electron_1.dialog.showOpenDialog(this.mainWindow, {
                                properties: ['openDirectory'],
                                title: 'Select Plugin Directory'
                            });
                            if (!result.canceled && result.filePaths.length > 0) {
                                const pluginPath = result.filePaths[0];
                                this.mainWindow?.webContents.send('menu-action', 'import-plugin', { pluginPath });
                            }
                        }
                    },
                    { type: 'separator' },
                    {
                        label: 'Exit',
                        accelerator: process.platform === 'darwin' ? 'Cmd+Q' : 'Ctrl+Q',
                        click: () => {
                            electron_1.app.quit();
                        }
                    }
                ]
            },
            {
                label: 'Edit',
                submenu: [
                    { role: 'undo' },
                    { role: 'redo' },
                    { type: 'separator' },
                    { role: 'cut' },
                    { role: 'copy' },
                    { role: 'paste' },
                    { role: 'selectAll' }
                ]
            },
            {
                label: 'View',
                submenu: [
                    { role: 'reload' },
                    { role: 'forceReload' },
                    { role: 'toggleDevTools' },
                    { type: 'separator' },
                    { role: 'resetZoom' },
                    { role: 'zoomIn' },
                    { role: 'zoomOut' },
                    { type: 'separator' },
                    { role: 'togglefullscreen' }
                ]
            },
            {
                label: 'Workflow',
                submenu: [
                    {
                        label: 'Create New',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'create-workflow');
                        }
                    },
                    {
                        label: 'Import from File',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'import-workflow');
                        }
                    },
                    {
                        label: 'Export to File',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'export-workflow');
                        }
                    },
                    { type: 'separator' },
                    {
                        label: 'Schedule Task',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'schedule-task');
                        }
                    },
                    {
                        label: 'View Executions',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'view-executions');
                        }
                    }
                ]
            },
            {
                label: 'Monitoring',
                submenu: [
                    {
                        label: 'System Dashboard',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'show-dashboard');
                        }
                    },
                    {
                        label: 'Performance Metrics',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'show-metrics');
                        }
                    },
                    {
                        label: 'System Alerts',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'show-alerts');
                        }
                    },
                    {
                        label: 'Performance Baselines',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'show-baselines');
                        }
                    }
                ]
            },
            {
                label: 'Plugins',
                submenu: [
                    {
                        label: 'Plugin Manager',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'show-plugin-manager');
                        }
                    },
                    {
                        label: 'Install Plugin',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'install-plugin');
                        }
                    },
                    {
                        label: 'Plugin Marketplace',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'show-marketplace');
                        }
                    },
                    {
                        label: 'Plugin Settings',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'show-plugin-settings');
                        }
                    }
                ]
            },
            {
                label: 'Tools',
                submenu: [
                    {
                        label: 'VM Management',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'show-vm-management');
                        }
                    },
                    {
                        label: 'Docker Management',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'show-docker-management');
                        }
                    },
                    {
                        label: 'System Tools',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'show-system-tools');
                        }
                    },
                    {
                        label: 'Network Tools',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'show-network-tools');
                        }
                    }
                ]
            },
            {
                label: 'Help',
                submenu: [
                    {
                        label: 'Documentation',
                        click: () => {
                            electron_1.shell.openExternal('https://github.com/your-repo/mcp-god-mode/docs');
                        }
                    },
                    {
                        label: 'API Reference',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'show-api-reference');
                        }
                    },
                    {
                        label: 'Examples',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'show-examples');
                        }
                    },
                    { type: 'separator' },
                    {
                        label: 'Check for Updates',
                        click: () => {
                            this.mainWindow?.webContents.send('menu-action', 'check-updates');
                        }
                    },
                    {
                        label: 'About',
                        click: () => {
                            this.showAboutDialog();
                        }
                    }
                ]
            }
        ];
        // Platform-specific menu adjustments
        if (process.platform === 'darwin') {
            template.unshift({
                label: electron_1.app.getName(),
                submenu: [
                    { role: 'about' },
                    { type: 'separator' },
                    { role: 'services' },
                    { type: 'separator' },
                    { role: 'hide' },
                    { role: 'hideOthers' },
                    { role: 'unhide' },
                    { type: 'separator' },
                    { role: 'quit' }
                ]
            });
        }
        const menu = electron_1.Menu.buildFromTemplate(template);
        electron_1.Menu.setApplicationMenu(menu);
    }
    setupIPC() {
        // System information
        electron_1.ipcMain.handle('get-system-info', () => {
            return {
                platform: process.platform,
                arch: process.arch,
                nodeVersion: process.version,
                electronVersion: process.versions.electron,
                chromeVersion: process.versions.chrome,
                appVersion: electron_1.app.getVersion()
            };
        });
        // File operations
        electron_1.ipcMain.handle('save-file', async (event, options) => {
            const result = await electron_1.dialog.showSaveDialog(this.mainWindow, {
                defaultPath: options.defaultPath || 'workflow.json',
                filters: options.filters || [
                    { name: 'JSON Files', extensions: ['json'] },
                    { name: 'YAML Files', extensions: ['yaml', 'yml'] },
                    { name: 'All Files', extensions: ['*'] }
                ]
            });
            if (!result.canceled && result.filePath) {
                fs.writeFileSync(result.filePath, options.content);
                return { success: true, filePath: result.filePath };
            }
            return { success: false };
        });
        electron_1.ipcMain.handle('open-file', async (event, options) => {
            const result = await electron_1.dialog.showOpenDialog(this.mainWindow, {
                filters: options.filters || [
                    { name: 'All Files', extensions: ['*'] }
                ],
                properties: options.properties || ['openFile']
            });
            if (!result.canceled && result.filePaths.length > 0) {
                const filePath = result.filePaths[0];
                const content = fs.readFileSync(filePath, 'utf-8');
                return { success: true, filePath, content };
            }
            return { success: false };
        });
        // Directory operations
        electron_1.ipcMain.handle('select-directory', async (event, options) => {
            const result = await electron_1.dialog.showOpenDialog(this.mainWindow, {
                properties: ['openDirectory'],
                title: options.title || 'Select Directory'
            });
            if (!result.canceled && result.filePaths.length > 0) {
                return { success: true, directoryPath: result.filePaths[0] };
            }
            return { success: false };
        });
        // Web server control
        electron_1.ipcMain.handle('start-web-server', async (event, config) => {
            try {
                if (this.webServer) {
                    await this.webServer.stop();
                }
                this.webServer = new web_server_js_1.WebServer(config);
                await this.webServer.start();
                return { success: true, message: 'Web server started successfully' };
            }
            catch (error) {
                return { success: false, error: error instanceof Error ? error.message : String(error) };
            }
        });
        electron_1.ipcMain.handle('stop-web-server', async () => {
            try {
                if (this.webServer) {
                    await this.webServer.stop();
                    this.webServer = null;
                }
                return { success: true, message: 'Web server stopped successfully' };
            }
            catch (error) {
                return { success: false, error: error instanceof Error ? error.message : String(error) };
            }
        });
        electron_1.ipcMain.handle('get-web-server-status', () => {
            return {
                running: this.webServer !== null,
                port: this.webServer ? 3000 : null
            };
        });
        // System operations
        electron_1.ipcMain.handle('execute-system-command', async (event, command) => {
            try {
                const { exec } = require('child_process');
                const { promisify } = require('util');
                const execAsync = promisify(exec);
                const { stdout, stderr } = await execAsync(command);
                return { success: true, stdout, stderr };
            }
            catch (error) {
                return { success: false, error: error instanceof Error ? error.message : String(error) };
            }
        });
        // Notification
        electron_1.ipcMain.handle('show-notification', (event, options) => {
            const notification = new (require('electron').Notification)(options);
            notification.show();
            return { success: true };
        });
        // Window management
        electron_1.ipcMain.handle('minimize-window', () => {
            this.mainWindow?.minimize();
            return { success: true };
        });
        electron_1.ipcMain.handle('maximize-window', () => {
            if (this.mainWindow?.isMaximized()) {
                this.mainWindow.unmaximize();
            }
            else {
                this.mainWindow?.maximize();
            }
            return { success: true };
        });
        electron_1.ipcMain.handle('close-window', () => {
            this.mainWindow?.close();
            return { success: true };
        });
    }
    async startWebServer() {
        try {
            this.webServer = new web_server_js_1.WebServer({
                port: 3000,
                host: 'localhost',
                enableCors: true,
                corsOrigin: ['http://localhost:3000'],
                enableCompression: true,
                enableLogging: true,
                staticPath: './public',
                apiPrefix: '/api/v1'
            });
            await this.webServer.start();
            console.log('Web server started for desktop app');
        }
        catch (error) {
            console.error('Failed to start web server for desktop app:', error);
        }
    }
    showAboutDialog() {
        electron_1.dialog.showMessageBox(this.mainWindow, {
            type: 'info',
            title: 'About MCP God Mode',
            message: 'MCP God Mode - Ultimate System Management',
            detail: `Version: ${electron_1.app.getVersion()}\n\nA comprehensive system management platform with VM management, Docker support, monitoring, automation, and more.\n\nBuilt with Electron and Node.js`,
            buttons: ['OK']
        });
    }
}
exports.MCPGodModeDesktop = MCPGodModeDesktop;
// Start the desktop app
const desktopApp = new MCPGodModeDesktop();
