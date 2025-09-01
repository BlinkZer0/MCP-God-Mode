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
exports.COMMAND_MAPPINGS = exports.MOBILE_PATHS = exports.PROC_ALLOWLIST = exports.PROC_ALLOWLIST_RAW = exports.WEB_ALLOWLIST = exports.MAX_BYTES = exports.ALLOWED_ROOTS = exports.config = exports.MOBILE_CONFIG = exports.IS_MOBILE_WEB = exports.IS_IOS = exports.IS_ANDROID = exports.IS_MOBILE = exports.IS_MACOS = exports.IS_LINUX = exports.IS_WINDOWS = exports.PLATFORM = void 0;
const os = __importStar(require("node:os"));
// Cross-platform OS detection
exports.PLATFORM = os.platform();
exports.IS_WINDOWS = exports.PLATFORM === "win32";
exports.IS_LINUX = exports.PLATFORM === "linux";
exports.IS_MACOS = exports.PLATFORM === "darwin";
// Mobile platform detection
exports.IS_MOBILE = process.env.MOBILE_PLATFORM === "true" || process.env.REACT_NATIVE === "true";
exports.IS_ANDROID = process.env.ANDROID === "true" || process.env.PLATFORM === "android";
exports.IS_IOS = process.env.IOS === "true" || process.env.PLATFORM === "ios";
exports.IS_MOBILE_WEB = process.env.MOBILE_WEB === "true" || process.env.PLATFORM === "mobile-web";
// Mobile-specific configurations
exports.MOBILE_CONFIG = {
    enableNativeFeatures: exports.IS_ANDROID || exports.IS_IOS,
    enableWebFallbacks: exports.IS_MOBILE_WEB || (!exports.IS_ANDROID && !exports.IS_IOS),
    maxFileSize: exports.IS_MOBILE ? 50 * 1024 * 1024 : 100 * 1024 * 1024, // 50MB on mobile, 100MB on desktop
    enableCamera: exports.IS_ANDROID || exports.IS_IOS,
    enableLocation: exports.IS_ANDROID || exports.IS_IOS,
    enableNotifications: exports.IS_ANDROID || exports.IS_IOS,
    enableBiometrics: exports.IS_ANDROID || exports.IS_IOS,
    enableBluetooth: exports.IS_ANDROID || exports.IS_IOS,
    enableNFC: exports.IS_ANDROID || exports.IS_IOS,
    enableSensors: exports.IS_ANDROID || exports.IS_IOS
};
// Environment configuration validation
exports.config = {
    allowedRoot: process.env.ALLOWED_ROOT || "",
    webAllowlist: process.env.WEB_ALLOWLIST || "",
    procAllowlist: process.env.PROC_ALLOWLIST || "",
    extraPath: process.env.EXTRA_PATH || "",
    logLevel: process.env.LOG_LEVEL || "info",
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE || String(exports.MOBILE_CONFIG.maxFileSize)),
    timeout: parseInt(process.env.COMMAND_TIMEOUT || "30000"),
    enableSecurityChecks: process.env.ENABLE_SECURITY_CHECKS !== "false",
    mobilePlatform: exports.IS_MOBILE ? (exports.IS_ANDROID ? "android" : exports.IS_IOS ? "ios" : "mobile-web") : "desktop"
};
// Universal access - allow all drives and paths
exports.ALLOWED_ROOTS = exports.config.allowedRoot
    ? exports.config.allowedRoot.split(",").map(s => s.trim()).filter(Boolean)
    : [];
exports.MAX_BYTES = exports.config.maxFileSize;
exports.WEB_ALLOWLIST = []; // Empty array means no restrictions
exports.PROC_ALLOWLIST_RAW = exports.config.procAllowlist;
exports.PROC_ALLOWLIST = exports.PROC_ALLOWLIST_RAW === "" ? [] : exports.PROC_ALLOWLIST_RAW.split(",").map(s => s.trim()).filter(Boolean);
// Mobile-specific paths and permissions
exports.MOBILE_PATHS = {
    android: {
        internal: "/data/data",
        external: "/storage/emulated/0",
        downloads: "/storage/emulated/0/Download",
        pictures: "/storage/emulated/0/Pictures",
        documents: "/storage/emulated/0/Documents"
    },
    ios: {
        documents: "/var/mobile/Containers/Data/Application",
        downloads: "/var/mobile/Containers/Data/Application",
        pictures: "/var/mobile/Containers/Data/Application",
        shared: "/var/mobile/Containers/Shared/AppGroup"
    }
};
// Cross-platform command mappings
exports.COMMAND_MAPPINGS = {
    android: {
        fileManager: "am start -a android.intent.action.VIEW -d file://",
        packageManager: "pm",
        systemSettings: "am start -a android.settings.APPLICATION_DETAILS_SETTINGS",
        processManager: "ps",
        serviceManager: "dumpsys",
        networkManager: "ip",
        storageManager: "df",
        userManager: "pm list-users"
    },
    ios: {
        fileManager: "open",
        packageManager: "dpkg",
        systemSettings: "open -a Settings",
        processManager: "ps",
        serviceManager: "launchctl",
        networkManager: "ifconfig",
        storageManager: "df",
        userManager: "dscl . -list /Users"
    },
    windows: {
        fileManager: "explorer",
        packageManager: "winget",
        systemSettings: "ms-settings:",
        processManager: "tasklist",
        serviceManager: "sc",
        networkManager: "ipconfig",
        storageManager: "wmic logicaldisk",
        userManager: "net user"
    },
    linux: {
        fileManager: "xdg-open",
        packageManager: "apt",
        systemSettings: "gnome-control-center",
        processManager: "ps",
        serviceManager: "systemctl",
        networkManager: "ip",
        storageManager: "df",
        userManager: "cat /etc/passwd"
    },
    macos: {
        fileManager: "open",
        packageManager: "brew",
        systemSettings: "open -a System\\ Preferences",
        processManager: "ps",
        serviceManager: "launchctl",
        networkManager: "ifconfig",
        storageManager: "df",
        userManager: "dscl . -list /Users"
    }
};
