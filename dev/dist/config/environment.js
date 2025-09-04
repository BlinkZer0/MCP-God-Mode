import * as os from "node:os";
// Cross-platform OS detection
export const PLATFORM = os.platform();
export const IS_WINDOWS = PLATFORM === "win32";
export const IS_LINUX = PLATFORM === "linux";
export const IS_MACOS = PLATFORM === "darwin";
// Mobile platform detection
export const IS_MOBILE = process.env.MOBILE_PLATFORM === "true" || process.env.REACT_NATIVE === "true";
export const IS_ANDROID = process.env.ANDROID === "true" || process.env.PLATFORM === "android";
export const IS_IOS = process.env.IOS === "true" || process.env.PLATFORM === "ios";
export const IS_MOBILE_WEB = process.env.MOBILE_WEB === "true" || process.env.PLATFORM === "mobile-web";
// Mobile-specific configurations
export const MOBILE_CONFIG = {
    enableNativeFeatures: IS_ANDROID || IS_IOS,
    enableWebFallbacks: IS_MOBILE_WEB || (!IS_ANDROID && !IS_IOS),
    maxFileSize: IS_MOBILE ? 50 * 1024 * 1024 : 100 * 1024 * 1024, // 50MB on mobile, 100MB on desktop
    enableCamera: IS_ANDROID || IS_IOS,
    enableLocation: IS_ANDROID || IS_IOS,
    enableNotifications: IS_ANDROID || IS_IOS,
    enableBiometrics: IS_ANDROID || IS_IOS,
    enableBluetooth: IS_ANDROID || IS_IOS,
    enableNFC: IS_ANDROID || IS_IOS,
    enableSensors: IS_ANDROID || IS_IOS
};
// Environment configuration validation
export const config = {
    allowedRoot: process.env.ALLOWED_ROOT || "",
    webAllowlist: process.env.WEB_ALLOWLIST || "",
    procAllowlist: process.env.PROC_ALLOWLIST || "",
    extraPath: process.env.EXTRA_PATH || "",
    logLevel: process.env.LOG_LEVEL || "info",
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE || String(MOBILE_CONFIG.maxFileSize)),
    timeout: parseInt(process.env.COMMAND_TIMEOUT || "30000"),
    enableSecurityChecks: process.env.ENABLE_SECURITY_CHECKS !== "false",
    mobilePlatform: IS_MOBILE ? (IS_ANDROID ? "android" : IS_IOS ? "ios" : "mobile-web") : "desktop"
};
// Universal access - allow all drives and paths
export const ALLOWED_ROOTS = config.allowedRoot
    ? config.allowedRoot.split(",").map(s => s.trim()).filter(Boolean)
    : [];
export const MAX_BYTES = config.maxFileSize;
export const WEB_ALLOWLIST = []; // Empty array means no restrictions
export const PROC_ALLOWLIST_RAW = config.procAllowlist;
export const PROC_ALLOWLIST = PROC_ALLOWLIST_RAW === "" ? [] : PROC_ALLOWLIST_RAW.split(",").map(s => s.trim()).filter(Boolean);
// Mobile-specific paths and permissions
export const MOBILE_PATHS = {
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
export const COMMAND_MAPPINGS = {
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
