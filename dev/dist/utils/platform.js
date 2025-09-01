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
exports.ALLOWED_ROOTS_ARRAY = void 0;
exports.getRootPaths = getRootPaths;
exports.getPlatformCommand = getPlatformCommand;
exports.getMobilePermissions = getMobilePermissions;
exports.isMobileFeatureAvailable = isMobileFeatureAvailable;
exports.getMobileDeviceInfo = getMobileDeviceInfo;
exports.getFileOperationCommand = getFileOperationCommand;
exports.getMobileProcessCommand = getMobileProcessCommand;
exports.getMobileServiceCommand = getMobileServiceCommand;
exports.getMobileNetworkCommand = getMobileNetworkCommand;
exports.getMobileStorageCommand = getMobileStorageCommand;
exports.getMobileUserCommand = getMobileUserCommand;
const os = __importStar(require("node:os"));
const fsSync = __importStar(require("node:fs"));
const environment_js_1 = require("../config/environment.js");
// Cross-platform utility functions
function getRootPaths() {
    if (environment_js_1.IS_MOBILE) {
        return getMobileRootPaths();
    }
    else if (environment_js_1.IS_WINDOWS) {
        // Get all available drives on Windows
        const drives = [];
        try {
            for (let i = 65; i <= 90; i++) { // ASCII A-Z
                const driveLetter = String.fromCharCode(i) + ":\\";
                try {
                    const stats = fsSync.statSync(driveLetter);
                    if (stats.isDirectory()) {
                        drives.push(driveLetter);
                    }
                }
                catch {
                    // Drive doesn't exist or isn't accessible, skip it
                }
            }
        }
        catch (error) {
            // Could not enumerate drives
        }
        return drives;
    }
    else {
        // Unix-like systems: allow root and home directory
        return ["/", os.homedir()];
    }
}
// Mobile-specific root path handling
function getMobileRootPaths() {
    if (environment_js_1.IS_ANDROID) {
        return [
            environment_js_1.MOBILE_PATHS.android.external,
            environment_js_1.MOBILE_PATHS.android.downloads,
            environment_js_1.MOBILE_PATHS.android.pictures,
            environment_js_1.MOBILE_PATHS.android.documents
        ];
    }
    else if (environment_js_1.IS_IOS) {
        return [
            environment_js_1.MOBILE_PATHS.ios.documents,
            environment_js_1.MOBILE_PATHS.ios.downloads,
            environment_js_1.MOBILE_PATHS.ios.pictures,
            environment_js_1.MOBILE_PATHS.ios.shared
        ];
    }
    return [process.cwd()];
}
// Get platform-specific command for a given operation
function getPlatformCommand(operation) {
    if (environment_js_1.IS_ANDROID) {
        return environment_js_1.COMMAND_MAPPINGS.android[operation];
    }
    else if (environment_js_1.IS_IOS) {
        return environment_js_1.COMMAND_MAPPINGS.ios[operation];
    }
    else if (environment_js_1.IS_WINDOWS) {
        return environment_js_1.COMMAND_MAPPINGS.windows[operation];
    }
    else if (environment_js_1.IS_LINUX) {
        return environment_js_1.COMMAND_MAPPINGS.linux[operation];
    }
    else if (environment_js_1.IS_MACOS) {
        return environment_js_1.COMMAND_MAPPINGS.macos[operation];
    }
    return "";
}
// Mobile-specific utility functions
function getMobilePermissions() {
    if (environment_js_1.IS_ANDROID) {
        return [
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.SEND_SMS",
            "android.permission.CALL_PHONE"
        ];
    }
    else if (environment_js_1.IS_IOS) {
        return [
            "NSCameraUsageDescription",
            "NSLocationWhenInUseUsageDescription",
            "NSLocationAlwaysAndWhenInUseUsageDescription",
            "NSMicrophoneUsageDescription",
            "NSContactsUsageDescription",
            "NSCalendarsUsageDescription",
            "NSPhotoLibraryUsageDescription",
            "NSBluetoothAlwaysUsageDescription",
            "NSFaceIDUsageDescription"
        ];
    }
    return [];
}
// Check if mobile feature is available
function isMobileFeatureAvailable(feature) {
    if (!environment_js_1.IS_MOBILE)
        return false;
    switch (feature) {
        case "camera":
            return environment_js_1.IS_ANDROID || environment_js_1.IS_IOS;
        case "location":
            return environment_js_1.IS_ANDROID || environment_js_1.IS_IOS;
        case "biometrics":
            return environment_js_1.IS_ANDROID || environment_js_1.IS_IOS;
        case "bluetooth":
            return environment_js_1.IS_ANDROID || environment_js_1.IS_IOS;
        case "nfc":
            return environment_js_1.IS_ANDROID || environment_js_1.IS_IOS;
        case "sensors":
            return environment_js_1.IS_ANDROID || environment_js_1.IS_IOS;
        case "notifications":
            return environment_js_1.IS_ANDROID || environment_js_1.IS_IOS;
        default:
            return false;
    }
}
// Get mobile device info
function getMobileDeviceInfo() {
    if (!environment_js_1.IS_MOBILE)
        return null;
    return {
        platform: environment_js_1.IS_ANDROID ? "android" : environment_js_1.IS_IOS ? "ios" : "mobile-web",
        version: process.version,
        arch: os.arch(),
        cpus: os.cpus().length,
        memory: os.totalmem(),
        hostname: os.hostname(),
        userInfo: os.userInfo(),
        availablePaths: getMobileRootPaths(),
        permissions: getMobilePermissions()
    };
}
// Cross-platform file operations with mobile support
function getFileOperationCommand(operation, source, destination) {
    if (environment_js_1.IS_MOBILE) {
        return getMobileFileOperationCommand(operation, source, destination);
    }
    else if (environment_js_1.IS_WINDOWS) {
        return getWindowsFileOperationCommand(operation, source, destination);
    }
    else {
        return getUnixFileOperationCommand(operation, source, destination);
    }
}
function getMobileFileOperationCommand(operation, source, destination) {
    if (environment_js_1.IS_ANDROID) {
        switch (operation) {
            case "copy":
                return `cp "${source}" "${destination}"`;
            case "move":
                return `mv "${source}" "${destination}"`;
            case "delete":
                return `rm "${source}"`;
            case "list":
                return `ls -la "${source}"`;
            default:
                return `ls "${source}"`;
        }
    }
    else if (environment_js_1.IS_IOS) {
        switch (operation) {
            case "copy":
                return `cp "${source}" "${destination}"`;
            case "move":
                return `mv "${source}" "${destination}"`;
            case "delete":
                return `rm "${source}"`;
            case "list":
                return `ls -la "${source}"`;
            default:
                return `ls "${source}"`;
        }
    }
    return "";
}
function getWindowsFileOperationCommand(operation, source, destination) {
    switch (operation) {
        case "copy":
            return `copy "${source}" "${destination}"`;
        case "move":
            return `move "${source}" "${destination}"`;
        case "delete":
            return `del "${source}"`;
        case "list":
            return `dir "${source}"`;
        default:
            return `dir "${source}"`;
    }
}
function getUnixFileOperationCommand(operation, source, destination) {
    switch (operation) {
        case "copy":
            return `cp "${source}" "${destination}"`;
        case "move":
            return `mv "${source}" "${destination}"`;
        case "delete":
            return `rm "${source}"`;
        case "list":
            return `ls -la "${source}"`;
        default:
            return `ls "${source}"`;
    }
}
// Mobile-specific process management
function getMobileProcessCommand(operation, filter) {
    if (environment_js_1.IS_ANDROID) {
        switch (operation) {
            case "list":
                return filter ? `ps | grep "${filter}"` : "ps";
            case "kill":
                return `kill -9 ${filter}`;
            case "info":
                return `ps -p ${filter}`;
            default:
                return "ps";
        }
    }
    else if (environment_js_1.IS_IOS) {
        switch (operation) {
            case "list":
                return filter ? `ps aux | grep "${filter}"` : "ps aux";
            case "kill":
                return `kill -9 ${filter}`;
            case "info":
                return `ps -p ${filter}`;
            default:
                return "ps aux";
        }
    }
    return "";
}
// Mobile-specific service management
function getMobileServiceCommand(operation, service) {
    if (environment_js_1.IS_ANDROID) {
        switch (operation) {
            case "list":
                return service ? `dumpsys ${service}` : "dumpsys";
            case "start":
                return `am startservice ${service}`;
            case "stop":
                return `am stopservice ${service}`;
            case "status":
                return `dumpsys ${service}`;
            default:
                return "dumpsys";
        }
    }
    else if (environment_js_1.IS_IOS) {
        switch (operation) {
            case "list":
                return "launchctl list";
            case "start":
                return `launchctl start ${service}`;
            case "stop":
                return `launchctl stop ${service}`;
            case "status":
                return `launchctl list | grep ${service}`;
            default:
                return "launchctl list";
        }
    }
    return "";
}
// Mobile-specific network management
function getMobileNetworkCommand(operation, networkInterface) {
    if (environment_js_1.IS_ANDROID) {
        switch (operation) {
            case "interfaces":
                return "ip addr show";
            case "status":
                return networkInterface ? `ip addr show ${networkInterface}` : "ip addr show";
            case "config":
                return "ip route show";
            case "dns":
                return "cat /etc/resolv.conf";
            default:
                return "ip addr show";
        }
    }
    else if (environment_js_1.IS_IOS) {
        switch (operation) {
            case "interfaces":
                return "ifconfig";
            case "status":
                return networkInterface ? `ifconfig ${networkInterface}` : "ifconfig";
            case "config":
                return "netstat -rn";
            case "dns":
                return "cat /etc/resolv.conf";
            default:
                return "ifconfig";
        }
    }
    return "";
}
// Mobile-specific storage management
function getMobileStorageCommand(operation, path) {
    if (environment_js_1.IS_ANDROID) {
        switch (operation) {
            case "usage":
                return path ? `df -h "${path}"` : "df -h";
            case "info":
                return "lsblk";
            case "mount":
                return "mount";
            case "space":
                return "du -sh *";
            default:
                return "df -h";
        }
    }
    else if (environment_js_1.IS_IOS) {
        switch (operation) {
            case "usage":
                return path ? `df -h "${path}"` : "df -h";
            case "info":
                return "lsblk";
            case "mount":
                return "mount";
            case "space":
                return "du -sh *";
            default:
                return "df -h";
        }
    }
    return "";
}
// Mobile-specific user management
function getMobileUserCommand(operation, user) {
    if (environment_js_1.IS_ANDROID) {
        switch (operation) {
            case "list":
                return "pm list-users";
            case "info":
                return user ? `pm list-users | grep ${user}` : "pm list-users";
            case "create":
                return `pm create-user ${user}`;
            case "remove":
                return `pm remove-user ${user}`;
            default:
                return "pm list-users";
        }
    }
    else if (environment_js_1.IS_IOS) {
        switch (operation) {
            case "list":
                return "dscl . -list /Users";
            case "info":
                return user ? `dscl . -read /Users/${user}` : "dscl . -list /Users";
            case "create":
                return `dscl . -create /Users/${user}`;
            case "remove":
                return `dscl . -delete /Users/${user}`;
            default:
                return "dscl . -list /Users";
        }
    }
    return "";
}
// Export the enhanced platform utilities
exports.ALLOWED_ROOTS_ARRAY = getRootPaths();
