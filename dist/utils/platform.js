import * as os from "node:os";
import * as fsSync from "node:fs";
import { IS_WINDOWS, IS_LINUX, IS_MACOS, IS_ANDROID, IS_IOS, IS_MOBILE, MOBILE_PATHS, COMMAND_MAPPINGS } from "../config/environment.js";
// Cross-platform utility functions
export function getRootPaths() {
    if (IS_MOBILE) {
        return getMobileRootPaths();
    }
    else if (IS_WINDOWS) {
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
    if (IS_ANDROID) {
        return [
            MOBILE_PATHS.android.external,
            MOBILE_PATHS.android.downloads,
            MOBILE_PATHS.android.pictures,
            MOBILE_PATHS.android.documents
        ];
    }
    else if (IS_IOS) {
        return [
            MOBILE_PATHS.ios.documents,
            MOBILE_PATHS.ios.downloads,
            MOBILE_PATHS.ios.pictures,
            MOBILE_PATHS.ios.shared
        ];
    }
    return [process.cwd()];
}
// Get platform-specific command for a given operation
export function getPlatformCommand(operation) {
    if (IS_ANDROID) {
        return COMMAND_MAPPINGS.android[operation];
    }
    else if (IS_IOS) {
        return COMMAND_MAPPINGS.ios[operation];
    }
    else if (IS_WINDOWS) {
        return COMMAND_MAPPINGS.windows[operation];
    }
    else if (IS_LINUX) {
        return COMMAND_MAPPINGS.linux[operation];
    }
    else if (IS_MACOS) {
        return COMMAND_MAPPINGS.macos[operation];
    }
    return "";
}
// Mobile-specific utility functions
export function getMobilePermissions() {
    if (IS_ANDROID) {
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
    else if (IS_IOS) {
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
export function isMobileFeatureAvailable(feature) {
    if (!IS_MOBILE)
        return false;
    switch (feature) {
        case "camera":
            return IS_ANDROID || IS_IOS;
        case "location":
            return IS_ANDROID || IS_IOS;
        case "biometrics":
            return IS_ANDROID || IS_IOS;
        case "bluetooth":
            return IS_ANDROID || IS_IOS;
        case "nfc":
            return IS_ANDROID || IS_IOS;
        case "sensors":
            return IS_ANDROID || IS_IOS;
        case "notifications":
            return IS_ANDROID || IS_IOS;
        default:
            return false;
    }
}
// Get mobile device info
export function getMobileDeviceInfo() {
    if (!IS_MOBILE)
        return null;
    return {
        platform: IS_ANDROID ? "android" : IS_IOS ? "ios" : "mobile-web",
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
export function getFileOperationCommand(operation, source, destination) {
    if (IS_MOBILE) {
        return getMobileFileOperationCommand(operation, source, destination);
    }
    else if (IS_WINDOWS) {
        return getWindowsFileOperationCommand(operation, source, destination);
    }
    else {
        return getUnixFileOperationCommand(operation, source, destination);
    }
}
function getMobileFileOperationCommand(operation, source, destination) {
    if (IS_ANDROID) {
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
    else if (IS_IOS) {
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
export function getMobileProcessCommand(operation, filter) {
    if (IS_ANDROID) {
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
    else if (IS_IOS) {
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
export function getMobileServiceCommand(operation, service) {
    if (IS_ANDROID) {
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
    else if (IS_IOS) {
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
export function getMobileNetworkCommand(operation, networkInterface) {
    if (IS_ANDROID) {
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
    else if (IS_IOS) {
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
export function getMobileStorageCommand(operation, path) {
    if (IS_ANDROID) {
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
    else if (IS_IOS) {
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
export function getMobileUserCommand(operation, user) {
    if (IS_ANDROID) {
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
    else if (IS_IOS) {
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
export const ALLOWED_ROOTS_ARRAY = getRootPaths();
