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
  mobilePlatform: IS_MOBILE ? (IS_ANDROID ? "android" : IS_IOS ? "ios" : "mobile-web") : "desktop",
  // Legal compliance configuration
  legalCompliance: {
    enabled: process.env.LEGAL_COMPLIANCE_ENABLED === "true",
    auditLogging: {
      enabled: process.env.AUDIT_LOGGING_ENABLED === "true",
      logLevel: (process.env.AUDIT_LOG_LEVEL as 'minimal' | 'standard' | 'comprehensive') || 'standard',
      retentionDays: parseInt(process.env.AUDIT_RETENTION_DAYS || "2555"), // 7 years default
      includeUserActions: process.env.AUDIT_INCLUDE_USER_ACTIONS !== "false",
      includeSystemEvents: process.env.AUDIT_INCLUDE_SYSTEM_EVENTS !== "false",
      includeDataAccess: process.env.AUDIT_INCLUDE_DATA_ACCESS !== "false",
      includeSecurityEvents: process.env.AUDIT_INCLUDE_SECURITY_EVENTS !== "false"
    },
    evidencePreservation: {
      enabled: process.env.EVIDENCE_PRESERVATION_ENABLED === "true",
      autoPreserve: process.env.EVIDENCE_AUTO_PRESERVE === "true",
      preservationPath: process.env.EVIDENCE_PRESERVATION_PATH || "./legal/evidence",
      hashAlgorithm: (process.env.EVIDENCE_HASH_ALGORITHM as 'sha256' | 'sha512' | 'md5') || 'sha256',
      includeMetadata: process.env.EVIDENCE_INCLUDE_METADATA !== "false",
      includeTimestamps: process.env.EVIDENCE_INCLUDE_TIMESTAMPS !== "false",
      includeUserContext: process.env.EVIDENCE_INCLUDE_USER_CONTEXT !== "false"
    },
    legalHold: {
      enabled: process.env.LEGAL_HOLD_ENABLED === "true",
      holdPath: process.env.LEGAL_HOLD_PATH || "./legal/holds",
      retentionPolicy: (process.env.LEGAL_HOLD_RETENTION_POLICY as 'indefinite' | 'scheduled' | 'manual') || 'manual',
      scheduledRetentionDays: parseInt(process.env.LEGAL_HOLD_SCHEDULED_DAYS || "30"),
      includeNotifications: process.env.LEGAL_HOLD_NOTIFICATIONS === "true",
      notificationEmail: process.env.LEGAL_HOLD_NOTIFICATION_EMAIL || undefined
    },
    chainOfCustody: {
      enabled: process.env.CHAIN_OF_CUSTODY_ENABLED === "true",
      includeDigitalSignatures: process.env.CHAIN_OF_CUSTODY_SIGNATURES === "true",
      includeWitnesses: process.env.CHAIN_OF_CUSTODY_WITNESSES === "true",
      witnessEmails: process.env.CHAIN_OF_CUSTODY_WITNESS_EMAILS?.split(',').map(e => e.trim()) || [],
      requireApproval: process.env.CHAIN_OF_CUSTODY_APPROVAL === "true",
      approvalWorkflow: (process.env.CHAIN_OF_CUSTODY_WORKFLOW as 'single' | 'dual' | 'committee') || 'single'
    },
    dataIntegrity: {
      enabled: process.env.DATA_INTEGRITY_ENABLED === "true",
      verifyOnAccess: process.env.DATA_INTEGRITY_VERIFY_ACCESS === "true",
      verifyOnModification: process.env.DATA_INTEGRITY_VERIFY_MODIFICATION !== "false",
      backupBeforeModification: process.env.DATA_INTEGRITY_BACKUP_BEFORE_MOD === "true",
      includeChecksums: process.env.DATA_INTEGRITY_INCLUDE_CHECKSUMS !== "false"
    },
    complianceFrameworks: {
      sox: process.env.COMPLIANCE_SOX === "true",
      hipaa: process.env.COMPLIANCE_HIPAA === "true",
      gdpr: process.env.COMPLIANCE_GDPR === "true",
      pci: process.env.COMPLIANCE_PCI === "true",
      iso27001: process.env.COMPLIANCE_ISO27001 === "true",
      custom: process.env.COMPLIANCE_CUSTOM === "true"
    }
  }
};

// Universal access - allow all drives and paths
export const ALLOWED_ROOTS = config.allowedRoot
  ? config.allowedRoot.split(",").map(s => s.trim()).filter(Boolean)
  : [];

export const MAX_BYTES = config.maxFileSize;
export const WEB_ALLOWLIST: string[] = []; // Empty array means no restrictions
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
