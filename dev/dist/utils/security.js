"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sanitizeCommand = sanitizeCommand;
exports.isDangerousCommand = isDangerousCommand;
exports.shouldPerformSecurityChecks = shouldPerformSecurityChecks;
const environment_js_1 = require("../config/environment.js");
// Security: Command sanitization utility
function sanitizeCommand(command, args) {
    // Remove any command injection attempts
    const sanitizedCommand = command.replace(/[;&|`$(){}[\]]/g, '');
    const sanitizedArgs = args.map(arg => arg.replace(/[;&|`$(){}[\]]/g, ''));
    return { command: sanitizedCommand, args: sanitizedArgs };
}
// Security: Validate against dangerous commands
function isDangerousCommand(command) {
    const dangerousCommands = [
        'format', 'del', 'rmdir', 'shutdown', 'taskkill', 'rm', 'dd',
        'diskpart', 'reg', 'sc', 'wmic', 'powershell', 'cmd',
        'sudo', 'su', 'chmod', 'chown', 'mkfs', 'fdisk'
    ];
    return dangerousCommands.some(cmd => command.toLowerCase().includes(cmd.toLowerCase()));
}
// Security: Check if security checks are enabled
function shouldPerformSecurityChecks() {
    return environment_js_1.config.enableSecurityChecks;
}
