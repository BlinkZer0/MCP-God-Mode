import { config } from "../config/environment.js";

// Security: Command sanitization utility
export function sanitizeCommand(command: string, args: string[]): { command: string; args: string[] } {
  // Remove any command injection attempts
  const sanitizedCommand = command.replace(/[;&|`$(){}[\]]/g, '');
  const sanitizedArgs = args.map(arg => arg.replace(/[;&|`$(){}[\]]/g, ''));
  
  return { command: sanitizedCommand, args: sanitizedArgs };
}

// Security: Validate against dangerous commands
export function isDangerousCommand(command: string): boolean {
  const dangerousCommands = [
    'format', 'del', 'rmdir', 'shutdown', 'taskkill', 'rm', 'dd',
    'diskpart', 'reg', 'sc', 'wmic', 'powershell', 'cmd',
    'sudo', 'su', 'chmod', 'chown', 'mkfs', 'fdisk'
  ];
  
  return dangerousCommands.some(cmd => 
    command.toLowerCase().includes(cmd.toLowerCase())
  );
}

// Security: Check if security checks are enabled
export function shouldPerformSecurityChecks(): boolean {
  return config.enableSecurityChecks;
}
