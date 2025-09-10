/**
 * Flipper Zero MCP Tool Registry
 * Main entry point for Flipper Zero integration tools
 * 
 * NOTE: This file now exports the consolidated flipper_zero tool
 * instead of the individual 24 tools for better organization and usability.
 */

// Export the consolidated Flipper Zero tool
export { registerFlipperZeroTool, getFlipperZeroToolName } from './flipper_zero_consolidated.js';

/**
 * Legacy function name for backward compatibility
 * @deprecated Use registerFlipperZeroTool instead
 */
export async function registerFlipperTools(server: any, deps?: any): Promise<void> {
  console.log('[Flipper] Using legacy registerFlipperTools - consider updating to registerFlipperZeroTool');
  const { registerFlipperZeroTool } = await import('./flipper_zero_consolidated.js');
  registerFlipperZeroTool(server);
}

/**
 * Legacy function name for backward compatibility
 * @deprecated Use getFlipperZeroToolName instead
 */
export function getFlipperToolNames(): string[] {
  console.log('[Flipper] Using legacy getFlipperToolNames - consider updating to getFlipperZeroToolName');
  return ['flipper_zero'];
}