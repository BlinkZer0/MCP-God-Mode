// RF Sense Tools - Comprehensive RF Sensing Toolkit
// ================================================
// 
// This module provides a complete RF sensing toolkit with three tiers:
// 1. rf_sense.sim - Simulation and datasets (zero legal risk)
// 2. rf_sense.wifi_lab - Controlled lab experiments with Wi-Fi CSI
// 3. rf_sense.mmwave - FMCW mmWave dev-kit integration
// 
// All tools include comprehensive guardrails, legal compliance, and cross-platform support.

export { registerRfSenseSim } from "./rf_sense_sim.js";
export { registerRfSenseWifiLab } from "./rf_sense_wifi_lab.js";
export { registerRfSenseMmWave } from "./rf_sense_mmwave.js";
export { registerRfSenseNaturalLanguage } from "./rf_sense_natural_language.js";
export { registerRfSenseGuardrails } from "./rf_sense_guardrails.js";

// Re-export guardrail utilities for use by other modules
export {
  checkPlatformCompatibility,
  detectPlatform
} from "./rf_sense_guardrails.js";

// Re-export natural language utilities
export {
  getAvailableCommands,
  getCommandExamples
} from "./rf_sense_natural_language.js";
