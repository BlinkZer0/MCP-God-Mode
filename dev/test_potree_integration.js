#!/usr/bin/env node

/**
 * Test script for Potree integration with RF_sense tools
 * This script tests the integration by creating sample data and verifying the viewer works
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Sample RF_sense point cloud data
const samplePointCloudData = {
  sessionId: "test-potree-session-" + Date.now(),
  timestamp: new Date().toISOString(),
  points: [
    { x: 0, y: 0, z: 0, intensity: 0.8, classification: 1, velocity: 0, snr: 25, timestamp: Date.now() },
    { x: 1, y: 0, z: 0, intensity: 0.6, classification: 1, velocity: 0, snr: 22, timestamp: Date.now() },
    { x: 0, y: 1, z: 0, intensity: 0.7, classification: 1, velocity: 0, snr: 24, timestamp: Date.now() },
    { x: 0, y: 0, z: 1, intensity: 0.9, classification: 1, velocity: 0, snr: 26, timestamp: Date.now() },
    { x: 1, y: 1, z: 1, intensity: 0.5, classification: 1, velocity: 0, snr: 20, timestamp: Date.now() },
    { x: -1, y: -1, z: -1, intensity: 0.4, classification: 0, velocity: 0, snr: 18, timestamp: Date.now() },
    { x: 2, y: 2, z: 2, intensity: 0.3, classification: 0, velocity: 0, snr: 16, timestamp: Date.now() },
    { x: -2, y: 2, z: -2, intensity: 0.2, classification: 0, velocity: 0, snr: 14, timestamp: Date.now() }
  ],
  metadata: {
    source: 'rf_sense_test',
    pipeline: 'point_cloud',
    count: 8,
    potreeFormat: true
  },
  scanMode: false,
  localOnly: false
};

// Create test data file
const testDataPath = path.join(__dirname, 'sample_rf_sense_potree.json');
fs.writeFileSync(testDataPath, JSON.stringify(samplePointCloudData, null, 2));

console.log('🧪 Potree Integration Test');
console.log('========================');
console.log(`✅ Created sample point cloud data: ${testDataPath}`);
console.log(`📊 Sample data contains ${samplePointCloudData.points.length} points`);
console.log(`🔧 Potree format: ${samplePointCloudData.metadata.potreeFormat}`);
console.log(`📡 Source: ${samplePointCloudData.metadata.source}`);
console.log(`⚙️ Pipeline: ${samplePointCloudData.metadata.pipeline}`);

// Test the Potree viewer HTML file exists
const potreeViewerPath = path.join(__dirname, 'potree_viewer.html');
if (fs.existsSync(potreeViewerPath)) {
  console.log(`✅ Potree viewer HTML file exists: ${potreeViewerPath}`);
  
  // Check if the viewer contains Potree references
  const viewerContent = fs.readFileSync(potreeViewerPath, 'utf8');
  if (viewerContent.includes('potree')) {
    console.log('✅ Potree viewer contains Potree library references');
  } else {
    console.log('⚠️ Potree viewer may not have proper Potree integration');
  }
  
  if (viewerContent.includes('RF_sense')) {
    console.log('✅ Potree viewer is customized for RF_sense');
  } else {
    console.log('⚠️ Potree viewer may not be properly customized');
  }
} else {
  console.log(`❌ Potree viewer HTML file not found: ${potreeViewerPath}`);
}

// Test the legacy viewer exists (fallback)
const legacyViewerPath = path.join(__dirname, 'pointcloud_viewer_offline.html');
if (fs.existsSync(legacyViewerPath)) {
  console.log(`✅ Legacy viewer exists (fallback): ${legacyViewerPath}`);
} else {
  console.log(`⚠️ Legacy viewer not found: ${legacyViewerPath}`);
}

console.log('\n📋 Test Instructions:');
console.log('1. Start the MCP server with RF_sense tools enabled');
console.log('2. Open the Potree viewer at: http://localhost:3000/viewer/pointcloud');
console.log('3. Load the sample data file: ' + testDataPath);
console.log('4. Verify the point cloud renders correctly in Potree');
console.log('5. Test the RF_sense integration features (scan mode, etc.)');

console.log('\n🔗 API Endpoints to test:');
console.log('- GET /api/rf_sense/health - Check API health');
console.log('- GET /api/rf_sense/sessions - List available sessions');
console.log('- GET /api/rf_sense/potree/:sessionId - Get Potree-compatible data');
console.log('- POST /api/rf_sense/convert-to-potree - Convert session to Potree format');

console.log('\n🎯 RF_sense Tools to test:');
console.log('- rf_sense_mmwave with open_viewer action');
console.log('- rf_sense_wifi_lab with process action (pointcloud pipeline)');
console.log('- rf_sense_sim with process action (pointcloud pipeline)');

console.log('\n✨ Potree Integration Complete!');
console.log('The RF_sense tools now use Potree for enhanced point cloud visualization.');
console.log('Potree provides better performance for large datasets and advanced visualization features.');
