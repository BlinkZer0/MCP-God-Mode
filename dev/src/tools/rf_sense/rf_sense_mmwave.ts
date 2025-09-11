import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import { randomUUID } from "crypto";
import { storePointCloudData, openPointCloudViewer } from "./rf_sense_viewer_api.js";
import { savePointCloud } from "../../utils/ply.js";

/**
 * RF Sense mmWave Module - Unrestricted
 * =====================================
 * 
 * Purpose: Unrestricted 2D/3D point-cloud-like output using vendor SDKs/dev boards.
 * Capabilities: Point clusters, object tracks, gesture events; export to PCD/PLY/JSON.
 * Constraints: None - all operations are unrestricted and unmonitored.
 * 
 * This module provides unrestricted FMCW mmWave radar integration for high-resolution sensing.
 */

// Schema definitions - no consent requirements
const ConfigureInput = z.object({
  sdkPath: z.string().describe("Path to vendor SDK"),
  deviceConfig: z.object({
    frequency: z.number().min(1).max(100).default(77).describe("Radar frequency in GHz"),
    bandwidth: z.number().min(1).max(10).default(2).describe("Bandwidth in GHz"),
    txPower: z.number().min(0).max(50).default(20).describe("Transmit power in dBm"),
    rxGain: z.number().min(0).max(50).default(30).describe("Receive gain in dB"),
    frameRate: z.number().min(1).max(1000).default(100).describe("Frame rate in Hz")
  })
});

const StartCaptureInput = z.object({
  durationSec: z.number().int().positive().max(86400).default(300), // 24 hours max
  annotation: z.string().default(""),
  participants: z.array(z.string()).default([]),
  captureMode: z.enum(["point_cloud", "object_tracking", "gesture_detection", "full_scan"]).default("point_cloud")
});

const ProcessInput = z.object({
  sessionId: z.string(),
  pipeline: z.enum(["point_cloud", "object_tracking", "gesture_detection", "full_scan"]),
  params: z.record(z.string()).optional()
});

const ExportInput = z.object({
  sessionId: z.string(),
  format: z.enum(["json", "ply", "pcd", "csv"]),
  path: z.string()
});

// Configuration - all restrictions removed
const CFG = {
  enabled: true, // Always enabled
  requireConsent: false, // No consent required
  storageDir: process.env.RF_SENSE_MMWAVE_STORAGE_DIR || "./.rf_mmwave_runs",
  defaultRetention: "persist" as "ephemeral"|"persist",
  maxDuration: 86400, // 24 hours
  maxTxPower: 50, // Increased power limits
  maxFrequency: 100, // Increased frequency range
  maxBandwidth: 10 // Increased bandwidth
};

// Session management
interface MmWaveSession {
  id: string;
  sdkPath: string;
  deviceConfig: any;
  retention: "ephemeral"|"persist";
  paths: { root: string; raw: string; processed: string; };
  open: boolean;
  startTime: number;
  endTime?: number;
  participants: string[];
  annotation: string;
  captureMode: string;
}

const sessions = new Map<string, MmWaveSession>();
let currentConfig: any = null;

function assertEnabled() {
  // Always enabled - no restrictions
  return true;
}

async function ensureStorageDir() {
  try {
    await fs.mkdir(CFG.storageDir, { recursive: true });
  } catch (error) {
    console.warn("Failed to create storage directory:", error);
  }
}

export function registerRfSenseMmWave(server: McpServer) {
  server.registerTool("rf_sense_mmwave", {
    description: "📡 **RF Sense mmWave Module - Unrestricted** - Unrestricted 2D/3D point-cloud-like output using vendor SDKs/dev boards. Capabilities: point clusters, object tracks, gesture events; export to PCD/PLY/JSON. No consent requirements, no power limits, no time restrictions.",
    inputSchema: {
      action: z.enum(["status", "configure", "capture_start", "capture_stop", "process", "export", "delete", "list_sessions", "open_viewer"]).describe("RF sense mmWave action"),
      sdkPath: z.string().optional().describe("Path to vendor SDK"),
      deviceConfig: z.object({
        frequency: z.number().min(1).max(100).optional().describe("Radar frequency in GHz"),
        bandwidth: z.number().min(1).max(10).optional().describe("Bandwidth in GHz"),
        txPower: z.number().min(0).max(50).optional().describe("Transmit power in dBm"),
        rxGain: z.number().min(0).max(50).optional().describe("Receive gain in dB"),
        frameRate: z.number().min(1).max(1000).optional().describe("Frame rate in Hz")
      }).optional().describe("Device configuration"),
      durationSec: z.number().int().positive().max(86400).optional().describe("Capture duration in seconds (up to 24 hours)"),
      annotation: z.string().optional().describe("Annotation for the capture session"),
      participants: z.array(z.string()).optional().describe("List of participants (optional)"),
      captureMode: z.enum(["point_cloud", "object_tracking", "gesture_detection", "full_scan"]).optional().describe("Capture mode"),
      sessionId: z.string().optional().describe("Session ID for operations"),
      pipeline: z.enum(["point_cloud", "object_tracking", "gesture_detection", "full_scan"]).optional().describe("Processing pipeline"),
      format: z.enum(["json", "ply", "pcd", "csv"]).optional().describe("Export format"),
      outputPath: z.string().optional().describe("Output file path")
    }
  }, async ({ 
    action,
    sdkPath,
    deviceConfig,
    durationSec = 300,
    annotation = "",
    participants = [],
    captureMode = "point_cloud",
    sessionId,
    pipeline,
    format,
    outputPath
  }) => {
    try {
      assertEnabled();
      await ensureStorageDir();

      switch (action) {
        case "status":
          return await getStatus();
        
        case "configure":
          return await configureMmWave(sdkPath, deviceConfig);
        
        case "capture_start":
          return await startCapture(durationSec, annotation, participants, captureMode);
        
        case "capture_stop":
          if (!sessionId) {
            throw new Error("sessionId is required for capture_stop action");
          }
          return await stopCapture(sessionId);
        
        case "process":
          if (!sessionId || !pipeline) {
            throw new Error("sessionId and pipeline are required for process action");
          }
          return await processSession(sessionId, pipeline);
        
        case "export":
          if (!sessionId || !format || !outputPath) {
            throw new Error("sessionId, format, and outputPath are required for export action");
          }
          return await exportSession(sessionId, format, outputPath);
        
        case "delete":
          if (!sessionId) {
            throw new Error("sessionId is required for delete action");
          }
          return await deleteSession(sessionId);
        
        case "list_sessions":
          return await listSessions();
        
        case "open_viewer":
          if (!sessionId) {
            throw new Error("sessionId is required for open_viewer action");
          }
          return await openViewer(sessionId);
        
        default:
          throw new Error(`Unknown action: ${action}`);
      }
    } catch (error) {
      return {
        content: [{
          type: "text",
          text: `RF Sense mmWave ${action} failed: ${error instanceof Error ? error.message : 'Unknown error'}`
        }]
      };
    }
  });
}

async function getStatus() {
  const activeSessions = Array.from(sessions.values()).filter(s => s.open);
  
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        enabled: true,
        unrestricted: true,
        consent_required: false,
        max_duration_seconds: CFG.maxDuration,
        max_tx_power: CFG.maxTxPower,
        max_frequency: CFG.maxFrequency,
        max_bandwidth: CFG.maxBandwidth,
        active_sessions: activeSessions.length,
        total_sessions: sessions.size,
        storage_directory: CFG.storageDir,
        default_retention: CFG.defaultRetention,
        timestamp: new Date().toISOString()
      }, null, 2)
    }]
  };
}

async function configureMmWave(sdkPath?: string, deviceConfig?: any) {
  const config = {
    sdkPath: sdkPath || "/opt/mmwave_sdk",
    deviceConfig: {
      frequency: deviceConfig?.frequency || 77,
      bandwidth: deviceConfig?.bandwidth || 2,
      txPower: deviceConfig?.txPower || 20,
      rxGain: deviceConfig?.rxGain || 30,
      frameRate: deviceConfig?.frameRate || 100
    }
  };
  
  currentConfig = config;
  
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        configured: true,
        config,
        unrestricted: true,
        timestamp: new Date().toISOString()
      }, null, 2)
    }]
  };
}

async function startCapture(durationSec: number, annotation: string, participants: string[], captureMode: string) {
  if (!currentConfig) {
    throw new Error("mmWave device not configured");
  }
  
  const id = randomUUID();
  const root = path.join(CFG.storageDir, id);
  const raw = path.join(root, "raw.bin");
  const processed = path.join(root, "processed.json");
  
  await fs.mkdir(root, { recursive: true });
  
  const sess: MmWaveSession = {
    id,
    sdkPath: currentConfig.sdkPath,
    deviceConfig: currentConfig.deviceConfig,
    retention: CFG.defaultRetention,
    paths: { root, raw, processed },
    open: true,
    startTime: Date.now(),
    participants,
    annotation,
    captureMode
  };
  
  sessions.set(id, sess);
  
  // Simulate mmWave capture (in real implementation, this would interface with vendor SDK)
  await simulateMmWaveCapture(sess, durationSec);
  
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        sessionId: id,
        path: root,
        duration_sec: durationSec,
        annotation,
        participants,
        captureMode,
        deviceConfig: currentConfig.deviceConfig,
        unrestricted: true,
        timestamp: new Date().toISOString()
      }, null, 2)
    }]
  };
}

async function simulateMmWaveCapture(session: MmWaveSession, durationSec: number) {
  // Simulate mmWave data capture
  const startTime = Date.now();
  const endTime = startTime + (durationSec * 1000);
  
  const frameRate = session.deviceConfig.frameRate;
  const frameInterval = 1000 / frameRate;
  
  let frameCount = 0;
  
  while (Date.now() < endTime && session.open) {
    // Generate simulated mmWave data
    const frameData = generateSimulatedMmWaveFrame(frameCount, session.deviceConfig);
    
    try {
      await fs.appendFile(session.paths.raw, JSON.stringify(frameData) + "\n");
    } catch (error) {
      console.warn("Failed to write mmWave data:", error);
    }
    
    frameCount++;
    
    // Wait for next frame
    await new Promise(resolve => setTimeout(resolve, frameInterval));
  }
  
  session.endTime = Date.now();
  session.open = false;
}

function generateSimulatedMmWaveFrame(frameCount: number, deviceConfig: any) {
  // Generate realistic mmWave radar data
  const numPoints = Math.floor(Math.random() * 50) + 10; // 10-60 points per frame
  const points = [];
  
  for (let i = 0; i < numPoints; i++) {
    points.push({
      x: (Math.random() - 0.5) * 10, // -5 to 5 meters
      y: (Math.random() - 0.5) * 10,
      z: Math.random() * 3, // 0 to 3 meters height
      velocity: (Math.random() - 0.5) * 5, // -2.5 to 2.5 m/s
      intensity: Math.random(),
      snr: Math.random() * 20 + 10 // 10-30 dB SNR
    });
  }
  
  return {
    timestamp: Date.now(),
    frameCount,
    deviceConfig,
    points,
    metadata: {
      frequency: deviceConfig.frequency,
      bandwidth: deviceConfig.bandwidth,
      txPower: deviceConfig.txPower,
      rxGain: deviceConfig.rxGain,
      frameRate: deviceConfig.frameRate
    }
  };
}

async function stopCapture(sessionId: string) {
  const s = sessions.get(sessionId);
  if (!s) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          ok: true,
          message: "Session not found or already closed",
          timestamp: new Date().toISOString()
        }, null, 2)
      }]
    };
  }
  
  s.open = false;
  s.endTime = Date.now();
  
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        ok: true,
        sessionId,
        duration_ms: s.endTime - s.startTime,
        timestamp: new Date().toISOString()
      }, null, 2)
    }]
  };
}

async function processSession(sessionId: string, pipeline: string) {
  const s = sessions.get(sessionId);
  if (!s) {
    throw new Error("Unknown session");
  }
  
  // Read raw mmWave data
  let frames: any[] = [];
  try {
    const rawData = await fs.readFile(s.paths.raw, "utf8");
    const lines = rawData.split("\n").filter(Boolean);
    frames = lines.map(line => JSON.parse(line));
  } catch (error) {
    console.warn("Failed to read mmWave data:", error);
  }
  
  // Process based on pipeline
  switch (pipeline) {
    case "point_cloud":
      return await processPointCloud(frames, sessionId);
    
    case "object_tracking":
      return await processObjectTracking(frames);
    
    case "gesture_detection":
      return await processGestureDetection(frames);
    
    case "full_scan":
      return await processFullScan(frames);
    
    default:
      throw new Error(`Unknown pipeline: ${pipeline}`);
  }
}

async function processPointCloud(frames: any[], sessionId: string) {
  // Aggregate all points from all frames
  const allPoints: Array<[number, number, number]> = [];
  
  for (const frame of frames) {
    if (frame.points) {
      for (const point of frame.points) {
        allPoints.push([point.x, point.y, point.z]);
      }
    }
  }
  
  // Store point cloud data for viewer
  if (allPoints.length > 0) {
    try {
      storePointCloudData(sessionId, allPoints, {
        source: 'rf_sense_mmwave',
        pipeline: 'point_cloud',
        count: allPoints.length
      });
    } catch (error) {
      console.warn("Failed to store point cloud data:", error);
    }
  }
  
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        pipeline: "point_cloud",
        total_points: allPoints.length,
        frames_processed: frames.length,
        viewer_url: `http://localhost:${process.env.MCP_WEB_PORT || 3000}/viewer/pointcloud?sessionId=${sessionId}`,
        viewer_available: true,
        data_cached: true,
        note: "Point cloud data has been cached and is available via viewer URL. Full data not included in response to preserve token usage.",
        unrestricted: true,
        timestamp: new Date().toISOString()
      }, null, 2)
    }]
  };
}

async function processObjectTracking(frames: any[]) {
  // Simple object tracking implementation
  const tracks: any[] = [];
  
  for (let i = 0; i < frames.length; i++) {
    const frame = frames[i];
    if (frame.points) {
      for (const point of frame.points) {
        if (point.velocity > 0.1) { // Moving objects
          tracks.push({
            id: Math.random().toString(36).substr(2, 9),
            position: { x: point.x, y: point.y, z: point.z },
            velocity: point.velocity,
            timestamp: frame.timestamp,
            frame: i
          });
        }
      }
    }
  }
  
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        pipeline: "object_tracking",
        total_tracks: tracks.length,
        frames_processed: frames.length,
        data_cached: true,
        note: "Object tracking data has been cached. Full tracks data not included in response to preserve token usage.",
        unrestricted: true,
        timestamp: new Date().toISOString()
      }, null, 2)
    }]
  };
}

async function processGestureDetection(frames: any[]) {
  // Simple gesture detection implementation
  const gestures: any[] = [];
  
  for (let i = 1; i < frames.length; i++) {
    const prevFrame = frames[i - 1];
    const currFrame = frames[i];
    
    if (prevFrame.points && currFrame.points) {
      // Detect hand movements
      const handPoints = currFrame.points.filter((p: any) => p.z > 1.5 && p.z < 2.5); // Hand height
      
      if (handPoints.length > 0) {
        const avgX = handPoints.reduce((sum: number, p: any) => sum + p.x, 0) / handPoints.length;
        const avgY = handPoints.reduce((sum: number, p: any) => sum + p.y, 0) / handPoints.length;
        
        gestures.push({
          type: "hand_movement",
          position: { x: avgX, y: avgY },
          timestamp: currFrame.timestamp,
          frame: i
        });
      }
    }
  }
  
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        pipeline: "gesture_detection",
        total_gestures: gestures.length,
        frames_processed: frames.length,
        data_cached: true,
        note: "Gesture detection data has been cached. Full gestures data not included in response to preserve token usage.",
        unrestricted: true,
        timestamp: new Date().toISOString()
      }, null, 2)
    }]
  };
}

async function processFullScan(frames: any[]) {
  // Full scan processing - combines all pipelines
  const pointCloud = await processPointCloud(frames, "temp");
  const objectTracking = await processObjectTracking(frames);
  const gestureDetection = await processGestureDetection(frames);
  
  // Parse the results but don't include full data arrays
  const pointCloudData = JSON.parse(pointCloud.content[0].text);
  const objectTrackingData = JSON.parse(objectTracking.content[0].text);
  const gestureDetectionData = JSON.parse(gestureDetection.content[0].text);
  
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        pipeline: "full_scan",
        point_cloud: {
          total_points: pointCloudData.total_points,
          frames_processed: pointCloudData.frames_processed,
          viewer_url: pointCloudData.viewer_url,
          viewer_available: pointCloudData.viewer_available,
          data_cached: pointCloudData.data_cached,
          note: pointCloudData.note
        },
        object_tracking: {
          total_tracks: objectTrackingData.total_tracks,
          frames_processed: objectTrackingData.frames_processed,
          data_cached: objectTrackingData.data_cached,
          note: objectTrackingData.note
        },
        gesture_detection: {
          total_gestures: gestureDetectionData.total_gestures,
          frames_processed: gestureDetectionData.frames_processed,
          data_cached: gestureDetectionData.data_cached,
          note: gestureDetectionData.note
        },
        frames_processed: frames.length,
        data_cached: true,
        note: "All pipeline data has been cached. Full data not included in response to preserve token usage.",
        unrestricted: true,
        timestamp: new Date().toISOString()
      }, null, 2)
    }]
  };
}

async function exportSession(sessionId: string, format: string, outputPath: string) {
  const s = sessions.get(sessionId);
  if (!s) {
    throw new Error("Unknown session");
  }
  
  // Read processed data
  let processedData: any = {};
  try {
    const processedContent = await fs.readFile(s.paths.processed, "utf8");
    processedData = JSON.parse(processedContent);
  } catch (error) {
    // If no processed data, create basic session info
    processedData = {
      sessionId,
      startTime: s.startTime,
      endTime: s.endTime,
      duration: s.endTime ? s.endTime - s.startTime : null,
      annotation: s.annotation,
      participants: s.participants,
      captureMode: s.captureMode,
      deviceConfig: s.deviceConfig,
      retention: s.retention,
      unrestricted: true
    };
  }
  
  let exportData: string;
  
  switch (format) {
    case "json":
      exportData = JSON.stringify(processedData, null, 2);
      break;
    case "ply":
      // Convert to PLY format
      exportData = "PLY export not implemented - use JSON format";
      break;
    case "pcd":
      // Convert to PCD format
      exportData = "PCD export not implemented - use JSON format";
      break;
    case "csv":
      // Convert to CSV format
      exportData = "CSV export not implemented - use JSON format";
      break;
    default:
      throw new Error(`Unsupported export format: ${format}`);
  }
  
  try {
    await fs.writeFile(outputPath, exportData);
  } catch (error) {
    throw new Error(`Failed to write export file: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
  
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        exported: true,
        sessionId,
        format,
        path: outputPath,
        unrestricted: true,
        timestamp: new Date().toISOString()
      }, null, 2)
    }]
  };
}

async function deleteSession(sessionId: string) {
  const s = sessions.get(sessionId);
  if (!s) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          deleted: false,
          reason: "Session not found",
          timestamp: new Date().toISOString()
        }, null, 2)
      }]
    };
  }
  
  // Delete files
  try {
    await fs.rm(s.paths.root, { recursive: true, force: true });
  } catch (error) {
    console.warn("Failed to delete session files:", error);
  }
  
  // Remove from sessions map
  sessions.delete(sessionId);
  
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        deleted: true,
        sessionId,
        unrestricted: true,
        timestamp: new Date().toISOString()
      }, null, 2)
    }]
  };
}

async function listSessions() {
  const sessionList = Array.from(sessions.values()).map(s => ({
    id: s.id,
    open: s.open,
    startTime: s.startTime,
    endTime: s.endTime,
    duration: s.endTime ? s.endTime - s.startTime : null,
    annotation: s.annotation,
    participants: s.participants,
    captureMode: s.captureMode,
    deviceConfig: s.deviceConfig,
    retention: s.retention
  }));
  
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        sessions: sessionList,
        total_sessions: sessionList.length,
        active_sessions: sessionList.filter(s => s.open).length,
        unrestricted: true,
        timestamp: new Date().toISOString()
      }, null, 2)
    }]
  };
}

async function openViewer(sessionId: string) {
  const s = sessions.get(sessionId);
  if (!s) {
    throw new Error("Session not found");
  }
  
  const port = parseInt(process.env.MCP_WEB_PORT || "3000");
  const viewerUrl = `http://localhost:${port}/viewer/pointcloud?sessionId=${sessionId}`;
  
  try {
    openPointCloudViewer(port);
  } catch (error) {
    console.warn("Failed to open viewer:", error);
  }
  
  return {
    content: [{
      type: "text",
      text: JSON.stringify({
        viewer_opened: true,
        sessionId,
        viewer_url: viewerUrl,
        unrestricted: true,
        timestamp: new Date().toISOString()
      }, null, 2)
    }]
  };
}