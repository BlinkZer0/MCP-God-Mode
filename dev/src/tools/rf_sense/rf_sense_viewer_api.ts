/**
 * RF Sense Point Cloud Viewer API
 * Provides endpoints for serving the viewer and streaming live point cloud data
 * Enhanced with AI-safe scan mode and local-only operations
 */

import express from 'express';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { z } from 'zod';
import { 
  createSecuritySession, 
  enableScanMode, 
  disableScanMode, 
  isScanModeActive,
  isNetworkBlocked,
  sanitizeResponseData,
  getSecurityStatus,
  createSecurityMiddleware
} from './rf_sense_security_guard.js';

// Global store for point cloud data (in production, use a proper database)
interface PointCloudSession {
  id: string;
  timestamp: string;
  points: Array<[number, number, number]>;
  metadata: {
    source: string;
    sessionId: string;
    pipeline: string;
    count: number;
    potreeFormat?: boolean;
    enhancedPoints?: Array<{
      x: number;
      y: number;
      z: number;
      intensity: number;
      classification?: number;
      velocity?: number;
      snr?: number;
      timestamp?: number;
    }>;
  };
  securitySessionId?: string;
  scanMode?: boolean;
  localOnly?: boolean;
}

// In-memory store for point cloud sessions
const pointCloudStore = new Map<string, PointCloudSession>();
let lastSessionId: string | null = null;

// Security session mapping
const securitySessionMap = new Map<string, string>(); // pointCloudSessionId -> securitySessionId

/**
 * Setup RF Sense Point Cloud Viewer API endpoints
 */
export function setupRfSenseViewerAPI(app: express.Application): void {
  console.log('🎯 Setting up RF Sense Point Cloud Viewer API...');

  // Serve the Potree point cloud viewer
  const potreeViewerPath = path.join(process.cwd(), 'dev', 'potree_viewer.html');
  if (fs.existsSync(potreeViewerPath)) {
    app.get('/viewer/pointcloud', (req, res) => {
      res.sendFile(potreeViewerPath);
    });
    console.log(`📁 Potree point cloud viewer served from: ${potreeViewerPath}`);
  } else {
    console.warn(`⚠️ Potree viewer file not found: ${potreeViewerPath}`);
  }

  // Serve the legacy point cloud viewer static files (fallback)
  const viewerPath = path.join(process.cwd(), 'dev', 'web', 'pointcloud');
  if (fs.existsSync(viewerPath)) {
    app.use('/viewer/legacy', express.static(viewerPath));
    console.log(`📁 Legacy point cloud viewer served from: ${viewerPath}`);
  }

  // API endpoint to get the latest point cloud data
  app.get('/api/rf_sense/points', async (req, res) => {
    try {
      const sessionId = req.query.sessionId as string;
      const securitySessionId = req.query.securitySessionId as string;
      
      let session: PointCloudSession | undefined;
      
      if (sessionId) {
        // Get specific session
        session = pointCloudStore.get(sessionId);
      } else {
        // Get latest session
        if (lastSessionId) {
          session = pointCloudStore.get(lastSessionId);
        }
      }
      
      if (!session) {
        return res.status(404).json({
          error: 'No point cloud data available',
          message: 'No RF sense sessions found. Start a capture session first.'
        });
      }
      
      // Check if scan mode is active and sanitize data accordingly
      let responseData = {
        sessionId: session.id,
        timestamp: session.timestamp,
        points: session.points,
        metadata: session.metadata,
        scanMode: session.scanMode || false,
        localOnly: session.localOnly || false,
        potreeCompatible: session.metadata.potreeFormat || false,
        enhancedPoints: session.metadata.enhancedPoints || null
      };
      
      // If security session is provided, apply security middleware
      if (securitySessionId) {
        const security = createSecurityMiddleware(securitySessionId);
        if (security.checkNetworkAccess() && isScanModeActive(securitySessionId)) {
          // Sanitize data for AI-safe scan mode
          responseData = security.processData(responseData, 50); // Limit to 50 data points
          (responseData as any)._securityNote = "Data sanitized for AI-safe scan mode. Full data available in offline viewer.";
        }
      }
      
      res.json(responseData);
      
    } catch (error) {
      console.error('Error fetching point cloud data:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: 'Failed to fetch point cloud data'
      });
    }
  });

  // API endpoint to get available sessions
  app.get('/api/rf_sense/sessions', async (req, res) => {
    try {
      const sessions = Array.from(pointCloudStore.values()).map(session => ({
        id: session.id,
        timestamp: session.timestamp,
        metadata: session.metadata
      }));
      
      res.json({
        sessions,
        count: sessions.length,
        latest: lastSessionId
      });
      
    } catch (error) {
      console.error('Error fetching sessions:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: 'Failed to fetch sessions'
      });
    }
  });

  // API endpoint to store point cloud data (called by RF sense tools)
  app.post('/api/rf_sense/points', async (req, res) => {
    try {
      const schema = z.object({
        sessionId: z.string(),
        points: z.array(z.array(z.number()).length(3)),
        metadata: z.object({
          source: z.string().default('rf_sense'),
          pipeline: z.string().default('unknown'),
          count: z.number().optional()
        }).optional()
      });
      
      const data = schema.parse(req.body);
      
      const session: PointCloudSession = {
        id: data.sessionId,
        timestamp: new Date().toISOString(),
        points: data.points,
        metadata: {
          source: data.metadata?.source || 'rf_sense',
          sessionId: data.sessionId,
          pipeline: data.metadata?.pipeline || 'unknown',
          count: data.metadata?.count || data.points.length
        }
      };
      
      // Store the session
      pointCloudStore.set(data.sessionId, session);
      lastSessionId = data.sessionId;
      
      // Clean up old sessions (keep last 10)
      if (pointCloudStore.size > 10) {
        const sessions = Array.from(pointCloudStore.entries())
          .sort((a, b) => new Date(b[1].timestamp).getTime() - new Date(a[1].timestamp).getTime());
        
        // Remove oldest sessions
        for (let i = 10; i < sessions.length; i++) {
          pointCloudStore.delete(sessions[i][0]);
        }
      }
      
      res.json({
        success: true,
        sessionId: data.sessionId,
        pointCount: data.points.length,
        message: 'Point cloud data stored successfully'
      });
      
    } catch (error) {
      console.error('Error storing point cloud data:', error);
      res.status(400).json({
        error: 'Invalid request data',
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // API endpoint to delete a session
  app.delete('/api/rf_sense/sessions/:sessionId', async (req, res) => {
    try {
      const sessionId = req.params.sessionId;
      
      if (!pointCloudStore.has(sessionId)) {
        return res.status(404).json({
          error: 'Session not found',
          message: `Session ${sessionId} does not exist`
        });
      }
      
      pointCloudStore.delete(sessionId);
      
      // Update last session ID if needed
      if (lastSessionId === sessionId) {
        const remainingSessions = Array.from(pointCloudStore.keys());
        lastSessionId = remainingSessions.length > 0 ? remainingSessions[0] : null;
      }
      
      res.json({
        success: true,
        message: `Session ${sessionId} deleted successfully`
      });
      
    } catch (error) {
      console.error('Error deleting session:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: 'Failed to delete session'
      });
    }
  });

  // API endpoint to export point cloud data in various formats
  app.get('/api/rf_sense/export/:sessionId', async (req, res) => {
    try {
      const sessionId = req.params.sessionId;
      const format = req.query.format as string || 'json';
      
      const session = pointCloudStore.get(sessionId);
      if (!session) {
        return res.status(404).json({
          error: 'Session not found',
          message: `Session ${sessionId} does not exist`
        });
      }
      
      switch (format.toLowerCase()) {
        case 'json':
          res.setHeader('Content-Type', 'application/json');
          res.setHeader('Content-Disposition', `attachment; filename="rf_sense_${sessionId}.json"`);
          res.json({
            sessionId: session.id,
            timestamp: session.timestamp,
            points: session.points,
            metadata: session.metadata
          });
          break;
          
        case 'ply':
          // Generate PLY format
          const plyContent = generatePLY(session.points, session.metadata);
          res.setHeader('Content-Type', 'text/plain');
          res.setHeader('Content-Disposition', `attachment; filename="rf_sense_${sessionId}.ply"`);
          res.send(plyContent);
          break;
          
        default:
          res.status(400).json({
            error: 'Unsupported format',
            message: 'Supported formats: json, ply'
          });
      }
      
    } catch (error) {
      console.error('Error exporting session:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: 'Failed to export session'
      });
    }
  });

  // Security endpoints for AI-safe scan mode
  app.post('/api/rf_sense/security/session', (req, res) => {
    try {
      const { consentGiven } = req.body;
      const securitySessionId = createSecuritySession(consentGiven || false);
      
      res.json({
        success: true,
        securitySessionId,
        message: 'Security session created successfully'
      });
    } catch (error) {
      res.status(500).json({
        error: 'Failed to create security session',
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  app.post('/api/rf_sense/security/scan-mode', (req, res) => {
    try {
      const { securitySessionId, enable } = req.body;
      
      if (!securitySessionId) {
        return res.status(400).json({
          error: 'Security session ID required'
        });
      }
      
      const success = enable ? enableScanMode(securitySessionId) : disableScanMode(securitySessionId);
      
      if (success) {
        res.json({
          success: true,
          scanMode: enable,
          message: `Scan mode ${enable ? 'enabled' : 'disabled'} successfully`
        });
      } else {
        res.status(400).json({
          error: 'Failed to toggle scan mode',
          message: 'Invalid session or consent required'
        });
      }
    } catch (error) {
      res.status(500).json({
        error: 'Failed to toggle scan mode',
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  app.get('/api/rf_sense/security/status/:securitySessionId', (req, res) => {
    try {
      const { securitySessionId } = req.params;
      const status = getSecurityStatus(securitySessionId);
      
      res.json(status);
    } catch (error) {
      res.status(500).json({
        error: 'Failed to get security status',
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // Potree-specific endpoints
  app.get('/api/rf_sense/potree/:sessionId', async (req, res) => {
    try {
      const sessionId = req.params.sessionId;
      const session = pointCloudStore.get(sessionId);
      
      if (!session) {
        return res.status(404).json({
          error: 'Session not found',
          message: `Session ${sessionId} does not exist`
        });
      }
      
      // Return Potree-compatible format
      const potreeData = {
        sessionId: session.id,
        timestamp: session.timestamp,
        points: session.metadata.enhancedPoints || session.points.map(([x, y, z]) => ({ x, y, z, intensity: 0.5 })),
        metadata: {
          source: session.metadata.source,
          pipeline: session.metadata.pipeline,
          count: session.metadata.count,
          potreeFormat: session.metadata.potreeFormat || false
        },
        scanMode: session.scanMode || false,
        localOnly: session.localOnly || false
      };
      
      res.json(potreeData);
      
    } catch (error) {
      console.error('Error fetching Potree data:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: 'Failed to fetch Potree data'
      });
    }
  });

  // Convert point cloud to Potree format endpoint
  app.post('/api/rf_sense/convert-to-potree', async (req, res) => {
    try {
      const { sessionId, outputFormat = 'json' } = req.body;
      
      if (!sessionId) {
        return res.status(400).json({
          error: 'Session ID required'
        });
      }
      
      const session = pointCloudStore.get(sessionId);
      if (!session) {
        return res.status(404).json({
          error: 'Session not found'
        });
      }
      
      // Convert to Potree format
      const potreeData = {
        version: "1.8",
        octreeDir: "data",
        points: session.metadata.enhancedPoints || session.points.map(([x, y, z]) => ({ 
          x, y, z, 
          intensity: 0.5,
          classification: 0,
          velocity: 0,
          snr: 20
        })),
        metadata: {
          source: session.metadata.source,
          pipeline: session.metadata.pipeline,
          count: session.metadata.count,
          timestamp: session.timestamp,
          sessionId: session.id
        }
      };
      
      if (outputFormat === 'json') {
        res.json(potreeData);
      } else {
        // For other formats, you could implement conversion logic here
        res.status(400).json({
          error: 'Unsupported output format',
          message: 'Currently only JSON format is supported'
        });
      }
      
    } catch (error) {
      console.error('Error converting to Potree format:', error);
      res.status(500).json({
        error: 'Internal server error',
        message: 'Failed to convert to Potree format'
      });
    }
  });

  // Health check endpoint
  app.get('/api/rf_sense/health', (req, res) => {
    res.json({
      status: 'healthy',
      service: 'RF Sense Point Cloud Viewer API',
      version: '2.0.0',
      potreeIntegration: true,
      sessions: pointCloudStore.size,
      latest: lastSessionId,
      securityFeatures: {
        scanMode: true,
        networkBlocking: true,
        dataSanitization: true,
        localOnlyCache: true
      },
      endpoints: [
        'GET /viewer/pointcloud - Potree point cloud viewer interface',
        'GET /viewer/legacy - Legacy Three.js viewer (fallback)',
        'GET /api/rf_sense/points - Get latest point cloud data',
        'GET /api/rf_sense/sessions - List available sessions',
        'GET /api/rf_sense/potree/:id - Get Potree-compatible data',
        'POST /api/rf_sense/convert-to-potree - Convert session to Potree format',
        'POST /api/rf_sense/points - Store point cloud data',
        'DELETE /api/rf_sense/sessions/:id - Delete session',
        'GET /api/rf_sense/export/:id - Export session data',
        'POST /api/rf_sense/security/session - Create security session',
        'POST /api/rf_sense/security/scan-mode - Toggle scan mode',
        'GET /api/rf_sense/security/status/:id - Get security status'
      ]
    });
  });

  console.log('✅ RF Sense Point Cloud Viewer API setup complete');
}

/**
 * Store point cloud data from RF sense tools
 */
export function storePointCloudData(
  sessionId: string,
  points: Array<[number, number, number]>,
  metadata: {
    source?: string;
    pipeline?: string;
    count?: number;
    securitySessionId?: string;
    scanMode?: boolean;
    localOnly?: boolean;
    potreeFormat?: boolean;
    enhancedPoints?: Array<{
      x: number;
      y: number;
      z: number;
      intensity: number;
      classification?: number;
      velocity?: number;
      snr?: number;
      timestamp?: number;
    }>;
  } = {}
): void {
  const session: PointCloudSession = {
    id: sessionId,
    timestamp: new Date().toISOString(),
    points,
    metadata: {
      source: metadata.source || 'rf_sense',
      sessionId,
      pipeline: metadata.pipeline || 'unknown',
      count: metadata.count || points.length,
      potreeFormat: metadata.potreeFormat || false,
      enhancedPoints: metadata.enhancedPoints || undefined
    },
    securitySessionId: metadata.securitySessionId,
    scanMode: metadata.scanMode || false,
    localOnly: metadata.localOnly || false
  };
  
  pointCloudStore.set(sessionId, session);
  lastSessionId = sessionId;
  
  // Map security session if provided
  if (metadata.securitySessionId) {
    securitySessionMap.set(sessionId, metadata.securitySessionId);
  }
  
  console.log(`📊 Stored point cloud data: ${points.length} points for session ${sessionId}${metadata.scanMode ? ' (AI-safe scan mode)' : ''}`);
}

/**
 * Get the latest point cloud data
 */
export function getLatestPointCloudData(): PointCloudSession | null {
  if (lastSessionId) {
    return pointCloudStore.get(lastSessionId) || null;
  }
  return null;
}

/**
 * Generate PLY format content
 */
function generatePLY(
  points: Array<[number, number, number]>,
  metadata: any
): string {
  const n = points.length;
  
  let header = `ply
format ascii 1.0
comment Generated by RF Sense Point Cloud Viewer
comment Timestamp: ${new Date().toISOString()}
comment Source: ${metadata.source || 'rf_sense'}
comment Session: ${metadata.sessionId || 'unknown'}
comment Pipeline: ${metadata.pipeline || 'unknown'}
comment Point Count: ${n}
element vertex ${n}
property float x
property float y
property float z
end_header
`;
  
  const vertexData = points.map(([x, y, z]) => `${x} ${y} ${z}`).join('\n');
  
  return header + vertexData + '\n';
}

/**
 * Open the point cloud viewer in the default browser
 */
export function openPointCloudViewer(port: number = 3000): void {
  const viewerUrl = `http://localhost:${port}/viewer/pointcloud`;
  
  try {
    const { spawn } = require('child_process');
    const os = require('os');
    
    let command: string;
    let args: string[];
    
    switch (os.platform()) {
      case 'darwin':
        command = 'open';
        args = [viewerUrl];
        break;
      case 'win32':
        command = 'start';
        args = [viewerUrl];
        break;
      default:
        command = 'xdg-open';
        args = [viewerUrl];
    }
    
    spawn(command, args, { detached: true, stdio: 'ignore' });
    console.log(`🌐 Opening point cloud viewer: ${viewerUrl}`);
    
  } catch (error) {
    console.error('Failed to open point cloud viewer:', error);
    console.log(`📱 Please manually open: ${viewerUrl}`);
  }
}
