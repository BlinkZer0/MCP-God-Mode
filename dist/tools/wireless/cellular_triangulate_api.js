/**
 * Cellular Triangulation API Endpoints
 * ====================================
 *
 * Express.js API endpoints for cellular triangulation tower data collection.
 * This module provides HTTP endpoints for receiving tower data from client devices
 * and managing SMS-based triangulation requests.
 *
 * Endpoints:
 * - POST /api/cellular/collect - Receive tower data or GPS data from client devices
 * - GET /api/cellular/status/:token - Check status of triangulation request
 * - GET /api/cellular/towers/:token - Get tower or GPS data for specific token
 * - GET /api/cellular/tokens - List active tokens (admin only)
 *
 * Usage:
 * Import this module and use with Express app:
 *
 * import express from 'express';
 * import { setupCellularTriangulateAPI } from './cellular_triangulate_api';
 *
 * const app = express();
 * setupCellularTriangulateAPI(app);
 */
import express from 'express';
import path from 'path';
import { ss7ConfigManager } from '../../config/ss7-config.js';
import { ss7SecurityManager } from './ss7-security.js';
const towerDataStore = new Map();
const TOKEN_EXPIRY_MS = 30 * 60 * 1000; // 30 minutes
// Cleanup expired tokens periodically
setInterval(() => {
    const now = Date.now();
    for (const [token, entry] of towerDataStore.entries()) {
        if (now - entry.timestamp > TOKEN_EXPIRY_MS) {
            entry.status = 'expired';
            towerDataStore.delete(token);
        }
    }
}, 5 * 60 * 1000); // Cleanup every 5 minutes
/**
 * Setup cellular triangulation API endpoints
 */
export function setupCellularTriangulateAPI(app) {
    const router = express.Router();
    // Middleware for JSON parsing
    router.use(express.json());
    // Middleware for CORS (if needed)
    router.use((req, res, next) => {
        res.header('Access-Control-Allow-Origin', '*');
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
        if (req.method === 'OPTIONS') {
            res.sendStatus(200);
        }
        else {
            next();
        }
    });
    /**
     * POST /api/cellular/collect
     * Receive tower data or GPS data from client devices
     */
    router.post('/collect', async (req, res) => {
        try {
            const { token, towers, timestamp, device_info } = req.body;
            if (!token) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Missing required field: token'
                });
            }
            // Handle GPS data (single location object)
            if (towers && towers.length === 1 && towers[0].lat !== undefined && towers[0].lon !== undefined) {
                // GPS data format
                const gpsData = {
                    lat: towers[0].lat,
                    lon: towers[0].lon,
                    error_radius_m: towers[0].error_radius_m || 10,
                    timestamp: towers[0].timestamp || Date.now(),
                    method: towers[0].method || 'gps'
                };
                const entry = {
                    token,
                    gps_data: gpsData,
                    timestamp: timestamp || Date.now(),
                    device_info,
                    status: 'completed',
                    data_type: 'gps'
                };
                towerDataStore.set(token, entry);
                console.log(`Received GPS data for token ${token}: lat=${gpsData.lat}, lon=${gpsData.lon}, accuracy=${gpsData.error_radius_m}m`);
                return res.json({
                    status: 'success',
                    message: 'GPS data received successfully',
                    token,
                    data_type: 'gps',
                    location: {
                        lat: gpsData.lat,
                        lon: gpsData.lon,
                        error_radius_m: gpsData.error_radius_m
                    }
                });
            }
            // Handle tower data (array of tower objects)
            if (!towers || !Array.isArray(towers)) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Missing required fields: towers (array)'
                });
            }
            // Validate tower data structure
            for (const tower of towers) {
                if (!tower.cid || !tower.lac || !tower.mcc || !tower.mnc) {
                    return res.status(400).json({
                        status: 'error',
                        message: 'Invalid tower data structure. Required: cid, lac, mcc, mnc'
                    });
                }
            }
            // Store tower data
            const entry = {
                token,
                towers,
                timestamp: timestamp || Date.now(),
                device_info,
                status: 'completed',
                data_type: 'towers'
            };
            towerDataStore.set(token, entry);
            console.log(`Received tower data for token ${token}: ${towers.length} towers`);
            res.json({
                status: 'success',
                message: 'Tower data received successfully',
                token,
                data_type: 'towers',
                towers_received: towers.length
            });
        }
        catch (error) {
            console.error('Error processing location data:', error);
            res.status(500).json({
                status: 'error',
                message: 'Internal server error'
            });
        }
    });
    /**
     * GET /api/cellular/status/:token
     * Check status of triangulation request
     */
    router.get('/status/:token', async (req, res) => {
        try {
            const { token } = req.params;
            if (!token) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Token is required'
                });
            }
            const entry = towerDataStore.get(token);
            if (!entry) {
                return res.status(404).json({
                    status: 'error',
                    message: 'Token not found or expired'
                });
            }
            res.json({
                status: 'success',
                token,
                data_status: entry.status,
                data_type: entry.data_type,
                towers_count: entry.towers?.length || 0,
                gps_data: entry.gps_data,
                timestamp: entry.timestamp,
                device_info: entry.device_info,
                location: entry.location
            });
        }
        catch (error) {
            console.error('Error checking token status:', error);
            res.status(500).json({
                status: 'error',
                message: 'Internal server error'
            });
        }
    });
    /**
     * GET /api/cellular/towers/:token
     * Get tower data for specific token
     */
    router.get('/towers/:token', async (req, res) => {
        try {
            const { token } = req.params;
            if (!token) {
                return res.status(400).json({
                    status: 'error',
                    message: 'Token is required'
                });
            }
            const entry = towerDataStore.get(token);
            if (!entry) {
                return res.status(404).json({
                    status: 'error',
                    message: 'Token not found or expired'
                });
            }
            res.json({
                status: 'success',
                token,
                data_type: entry.data_type,
                towers: entry.towers,
                gps_data: entry.gps_data,
                timestamp: entry.timestamp,
                device_info: entry.device_info
            });
        }
        catch (error) {
            console.error('Error getting tower data:', error);
            res.status(500).json({
                status: 'error',
                message: 'Internal server error'
            });
        }
    });
    /**
     * GET /api/cellular/tokens
     * List active tokens (admin only)
     */
    router.get('/tokens', async (req, res) => {
        try {
            // Simple admin check (in production, use proper authentication)
            const adminKey = req.headers['x-admin-key'];
            if (adminKey !== process.env.ADMIN_KEY) {
                return res.status(403).json({
                    status: 'error',
                    message: 'Admin access required'
                });
            }
            const tokens = Array.from(towerDataStore.entries()).map(([token, entry]) => ({
                token,
                status: entry.status,
                towers_count: entry.towers.length,
                timestamp: entry.timestamp,
                device_info: entry.device_info
            }));
            res.json({
                status: 'success',
                tokens,
                total: tokens.length
            });
        }
        catch (error) {
            console.error('Error listing tokens:', error);
            res.status(500).json({
                status: 'error',
                message: 'Internal server error'
            });
        }
    });
    /**
     * DELETE /api/cellular/tokens/:token
     * Delete specific token (admin only)
     */
    router.delete('/tokens/:token', async (req, res) => {
        try {
            // Simple admin check
            const adminKey = req.headers['x-admin-key'];
            if (adminKey !== process.env.ADMIN_KEY) {
                return res.status(403).json({
                    status: 'error',
                    message: 'Admin access required'
                });
            }
            const { token } = req.params;
            const deleted = towerDataStore.delete(token);
            if (deleted) {
                res.json({
                    status: 'success',
                    message: `Token ${token} deleted successfully`
                });
            }
            else {
                res.status(404).json({
                    status: 'error',
                    message: 'Token not found'
                });
            }
        }
        catch (error) {
            console.error('Error deleting token:', error);
            res.status(500).json({
                status: 'error',
                message: 'Internal server error'
            });
        }
    });
    /**
     * GET /collect
     * Serve the location collection webpage
     */
    router.get('/collect', async (req, res) => {
        try {
            const token = req.query.t;
            if (!token) {
                return res.status(400).send(`
          <html>
            <head><title>Error</title></head>
            <body>
              <h1>Error</h1>
              <p>No token provided in URL. Please use: /collect?t=your_token</p>
            </body>
          </html>
        `);
            }
            // Serve the HTML page
            const path = require('path');
            const fs = require('fs');
            const htmlPath = path.join(__dirname, 'collect.html');
            if (fs.existsSync(htmlPath)) {
                res.sendFile(htmlPath);
            }
            else {
                // Fallback HTML if file doesn't exist
                res.send(`
          <!DOCTYPE html>
          <html>
            <head>
              <title>Location Collection</title>
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
            </head>
            <body>
              <h1>Location Collection</h1>
              <p>Token: ${token}</p>
              <button onclick="getLocation()">Get My Location</button>
              <div id="status"></div>
              
              <script>
                async function getLocation() {
                  try {
                    const position = await new Promise((resolve, reject) => {
                      navigator.geolocation.getCurrentPosition(resolve, reject);
                    });
                    
                    const data = [{
                      lat: position.coords.latitude,
                      lon: position.coords.longitude,
                      error_radius_m: position.coords.accuracy || 10
                    }];
                    
                    const response = await fetch('/api/cellular/collect?t=${token}', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify(data)
                    });
                    
                    const result = await response.json();
                    document.getElementById('status').innerHTML = 
                      '<p style="color: green;">Location sent successfully!</p>';
                  } catch (error) {
                    document.getElementById('status').innerHTML = 
                      '<p style="color: red;">Error: ' + error.message + '</p>';
                  }
                }
              </script>
            </body>
          </html>
        `);
            }
        }
        catch (error) {
            console.error('Error serving collect page:', error);
            res.status(500).send('Internal server error');
        }
    });
    /**
     * GET /api/cellular/ss7/config
     * Get SS7 configuration (without sensitive data)
     */
    router.get('/ss7/config', async (req, res) => {
        try {
            const config = await ss7ConfigManager.loadConfig();
            if (!config) {
                return res.status(404).json({
                    status: 'error',
                    message: 'SS7 configuration not found'
                });
            }
            // Return config without sensitive data
            const publicConfig = {
                network_operator: config.network_operator,
                license_type: config.license_type,
                expiration_date: config.expiration_date,
                authorized_users: config.authorized_users,
                rate_limits: config.rate_limits,
                security_settings: config.security_settings
            };
            res.json({
                status: 'success',
                config: publicConfig
            });
        }
        catch (error) {
            res.status(500).json({
                status: 'error',
                message: 'Failed to load SS7 configuration',
                error: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    });
    /**
     * POST /api/cellular/ss7/config
     * Save SS7 configuration
     */
    router.post('/ss7/config', async (req, res) => {
        try {
            const config = req.body;
            const saved = await ss7ConfigManager.saveConfig(config);
            if (saved) {
                res.json({
                    status: 'success',
                    message: 'SS7 configuration saved successfully'
                });
            }
            else {
                res.status(400).json({
                    status: 'error',
                    message: 'Failed to save SS7 configuration'
                });
            }
        }
        catch (error) {
            res.status(500).json({
                status: 'error',
                message: 'Failed to save SS7 configuration',
                error: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    });
    /**
     * POST /api/cellular/ss7/security-check
     * Perform security check for SS7 operations
     */
    router.post('/ss7/security-check', async (req, res) => {
        try {
            const { phone_number, user_id, operation, ip_address, user_agent } = req.body;
            if (!phone_number || !user_id) {
                return res.status(400).json({
                    status: 'error',
                    message: 'phone_number and user_id are required'
                });
            }
            const securityCheck = await ss7SecurityManager.performSecurityCheck(phone_number, user_id, operation || 'ss7_query', ip_address || req.ip, user_agent || req.get('User-Agent'));
            res.json({
                status: 'success',
                security_check: securityCheck
            });
        }
        catch (error) {
            res.status(500).json({
                status: 'error',
                message: 'Security check failed',
                error: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    });
    /**
     * POST /api/cellular/ss7/consent
     * Record consent for phone number
     */
    router.post('/ss7/consent', async (req, res) => {
        try {
            const consent = req.body;
            const recorded = await ss7SecurityManager.recordConsent(consent);
            if (recorded) {
                res.json({
                    status: 'success',
                    message: 'Consent recorded successfully'
                });
            }
            else {
                res.status(400).json({
                    status: 'error',
                    message: 'Failed to record consent'
                });
            }
        }
        catch (error) {
            res.status(500).json({
                status: 'error',
                message: 'Failed to record consent',
                error: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    });
    /**
     * GET /api/cellular/ss7/consent/:phoneNumber/:userId
     * Get consent status for phone number and user
     */
    router.get('/ss7/consent/:phoneNumber/:userId', async (req, res) => {
        try {
            const { phoneNumber, userId } = req.params;
            const consent = ss7SecurityManager.getConsentStatus(phoneNumber, userId);
            res.json({
                status: 'success',
                consent: consent
            });
        }
        catch (error) {
            res.status(500).json({
                status: 'error',
                message: 'Failed to get consent status',
                error: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    });
    /**
     * POST /api/cellular/ss7/query
     * Execute SS7 query with security checks
     */
    router.post('/ss7/query', async (req, res) => {
        try {
            const { phone_number, user_id, ss7_pc, ss7_gt, ss7_hlr, api_key } = req.body;
            if (!phone_number || !ss7_pc || !ss7_gt || !ss7_hlr) {
                return res.status(400).json({
                    status: 'error',
                    message: 'phone_number, ss7_pc, ss7_gt, and ss7_hlr are required'
                });
            }
            // Perform security check
            const securityCheck = await ss7SecurityManager.performSecurityCheck(phone_number, user_id || 'anonymous', 'ss7_query', req.ip, req.get('User-Agent'));
            if (!securityCheck.passed) {
                return res.status(403).json({
                    status: 'error',
                    message: 'Security check failed',
                    reason: securityCheck.reason,
                    recommendations: securityCheck.recommendations
                });
            }
            // Execute SS7 query via Python script
            const { spawn } = require('child_process');
            const pythonScript = path.join(__dirname, 'cellular_triangulate.py');
            const args = [
                '-c',
                `from cellular_triangulate import CellularTriangulateTool; tool = CellularTriangulateTool(); result = tool.query_ss7_location('${phone_number}', '${ss7_pc}', '${ss7_gt}', '${ss7_hlr}', '${user_id || 'anonymous'}'); print(result)`
            ];
            const result = await new Promise((resolve, reject) => {
                const proc = spawn('python3', args, { stdio: 'pipe' });
                let output = '';
                let errorOutput = '';
                proc.stdout.on('data', (data) => {
                    output += data.toString();
                });
                proc.stderr.on('data', (data) => {
                    errorOutput += data.toString();
                });
                proc.on('close', (code) => {
                    if (code === 0) {
                        try {
                            const parsedResult = JSON.parse(output);
                            resolve(parsedResult);
                        }
                        catch (parseError) {
                            reject(new Error(`Failed to parse result: ${output}`));
                        }
                    }
                    else {
                        reject(new Error(`Python script failed: ${errorOutput}`));
                    }
                });
                proc.on('error', (error) => {
                    reject(error);
                });
            });
            // Log the successful operation
            await ss7SecurityManager.logSecurityEvent('ss7_query_success', {
                phone_number,
                user_id: user_id || 'anonymous',
                ss7_pc,
                ss7_gt,
                ss7_hlr
            }, user_id, req.ip);
            // Update abuse counters
            ss7SecurityManager.updateAbuseCounters(phone_number, user_id || 'anonymous', req.ip);
            res.json({
                status: 'success',
                message: 'SS7 query completed successfully',
                result: result
            });
        }
        catch (error) {
            // Log the failed operation
            await ss7SecurityManager.logSecurityEvent('ss7_query_failed', {
                phone_number: req.body.phone_number,
                user_id: req.body.user_id || 'anonymous',
                error: error instanceof Error ? error.message : 'Unknown error'
            }, req.body.user_id, req.ip);
            res.status(500).json({
                status: 'error',
                message: 'SS7 query failed',
                error: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    });
    /**
     * GET /api/cellular/ss7/status
     * Get SS7 system status
     */
    router.get('/ss7/status', async (req, res) => {
        try {
            const config = await ss7ConfigManager.loadConfig();
            const isConfigured = config !== null;
            res.json({
                status: 'success',
                ss7_configured: isConfigured,
                license_type: config?.license_type || 'none',
                network_operator: config?.network_operator || 'unknown',
                authorized_users_count: config?.authorized_users.length || 0,
                rate_limits: config?.rate_limits || null
            });
        }
        catch (error) {
            res.status(500).json({
                status: 'error',
                message: 'Failed to get SS7 status',
                error: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    });
    /**
     * GET /api/cellular/health
     * Health check endpoint
     */
    router.get('/health', async (req, res) => {
        res.json({
            status: 'healthy',
            service: 'cellular-triangulation-api',
            timestamp: new Date().toISOString(),
            active_tokens: towerDataStore.size,
            uptime: process.uptime(),
            ss7_endpoints: [
                'GET /api/cellular/ss7/config',
                'POST /api/cellular/ss7/config',
                'POST /api/cellular/ss7/security-check',
                'POST /api/cellular/ss7/consent',
                'GET /api/cellular/ss7/consent/:phoneNumber/:userId',
                'POST /api/cellular/ss7/query',
                'GET /api/cellular/ss7/status'
            ]
        });
    });
    // Mount the router
    app.use('/api/cellular', router);
    console.log('📡 Cellular Triangulation API endpoints registered');
    console.log('   GET  /collect?t=token - Serve location collection webpage');
    console.log('   POST /api/cellular/collect - Receive tower/GPS data');
    console.log('   GET  /api/cellular/status/:token - Check request status');
    console.log('   GET  /api/cellular/towers/:token - Get tower/GPS data');
    console.log('   GET  /api/cellular/tokens - List active tokens (admin)');
    console.log('   GET  /api/cellular/health - Health check');
    console.log('   SS7 Endpoints:');
    console.log('   GET  /api/cellular/ss7/config - Get SS7 configuration');
    console.log('   POST /api/cellular/ss7/config - Save SS7 configuration');
    console.log('   POST /api/cellular/ss7/security-check - Security check');
    console.log('   POST /api/cellular/ss7/consent - Record consent');
    console.log('   GET  /api/cellular/ss7/consent/:phone/:user - Get consent');
    console.log('   POST /api/cellular/ss7/query - Execute SS7 query');
    console.log('   GET  /api/cellular/ss7/status - SS7 system status');
}
/**
 * Helper function to check for tower data or GPS data response
 * This is used by the Python cellular triangulation tool
 */
export function checkForTowerDataResponse(token) {
    const entry = towerDataStore.get(token);
    if (entry && entry.status === 'completed') {
        if (entry.data_type === 'gps' && entry.gps_data) {
            // Return GPS data in a format compatible with the Python tool
            return [{
                    lat: entry.gps_data.lat,
                    lon: entry.gps_data.lon,
                    error_radius_m: entry.gps_data.error_radius_m
                }];
        }
        else if (entry.towers) {
            return entry.towers;
        }
    }
    return null;
}
/**
 * Helper function to store triangulation result
 */
export function storeTriangulationResult(token, location) {
    const entry = towerDataStore.get(token);
    if (entry) {
        entry.location = location;
        entry.status = 'completed';
        towerDataStore.set(token, entry);
    }
}
/**
 * Express app factory for standalone cellular triangulation API server
 */
export function createCellularTriangulateAPIApp() {
    const app = express();
    // Basic middleware
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    // Setup cellular triangulation API
    setupCellularTriangulateAPI(app);
    // Root endpoint
    app.get('/', (req, res) => {
        res.json({
            service: 'Cellular Triangulation API',
            version: '1.0.0',
            endpoints: [
                'POST /api/cellular/collect',
                'GET /api/cellular/status/:token',
                'GET /api/cellular/towers/:token',
                'GET /api/cellular/tokens',
                'GET /api/cellular/health'
            ]
        });
    });
    // Error handling middleware
    app.use((error, req, res, next) => {
        console.error('API Error:', error);
        res.status(500).json({
            status: 'error',
            message: 'Internal server error'
        });
    });
    return app;
}
// Export for use in other modules
export { towerDataStore };
