/**
 * LAS Export Utilities for RF Sense Point Cloud Data
 * Supports LAS 1.4 format for professional LiDAR point cloud processing
 * Compatible with CloudCompare, QGIS, ArcGIS, and other standard tools
 */
/**
 * LAS 1.4 format constants
 */
const LAS_FORMAT_VERSION = 14;
const LAS_POINT_FORMAT_0 = 0; // Basic point format
const LAS_POINT_FORMAT_1 = 1; // With GPS time
const LAS_POINT_FORMAT_2 = 2; // With RGB
const LAS_POINT_FORMAT_3 = 3; // With GPS time and RGB
const LAS_POINT_FORMAT_4 = 4; // With GPS time and waveform
const LAS_POINT_FORMAT_5 = 5; // With GPS time, RGB and waveform
/**
 * Convert point cloud data to LAS 1.4 binary format
 * Supports multiple point formats based on available data
 */
export function pointsToLAS(points, options = {}) {
    const { pointFormat = 0, includeColors = false, includeIntensity = true, includeGPSTime = false, includeClassification = false, metadata = {} } = options;
    // Normalize input format
    let normalizedPoints;
    let cloudMetadata = {};
    if (Array.isArray(points)) {
        // Handle array of [x,y,z] tuples
        normalizedPoints = points.map((p, i) => {
            if (Array.isArray(p)) {
                return {
                    x: p[0],
                    y: p[1],
                    z: p[2],
                    intensity: Math.floor(Math.random() * 65535) // Random intensity if not provided
                };
            }
            else {
                return {
                    ...p,
                    intensity: p.intensity || Math.floor(Math.random() * 65535)
                };
            }
        });
    }
    else if (points.points) {
        // Handle PointCloudData object
        normalizedPoints = points.points.map(p => ({
            ...p,
            intensity: p.intensity || Math.floor(Math.random() * 65535)
        }));
        if (points.metadata) {
            cloudMetadata = {
                source: points.metadata.source || 'rf_sense',
                timestamp: points.metadata.timestamp || new Date().toISOString(),
                count: points.metadata.count?.toString() || normalizedPoints.length.toString()
            };
        }
    }
    else {
        throw new Error('Invalid point cloud data format');
    }
    const n = normalizedPoints.length;
    // Calculate bounds
    const bounds = calculateBounds(normalizedPoints);
    const scale = calculateScale(bounds);
    const offset = calculateOffset(bounds);
    // Determine point format based on available data
    let actualPointFormat = pointFormat;
    if (includeColors && !actualPointFormat)
        actualPointFormat = 2;
    if (includeGPSTime && actualPointFormat < 1)
        actualPointFormat = 1;
    if (includeColors && includeGPSTime && actualPointFormat < 3)
        actualPointFormat = 3;
    // Calculate point record length
    const pointRecordLength = getPointRecordLength(actualPointFormat);
    // Create LAS file buffer
    const headerSize = 375; // LAS 1.4 header size
    const totalSize = headerSize + (n * pointRecordLength);
    const buffer = new ArrayBuffer(totalSize);
    const view = new DataView(buffer);
    // Write LAS header
    writeLASHeader(view, n, bounds, scale, offset, actualPointFormat, cloudMetadata, metadata);
    // Write point data
    writePointData(view, normalizedPoints, actualPointFormat, offset, scale, headerSize);
    return buffer.slice(0, totalSize);
}
/**
 * Calculate bounding box for point cloud
 */
function calculateBounds(points) {
    if (points.length === 0) {
        return { minX: 0, maxX: 0, minY: 0, maxY: 0, minZ: 0, maxZ: 0 };
    }
    let minX = points[0].x, maxX = points[0].x;
    let minY = points[0].y, maxY = points[0].y;
    let minZ = points[0].z, maxZ = points[0].z;
    for (const point of points) {
        minX = Math.min(minX, point.x);
        maxX = Math.max(maxX, point.x);
        minY = Math.min(minY, point.y);
        maxY = Math.max(maxY, point.y);
        minZ = Math.min(minZ, point.z);
        maxZ = Math.max(maxZ, point.z);
    }
    return { minX, maxX, minY, maxY, minZ, maxZ };
}
/**
 * Calculate scale factors for LAS format
 */
function calculateScale(bounds) {
    const rangeX = bounds.maxX - bounds.minX;
    const rangeY = bounds.maxY - bounds.minY;
    const rangeZ = bounds.maxZ - bounds.minZ;
    // Use appropriate scale based on range
    const scaleX = rangeX > 1000 ? 0.01 : rangeX > 100 ? 0.001 : 0.0001;
    const scaleY = rangeY > 1000 ? 0.01 : rangeY > 100 ? 0.001 : 0.0001;
    const scaleZ = rangeZ > 1000 ? 0.01 : rangeZ > 100 ? 0.001 : 0.0001;
    return [scaleX, scaleY, scaleZ];
}
/**
 * Calculate offset for LAS format
 */
function calculateOffset(bounds) {
    return [bounds.minX, bounds.minY, bounds.minZ];
}
/**
 * Get point record length for LAS format
 */
function getPointRecordLength(pointFormat) {
    switch (pointFormat) {
        case 0: return 20; // Basic point format
        case 1: return 28; // With GPS time
        case 2: return 26; // With RGB
        case 3: return 34; // With GPS time and RGB
        case 4: return 57; // With GPS time and waveform
        case 5: return 63; // With GPS time, RGB and waveform
        default: return 20;
    }
}
/**
 * Write LAS header to buffer
 */
function writeLASHeader(view, pointCount, bounds, scale, offset, pointFormat, cloudMetadata, metadata) {
    let offset_bytes = 0;
    // File signature "LASF"
    view.setUint8(offset_bytes, 0x4C);
    offset_bytes++; // 'L'
    view.setUint8(offset_bytes, 0x41);
    offset_bytes++; // 'A'
    view.setUint8(offset_bytes, 0x53);
    offset_bytes++; // 'S'
    view.setUint8(offset_bytes, 0x46);
    offset_bytes++; // 'F'
    // File source ID
    view.setUint16(offset_bytes, 0, true);
    offset_bytes += 2;
    // Global encoding
    view.setUint16(offset_bytes, 0, true);
    offset_bytes += 2;
    // Project ID GUID
    for (let i = 0; i < 16; i++) {
        view.setUint8(offset_bytes, 0);
        offset_bytes++;
    }
    // Version major and minor
    view.setUint8(offset_bytes, 1);
    offset_bytes++; // Version major
    view.setUint8(offset_bytes, 4);
    offset_bytes++; // Version minor
    // System identifier (32 bytes)
    const systemId = 'RF Sense Point Cloud Viewer';
    const systemIdBytes = new TextEncoder().encode(systemId.padEnd(32, '\0'));
    for (let i = 0; i < 32; i++) {
        view.setUint8(offset_bytes, systemIdBytes[i] || 0);
        offset_bytes++;
    }
    // Generating software (32 bytes)
    const softwareId = 'MCP God Mode RF Sense Tools';
    const softwareIdBytes = new TextEncoder().encode(softwareId.padEnd(32, '\0'));
    for (let i = 0; i < 32; i++) {
        view.setUint8(offset_bytes, softwareIdBytes[i] || 0);
        offset_bytes++;
    }
    // File creation day of year
    const now = new Date();
    const dayOfYear = Math.floor((now.getTime() - new Date(now.getFullYear(), 0, 0).getTime()) / 86400000);
    view.setUint16(offset_bytes, dayOfYear, true);
    offset_bytes += 2;
    // File creation year
    view.setUint16(offset_bytes, now.getFullYear(), true);
    offset_bytes += 2;
    // Header size
    view.setUint16(offset_bytes, 375, true);
    offset_bytes += 2;
    // Point data format ID
    view.setUint8(offset_bytes, pointFormat);
    offset_bytes++;
    // Point data record length
    view.setUint16(offset_bytes, getPointRecordLength(pointFormat), true);
    offset_bytes += 2;
    // Number of point records
    view.setUint32(offset_bytes, pointCount, true);
    offset_bytes += 4;
    // Number of points by return (5 values)
    for (let i = 0; i < 5; i++) {
        view.setUint32(offset_bytes, i === 0 ? pointCount : 0, true);
        offset_bytes += 4;
    }
    // X, Y, Z scale factors
    view.setFloat64(offset_bytes, scale[0], true);
    offset_bytes += 8;
    view.setFloat64(offset_bytes, scale[1], true);
    offset_bytes += 8;
    view.setFloat64(offset_bytes, scale[2], true);
    offset_bytes += 8;
    // X, Y, Z offsets
    view.setFloat64(offset_bytes, offset[0], true);
    offset_bytes += 8;
    view.setFloat64(offset_bytes, offset[1], true);
    offset_bytes += 8;
    view.setFloat64(offset_bytes, offset[2], true);
    offset_bytes += 8;
    // Max X, Y, Z
    view.setFloat64(offset_bytes, bounds.maxX, true);
    offset_bytes += 8;
    view.setFloat64(offset_bytes, bounds.maxY, true);
    offset_bytes += 8;
    view.setFloat64(offset_bytes, bounds.maxZ, true);
    offset_bytes += 8;
    // Min X, Y, Z
    view.setFloat64(offset_bytes, bounds.minX, true);
    offset_bytes += 8;
    view.setFloat64(offset_bytes, bounds.minY, true);
    offset_bytes += 8;
    view.setFloat64(offset_bytes, bounds.minZ, true);
    offset_bytes += 8;
    // Start of waveform data packet record (using 2x32bit instead of 64bit)
    view.setUint32(offset_bytes, 0, true);
    offset_bytes += 4;
    view.setUint32(offset_bytes, 0, true);
    offset_bytes += 4;
    // Start of first extended variable length record
    view.setUint32(offset_bytes, 0, true);
    offset_bytes += 4;
    // Number of extended variable length records
    view.setUint32(offset_bytes, 0, true);
    offset_bytes += 4;
    // Number of point records (using 2x32bit instead of 64bit)
    view.setUint32(offset_bytes, pointCount, true);
    offset_bytes += 4;
    view.setUint32(offset_bytes, 0, true);
    offset_bytes += 4;
    // Number of points by return (15 values for LAS 1.4, using 2x32bit instead of 64bit)
    for (let i = 0; i < 15; i++) {
        view.setUint32(offset_bytes, i === 0 ? pointCount : 0, true);
        offset_bytes += 4;
        view.setUint32(offset_bytes, 0, true);
        offset_bytes += 4;
    }
}
/**
 * Write point data to buffer
 */
function writePointData(view, points, pointFormat, offset, scale, headerSize) {
    let pointOffset = headerSize;
    for (const point of points) {
        // Convert to LAS coordinates
        const lasX = Math.round((point.x - offset[0]) / scale[0]);
        const lasY = Math.round((point.y - offset[1]) / scale[1]);
        const lasZ = Math.round((point.z - offset[2]) / scale[2]);
        // X, Y, Z coordinates (always present)
        view.setInt32(pointOffset, lasX, true);
        pointOffset += 4;
        view.setInt32(pointOffset, lasY, true);
        pointOffset += 4;
        view.setInt32(pointOffset, lasZ, true);
        pointOffset += 4;
        // Intensity
        view.setUint16(pointOffset, Math.min(65535, Math.max(0, point.intensity || 0)), true);
        pointOffset += 2;
        // Return number, number of returns, scan direction flag, edge of flight line
        const returnNumber = point.returnNumber || 1;
        const numberOfReturns = point.numberOfReturns || 1;
        const scanDirectionFlag = point.scanDirectionFlag || 0;
        const edgeOfFlightLine = point.edgeOfFlightLine || 0;
        let bitField = (returnNumber & 0x07) |
            ((numberOfReturns & 0x07) << 3) |
            ((scanDirectionFlag & 0x01) << 6) |
            ((edgeOfFlightLine & 0x01) << 7);
        view.setUint8(pointOffset, bitField);
        pointOffset += 1;
        // Classification
        view.setUint8(pointOffset, point.classification || 0);
        pointOffset += 1;
        // Scan angle rank
        view.setInt8(pointOffset, 0);
        pointOffset += 1;
        // User data
        view.setUint8(pointOffset, 0);
        pointOffset += 1;
        // Point source ID
        view.setUint16(pointOffset, point.pointSourceId || 0, true);
        pointOffset += 2;
        // GPS time (if format 1 or 3)
        if (pointFormat === 1 || pointFormat === 3) {
            view.setFloat64(pointOffset, point.gpsTime || Date.now() / 1000, true);
            pointOffset += 8;
        }
        // RGB (if format 2 or 3)
        if (pointFormat === 2 || pointFormat === 3) {
            const r = Math.min(65535, Math.max(0, Math.round((point.r || 1) * 65535)));
            const g = Math.min(65535, Math.max(0, Math.round((point.g || 1) * 65535)));
            const b = Math.min(65535, Math.max(0, Math.round((point.b || 1) * 65535)));
            view.setUint16(pointOffset, r, true);
            pointOffset += 2;
            view.setUint16(pointOffset, g, true);
            pointOffset += 2;
            view.setUint16(pointOffset, b, true);
            pointOffset += 2;
        }
    }
}
/**
 * Convert point cloud data to JSON format compatible with LAS metadata
 */
export function pointsToLASJSON(points, options = {}) {
    const { includeMetadata = true, metadata = {} } = options;
    // Normalize input format
    let normalizedPoints;
    let cloudMetadata = {};
    if (Array.isArray(points)) {
        normalizedPoints = points.map((p, i) => {
            if (Array.isArray(p)) {
                return { x: p[0], y: p[1], z: p[2], intensity: Math.floor(Math.random() * 65535) };
            }
            else {
                return { ...p, intensity: p.intensity || Math.floor(Math.random() * 65535) };
            }
        });
    }
    else if (points.points) {
        normalizedPoints = points.points.map(p => ({
            ...p,
            intensity: p.intensity || Math.floor(Math.random() * 65535)
        }));
        if (points.metadata) {
            cloudMetadata = { ...points.metadata };
        }
    }
    else {
        throw new Error('Invalid point cloud data format');
    }
    const bounds = calculateBounds(normalizedPoints);
    const scale = calculateScale(bounds);
    const offset = calculateOffset(bounds);
    const result = {
        points: normalizedPoints,
        metadata: {
            ...cloudMetadata,
            ...metadata,
            format: 'las_compatible',
            count: normalizedPoints.length,
            bounds: {
                min: [bounds.minX, bounds.minY, bounds.minZ],
                max: [bounds.maxX, bounds.maxY, bounds.maxZ]
            },
            scale,
            offset,
            las_format: '1.4',
            source: cloudMetadata.source || 'rf_sense',
            timestamp: cloudMetadata.timestamp || new Date().toISOString()
        }
    };
    return JSON.stringify(result, null, 2);
}
/**
 * Utility function to save LAS point cloud data to file
 */
export async function saveLASPointCloud(points, filePath, options = {}) {
    const fs = await import('fs');
    const path = await import('path');
    const { format = 'las', ...lasOptions } = options;
    // Ensure directory exists
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    let content;
    switch (format) {
        case 'las':
            content = pointsToLAS(points, lasOptions);
            fs.writeFileSync(filePath, Buffer.from(content));
            break;
        case 'las_json':
            content = pointsToLASJSON(points, lasOptions);
            fs.writeFileSync(filePath, content, 'utf8');
            break;
        default:
            throw new Error(`Unsupported LAS format: ${format}`);
    }
}
/**
 * LAS classification codes
 */
export const LAS_CLASSIFICATION = {
    CREATED_NEVER_CLASSIFIED: 0,
    UNCLASSIFIED: 1,
    GROUND: 2,
    LOW_VEGETATION: 3,
    MEDIUM_VEGETATION: 4,
    HIGH_VEGETATION: 5,
    BUILDING: 6,
    LOW_POINT_NOISE: 7,
    MODEL_KEY_POINT: 8,
    WATER: 9,
    RAIL: 10,
    ROAD_SURFACE: 11,
    OVERLAP: 12,
    WIRE_GUARD: 13,
    WIRE_CONDUCTOR: 14,
    TRANSMISSION_TOWER: 15,
    WIRE_STRUCTURE_CONNECTOR: 16,
    BRIDGE_DECK: 17,
    HIGH_NOISE: 18,
    // Additional classifications for RF sense data
    RF_SENSE_OBJECT: 19,
    RF_SENSE_PERSON: 20,
    RF_SENSE_MOTION: 21,
    RF_SENSE_STATIC: 22
};
