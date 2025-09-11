# RF_sense_mmwave Point Cloud Viewer

A robust, offline-capable 3D point cloud viewer for RF sensing data with AI-safe scan mode and local caching.

## Features

### 🎯 Core Capabilities
- **3M+ point rendering** with interactive performance
- **Multi-source fusion** (Wi-Fi, Bluetooth, File, Synthetic)
- **Voxel grid downsampling** for performance optimization
- **Real-time visualization** with customizable color modes
- **Export functionality** (JSON, PLY, Bundle formats)

### 🔒 AI-Safe Scan Mode
- **Network egress blocking** during radio operations
- **Local-only caching** with IndexedDB storage
- **SessionGuard** prevents data leakage to AI/tooling
- **Runtime CSP switching** for security enforcement
- **Offline operation** when radios disrupt connectivity

### 📡 Data Sources
- **File**: Drag-drop JSON point clouds
- **WebSocket**: Live streaming from local bridge
- **Web Bluetooth**: Direct BLE peripheral connection
- **Synthetic**: Demo data generator for testing

## Quick Start

### 1. Open the Viewer
```bash
# Open in browser
open dev/pointcloud_viewer_offline.html
```

### 2. Test with Sample Data
```bash
# Start WebSocket server (optional)
node dev/ws_point_server.js

# In viewer: Connect to ws://localhost:8787/points
```

### 3. Enable Scan Mode
1. Click "Start Scan (AI-Safe)"
2. All network egress is blocked
3. Data is cached locally only
4. Click "Stop Scan & Resume AI" to exit

## Data Formats

### JSON Schema (Objects)
```json
{
  "points": [
    {
      "x": 1.5,
      "y": -0.8,
      "z": 2.1,
      "i": 0.7,
      "src": "wifi",
      "t": 1640995200000
    }
  ]
}
```

### JSON Schema (Packed Arrays)
```json
{
  "xyz": [1.5, -0.8, 2.1, 1.6, -0.7, 2.2],
  "intensity": [0.7, 0.8],
  "src": "wifi",
  "t": 1640995200000
}
```

### Web Bluetooth Binary
- **Format**: Little-endian float32
- **Structure**: `[x, y, z, intensity]` repeating
- **Service UUID**: `0000ffaa-0000-1000-8000-00805f9b34fb`
- **Characteristic UUID**: `0000ffab-0000-1000-8000-00805f9b34fb`

## Controls

### Visualization
- **Point Size**: Adjust point rendering size
- **Color Mode**: 
  - Intensity (turbo colormap)
  - Source (per-radio color coding)
  - Z-Height (elevation-based)
- **Intensity Range**: Manual or auto-exposure
- **Voxel Size**: Downsampling resolution (meters)

### Data Management
- **Frame Buffer**: Number of frames to keep in memory
- **Pause/Resume**: Control data ingestion
- **Clear**: Reset all data
- **Recenter**: Auto-fit camera to data bounds

### Export Options
- **Screenshot**: PNG capture of current view
- **JSON Export**: Merged point cloud as JSON
- **PLY Export**: Standard point cloud format
- **Bundle Export**: Complete session with metadata

## Scan Mode Details

### Security Features
- **SessionGuard**: Blocks all network APIs during scan
- **CSP Enforcement**: Runtime content security policy switching
- **Local-Only Cache**: IndexedDB storage with no egress
- **Manual Resume**: User must explicitly exit scan mode

### Cache Management
- **Session Tracking**: Each scan creates a new session
- **Frame Storage**: All incoming data cached as blobs
- **Bundle Export**: Complete session export with manifest
- **Purge Function**: Clear all cached data

### Network Restrictions
- **Blocked**: fetch, WebSocket (non-loopback), XHR, sendBeacon, postMessage
- **Allowed**: Loopback WebSocket (127.0.0.1, localhost)
- **Configurable**: Toggle loopback-only mode

## Performance

### Optimization Features
- **Voxel Downsampling**: Configurable resolution for large datasets
- **Frame Buffering**: Circular buffer with configurable size
- **GPU Rendering**: Three.js with custom shaders
- **Dynamic Updates**: Efficient buffer management

### Recommended Settings
- **Voxel Size**: 0.03m for detailed, 0.1m for performance
- **Frame Buffer**: 20 frames for real-time, 100+ for analysis
- **Point Size**: 1.5px for overview, 3px for detail

## Integration

### WebSocket Bridge
```javascript
// Example bridge for Wi-Fi CSI data
const frame = {
  xyz: [...], // float32 array of x,y,z coordinates
  intensity: [...], // float32 array of intensities
  src: "wifi",
  t: Date.now()
};
websocket.send(JSON.stringify(frame) + "\n");
```

### BLE Peripheral
```c
// Example BLE streaming (Arduino/ESP32)
struct Point {
  float x, y, z, intensity;
};

void streamPoints() {
  Point p = {x: 1.0, y: 0.5, z: 2.0, intensity: 0.8};
  bleCharacteristic.writeValue((uint8_t*)&p, sizeof(p));
}
```

## Troubleshooting

### Common Issues
1. **No WebSocket connection**: Check if server is running on correct port
2. **BLE not connecting**: Ensure device advertises correct service UUID
3. **Poor performance**: Increase voxel size or reduce frame buffer
4. **Scan mode not working**: Check browser console for CSP violations

### Browser Compatibility
- **Chrome/Edge**: Full support including Web Bluetooth
- **Firefox**: WebSocket and file support (no BLE)
- **Safari**: Limited WebSocket support, no BLE

### Performance Tips
- Use Chrome for best performance
- Enable hardware acceleration
- Close other tabs during intensive scanning
- Use voxel downsampling for large datasets

## Development

### File Structure
```
dev/
├── pointcloud_viewer_offline.html  # Main viewer (standalone)
├── ws_point_server.js              # Sample WebSocket server
└── POINTCLOUD_VIEWER_README.md     # This documentation
```

### Key Components
- **SessionGuard**: Network blocking system
- **Cache**: IndexedDB storage management
- **Three.js Scene**: 3D rendering with custom shaders
- **Data Fusion**: Multi-source point cloud merging
- **Voxel Grid**: Downsampling algorithm

### Extending the Viewer
- Add new data sources in the ingestion section
- Implement custom color modes in fragment shader
- Add new export formats in the export handlers
- Extend cache schema for additional metadata

## License

Part of the MCP-God-Mode project. See main repository for license details.
