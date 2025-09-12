# rf_sense/localize

## ⚠️ **EXPERIMENTAL TOOL WARNING**

**This tool is experimental and remains untested. We are building the structure before reaching our goal of 100% functionality.**

**⚠️ CRITICAL SAFETY WARNING**: RF sensing tools can be **extremely harmful to devices** if misused. This tool processes RF-derived point cloud data which can:
- **Damage RF hardware** through improper signal processing
- **Interfere with critical communications** including emergency services
- **Cause electromagnetic interference (EMI)** affecting medical devices
- **Violate FCC and international RF regulations**
- **Create privacy violations** through unauthorized monitoring

**Use at your own risk. We strongly advise against using these tools unless you are a qualified RF engineer with proper authorization and understanding of the risks.**

**Purpose**: Localize a fresh point set (or LAS/LAZ) against an existing RF map and return pose + fitness. Optionally emit a transformed LAS file.

## Overview

The `rf_sense_localize` tool performs 6-DoF pose estimation by aligning a new scan against a known RF-derived map using a two-stage registration process:

1. **Coarse Registration**: Normal Distributions Transform (NDT) for initial alignment
2. **Fine Registration**: Iterative Closest Point (ICP) point-to-plane for precise alignment

This tool is designed for RF sensing applications where you need to determine the position and orientation of a new scan relative to an existing reference map.

## Parameters

### Required Parameters

- **`map_path`** (string) - Path to .las/.laz file containing the reference map or clustered layout

### Input Data (Choose One)

- **`scan_path`** (string, optional) - Path to .las/.laz file containing the scan to localize
- **`scan_points`** (array, optional) - Raw point cloud data as array of [x,y,z] coordinates

### Optional Parameters

- **`intensity`** (array, optional) - Intensity values for each point
- **`times`** (array, optional) - Timestamp values for each point
- **`voxel`** (number, default: 0.05) - Voxel size for downsampling in meters
- **`max_iter`** (number, default: 60) - Maximum iterations for ICP refinement
- **`emit_las`** (boolean, default: false) - Whether to emit a transformed LAS file
- **`out_path`** (string, default: "scan_localized.las") - Output path for transformed LAS file
- **`safety_mode`** (enum: "on"|"off", default: "on") - Safety mode that mirrors repo safety toggles

## Output

The tool returns a JSON object containing:

```json
{
  "pose": [16 floats in row-major order],
  "fitness": 0.82,
  "rmse": 0.04,
  "inliers": 12345,
  "num_points": 20000,
  "map_points": 80000,
  "log": "NDT fitness: 0.1234, ICP fitness: 0.8200"
}
```

### Output Fields

- **`pose`** - 4x4 transformation matrix as 16-element array (row-major order)
- **`fitness`** - Registration fitness score (0-1, higher is better)
- **`rmse`** - Root mean square error of inlier correspondences
- **`inliers`** - Number of inlier point correspondences
- **`num_points`** - Number of points in the scan after downsampling
- **`map_points`** - Number of points in the map after downsampling
- **`log`** - Brief trace of registration process
- **`output_file`** - Path to emitted LAS file (if `emit_las` is true)

## Examples

### Example 1: LAS File to LAS File Localization

```json
{
  "map_path": "/maps/office.laz",
  "scan_path": "/scans/pass_2025-09-11.laz",
  "voxel": 0.05,
  "max_iter": 60,
  "emit_las": true,
  "out_path": "scan_localized.las"
}
```

### Example 2: Point Array Localization

```json
{
  "map_path": "/maps/warehouse.las",
  "scan_points": [
    [1.0, 2.0, 3.0],
    [1.1, 2.1, 3.1],
    [1.2, 2.2, 3.2]
  ],
  "intensity": [100, 150, 200],
  "times": [0.0, 0.1, 0.2],
  "voxel": 0.1,
  "max_iter": 100
}
```

### Example 3: High-Precision Localization

```json
{
  "map_path": "/maps/lab_environment.laz",
  "scan_path": "/scans/current_scan.las",
  "voxel": 0.02,
  "max_iter": 120,
  "emit_las": true,
  "out_path": "/output/precise_localization.las",
  "safety_mode": "off"
}
```

## Technical Details

### Registration Algorithm

1. **Point Cloud Loading**: Loads LAS/LAZ files or processes raw point arrays
2. **Downsampling**: Voxel-based downsampling to reduce computational complexity
3. **Normal Estimation**: Estimates surface normals for point-to-plane ICP
4. **Coarse Registration**: NDT for initial pose estimation
5. **Fine Registration**: ICP point-to-plane for precise alignment
6. **Output Generation**: Returns transformation matrix and quality metrics

### Error Handling

The tool includes comprehensive error handling:

- **File Validation**: Checks for file existence and format compatibility
- **Data Validation**: Ensures point clouds are non-empty and properly formatted
- **Registration Fallbacks**: Falls back to point-to-point ICP if point-to-plane fails
- **Graceful Degradation**: Uses NDT result if ICP fails completely

### Performance Considerations

- **Voxel Size**: Smaller voxels provide higher precision but increase computation time
- **Max Iterations**: More iterations improve convergence but increase processing time
- **Point Count**: Larger point clouds require more memory and processing time

## Dependencies

### Python Dependencies

The tool requires the following Python packages:

```
open3d==0.18.*
laspy>=2.5
numpy>=1.24
```

Install with:
```bash
npm run postinstall:rf_sense
```

### System Requirements

- Python 3.8 or higher
- Sufficient memory for point cloud processing
- Disk space for temporary files and output

## Safety and Legal Considerations

⚠️ **RF Safety Warning**: mmWave and unsupported RF hardware may be damaged if misused. Do not overdrive TX power; use authorized, supported devices only.

### Safety Features

- **Safety Mode**: Default "on" mode includes additional validation and logging
- **Input Validation**: Comprehensive validation of all input parameters
- **Error Boundaries**: Graceful handling of edge cases and failures
- **Audit Logging**: All operations are logged for compliance and debugging

### Legal Compliance

- **Authorized Use Only**: Ensure all RF operations comply with local regulations
- **Data Privacy**: Point cloud data may contain sensitive spatial information
- **Export Controls**: Some RF sensing technologies may be subject to export restrictions

## Troubleshooting

### Common Issues

1. **"Map file not found"**: Verify the map_path exists and is accessible
2. **"Scan data is empty"**: Check that scan file contains valid point data
3. **"Registration failed"**: Try adjusting voxel size or increasing max_iter
4. **"Python worker failed"**: Ensure Python dependencies are installed

### Performance Optimization

- Use appropriate voxel size for your application (0.05m is a good starting point)
- Limit point cloud size for faster processing
- Consider pre-processing large datasets
- Use SSD storage for better I/O performance

## Integration

### Server Registration

The tool is automatically registered in both server configurations:

- **Refactored Server**: Imported via `registerRfSenseLocalize(registry)`
- **Modular Server**: Included via glob pattern `dev/src/tools/rf_sense/*.ts`

### Category

The tool is registered under the `rf_sense` category alongside other RF sensing tools.

### Natural Language Interface

The tool integrates with the RF sense natural language interface for intuitive command processing.

## Related Tools

- `rf_sense_sim` - RF sensing simulation and synthetic data generation
- `rf_sense_wifi_lab` - Wi-Fi CSI-based RF sensing experiments
- `rf_sense_mmwave` - mmWave radar integration and processing
- `rf_sense_natural_language` - Natural language command processing for RF operations

## Version History

- **v1.0.0** - Initial implementation with NDT+ICP registration
- **v1.0.1** - Added comprehensive error handling and fallback mechanisms
- **v1.0.2** - Enhanced safety features and legal compliance integration
