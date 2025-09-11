#!/usr/bin/env python3
"""
RF Sense Localize Tool - Python Worker
======================================

Purpose: Localize a fresh point set (or LAS/LAZ) against an existing RF map and return pose + fitness.
Optionally emit a .LAS file with the transformed scan.

This script performs 6-DoF pose estimation by aligning a new scan against a known RF-derived map
using coarse NDT registration followed by fine ICP point-to-plane alignment.

Dependencies: open3d, laspy, numpy
"""

import argparse
import json
import sys
import traceback
import numpy as np
import laspy
import open3d as o3d
from pathlib import Path


def load_xyz_from_las(path: str) -> np.ndarray:
    """
    Load XYZ coordinates from a LAS/LAZ file.
    
    Args:
        path: Path to LAS/LAZ file
        
    Returns:
        numpy array of shape (N, 3) containing XYZ coordinates
    """
    try:
        with laspy.open(path) as f:
            las = f.read()
        xyz = np.vstack([las.x, las.y, las.z]).T.astype(np.float64)
        return xyz
    except Exception as e:
        raise ValueError(f"Failed to load LAS file {path}: {str(e)}")


def make_pcd(xyz: np.ndarray) -> o3d.geometry.PointCloud:
    """
    Create Open3D point cloud from XYZ coordinates.
    
    Args:
        xyz: numpy array of shape (N, 3) containing XYZ coordinates
        
    Returns:
        Open3D point cloud object
    """
    pc = o3d.geometry.PointCloud()
    pc.points = o3d.utility.Vector3dVector(xyz)
    return pc


def estimate_normals_safe(pc: o3d.geometry.PointCloud, radius: float = 0.1) -> None:
    """
    Safely estimate normals for a point cloud with fallback options.
    
    Args:
        pc: Open3D point cloud
        radius: Search radius for normal estimation
    """
    try:
        # Try with radius search first
        pc.estimate_normals(search_param=o3d.geometry.KDTreeSearchParamRadius(radius=radius))
    except:
        try:
            # Fallback to KNN search
            pc.estimate_normals(search_param=o3d.geometry.KDTreeSearchParamKNN(knn=20))
        except:
            # Final fallback - use default parameters
            pc.estimate_normals()


def perform_registration(scan_pc: o3d.geometry.PointCloud, 
                        map_pc: o3d.geometry.PointCloud,
                        voxel_size: float,
                        max_iterations: int) -> dict:
    """
    Perform two-stage registration: coarse NDT followed by fine ICP.
    
    Args:
        scan_pc: Scan point cloud to align
        map_pc: Reference map point cloud
        voxel_size: Voxel size for downsampling
        max_iterations: Maximum iterations for ICP
        
    Returns:
        Dictionary containing registration results
    """
    # Stage 1: Coarse registration using NDT
    try:
        ndt_result = o3d.pipelines.registration.registration_ndt(
            scan_pc, map_pc, voxel_size * 2, np.eye(4)
        )
        initial_transform = ndt_result.transformation
        ndt_fitness = ndt_result.fitness
    except Exception as e:
        # Fallback to identity if NDT fails
        initial_transform = np.eye(4)
        ndt_fitness = 0.0
        print(f"Warning: NDT registration failed, using identity transform: {e}", file=sys.stderr)

    # Stage 2: Fine registration using ICP point-to-plane
    try:
        icp_result = o3d.pipelines.registration.registration_icp(
            scan_pc, map_pc, voxel_size * 1.5, initial_transform,
            o3d.pipelines.registration.TransformationEstimationPointToPlane(),
            o3d.pipelines.registration.ICPConvergenceCriteria(max_iteration=max_iterations)
        )
        
        final_transform = icp_result.transformation
        fitness = float(icp_result.fitness)
        rmse = float(icp_result.inlier_rmse)
        inliers = len(icp_result.correspondence_set) if hasattr(icp_result, 'correspondence_set') else 0
        
    except Exception as e:
        # Fallback to point-to-point ICP if point-to-plane fails
        try:
            icp_result = o3d.pipelines.registration.registration_icp(
                scan_pc, map_pc, voxel_size * 1.5, initial_transform,
                o3d.pipelines.registration.TransformationEstimationPointToPoint(),
                o3d.pipelines.registration.ICPConvergenceCriteria(max_iteration=max_iterations)
            )
            
            final_transform = icp_result.transformation
            fitness = float(icp_result.fitness)
            rmse = float(icp_result.inlier_rmse)
            inliers = len(icp_result.correspondence_set) if hasattr(icp_result, 'correspondence_set') else 0
            
        except Exception as e2:
            # Final fallback - use initial transform
            final_transform = initial_transform
            fitness = ndt_fitness
            rmse = float('inf')
            inliers = 0
            print(f"Warning: ICP registration failed, using NDT result: {e2}", file=sys.stderr)

    return {
        "pose": [float(x) for x in final_transform.reshape(-1)],
        "fitness": fitness,
        "rmse": rmse,
        "inliers": inliers,
        "ndt_fitness": ndt_fitness
    }


def write_transformed_las(scan_pc: o3d.geometry.PointCloud, 
                         transform: np.ndarray, 
                         output_path: str) -> None:
    """
    Write transformed scan to LAS file.
    
    Args:
        scan_pc: Original scan point cloud
        transform: 4x4 transformation matrix
        output_path: Output LAS file path
    """
    try:
        # Apply transformation
        transformed_pc = scan_pc.transform(transform)
        transformed_points = np.asarray(transformed_pc.points)
        
        # Create LAS file
        header = laspy.LasHeader(point_format=3, version="1.2")
        las = laspy.LasData(header)
        
        # Set coordinates
        las.x = transformed_points[:, 0]
        las.y = transformed_points[:, 1]
        las.z = transformed_points[:, 2]
        
        # Write file
        las.write(output_path)
        
    except Exception as e:
        raise ValueError(f"Failed to write transformed LAS file {output_path}: {str(e)}")


def main():
    """Main function to handle command line arguments and perform localization."""
    parser = argparse.ArgumentParser(
        description="Localize an RF-derived scan against a known map",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python localize.py --map map.las --scan scan.las --voxel 0.05
  python localize.py --map map.laz --points-json points.json --emit-las --out result.las
        """
    )
    
    parser.add_argument("--map", required=True, help="Path to reference map LAS/LAZ file")
    parser.add_argument("--scan", help="Path to scan LAS/LAZ file")
    parser.add_argument("--points-json", help="Path to JSON file containing point data")
    parser.add_argument("--voxel", type=float, default=0.05, help="Voxel size for downsampling (default: 0.05)")
    parser.add_argument("--max-iter", type=int, default=60, help="Maximum ICP iterations (default: 60)")
    parser.add_argument("--emit-las", action="store_true", help="Emit transformed scan as LAS file")
    parser.add_argument("--out", default="scan_localized.las", help="Output LAS file path (default: scan_localized.las)")
    
    args = parser.parse_args()
    
    try:
        # Validate input arguments
        if not args.scan and not args.points_json:
            raise ValueError("Provide either --scan or --points-json")
        if args.scan and args.points_json:
            raise ValueError("Use either --scan or --points-json, not both")
        
        # Load reference map
        if not Path(args.map).exists():
            raise ValueError(f"Map file not found: {args.map}")
        
        map_xyz = load_xyz_from_las(args.map)
        if len(map_xyz) == 0:
            raise ValueError(f"Map file is empty: {args.map}")
        
        map_pc = make_pcd(map_xyz)
        map_pc = map_pc.voxel_down_sample(args.voxel)
        estimate_normals_safe(map_pc, args.voxel * 2)
        
        # Load scan data
        if args.scan:
            if not Path(args.scan).exists():
                raise ValueError(f"Scan file not found: {args.scan}")
            scan_xyz = load_xyz_from_las(args.scan)
        else:  # args.points_json
            if not Path(args.points_json).exists():
                raise ValueError(f"Points JSON file not found: {args.points_json}")
            
            with open(args.points_json, 'r') as f:
                payload = json.load(f)
            
            if "points" not in payload:
                raise ValueError("JSON file must contain 'points' field")
            
            scan_xyz = np.asarray(payload["points"], dtype=float)
            if len(scan_xyz.shape) != 2 or scan_xyz.shape[1] != 3:
                raise ValueError("Points must be an array of [x,y,z] coordinates")
        
        if len(scan_xyz) == 0:
            raise ValueError("Scan data is empty")
        
        scan_pc = make_pcd(scan_xyz)
        scan_pc = scan_pc.voxel_down_sample(args.voxel)
        estimate_normals_safe(scan_pc, args.voxel * 2)
        
        # Perform registration
        result = perform_registration(scan_pc, map_pc, args.voxel, args.max_iter)
        
        # Add metadata
        result["num_points"] = int(np.asarray(scan_pc.points).shape[0])
        result["map_points"] = int(np.asarray(map_pc.points).shape[0])
        result["log"] = f"NDT fitness: {result.get('ndt_fitness', 0.0):.4f}, ICP fitness: {result['fitness']:.4f}"
        
        # Remove temporary field
        if "ndt_fitness" in result:
            del result["ndt_fitness"]
        
        # Emit transformed LAS if requested
        if args.emit_las:
            transform_matrix = np.array(result["pose"]).reshape(4, 4)
            write_transformed_las(scan_pc, transform_matrix, args.out)
            result["output_file"] = args.out
        
        # Output result as JSON
        print(json.dumps(result, indent=2))
        return 0
        
    except Exception as e:
        error_result = {
            "error": str(e),
            "trace": traceback.format_exc()[:4000]
        }
        print(json.dumps(error_result, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())
