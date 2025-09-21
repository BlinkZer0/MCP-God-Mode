/**
 * AI Image Upscaler Module for MCP God Mode
 * 
 * This module provides AI-powered image upscaling functionality based on the
 * excellent work of the Upscayl project and its contributors.
 * 
 * Original Project: Upscayl - Free and Open Source AI Image Upscaler
 * Repository: https://github.com/upscayl/upscayl
 * License: AGPL-3.0 (GNU Affero General Public License v3.0)
 * 
 * Main Contributors:
 * - Nayam Amarshe (@NayamAmarshe) - Lead Developer
 * - TGS963 (@TGS963) - Core Contributor
 * 
 * This implementation adapts the core Upscayl functionality for the MCP God Mode
 * ecosystem while maintaining compatibility with the original project's architecture
 * and model formats. We extend our gratitude to the Upscayl team for making
 * high-quality AI image upscaling accessible to everyone.
 * 
 * Underlying Technologies:
 * - Real-ESRGAN: Advanced AI upscaling models by Tencent ARC Lab
 * - NCNN Framework: High-performance neural network inference
 * - Vulkan Compute: Cross-platform GPU acceleration
 */

import fs from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import { spawn, ChildProcess } from "child_process";
import { z } from "zod";
import sharp from "sharp";

// Complete AI Upscaling Models Collection (based on Upscayl/Real-ESRGAN)
// Includes all models from the official Upscayl project and custom models repository
export const UPSCALING_MODELS = {
  // Core Real-ESRGAN Models
  "realesrgan-x4plus": {
    id: "realesrgan-x4plus",
    name: "Real-ESRGAN x4plus",
    scale: 4,
    description: "General purpose 4x upscaling model, good for photos and artwork",
    category: "general"
  },
  "realesrgan-x4plus-anime": {
    id: "realesrgan-x4plus-anime",
    name: "Real-ESRGAN x4plus Anime",
    scale: 4,
    description: "Optimized for anime and cartoon images",
    category: "anime"
  },
  "realesrgan-x2plus": {
    id: "realesrgan-x2plus",
    name: "Real-ESRGAN x2plus",
    scale: 2,
    description: "2x upscaling model for moderate enhancement",
    category: "general"
  },
  "esrgan-x4": {
    id: "esrgan-x4",
    name: "ESRGAN x4",
    scale: 4,
    description: "Classic ESRGAN model for 4x upscaling",
    category: "general"
  },
  "waifu2x-cunet": {
    id: "waifu2x-cunet",
    name: "Waifu2x CUNet",
    scale: 2,
    description: "Waifu2x model optimized for anime/artwork",
    category: "anime"
  },
  
  // RealESRGAN v3 Models (Lightweight)
  "realesrgan-general-wdn-x4-v3": {
    id: "realesrgan-general-wdn-x4-v3",
    name: "RealESRGAN General WDN x4 v3",
    scale: 4,
    description: "Wide and deep network model - lightweight and faster with slightly worse quality",
    category: "general"
  },
  "realesrgan-general-x4-v3": {
    id: "realesrgan-general-x4-v3",
    name: "RealESRGAN General x4 v3",
    scale: 4,
    description: "Lightweight version of the default model",
    category: "general"
  },
  
  // Anime Video Models
  "realesr-animevideov3-x2": {
    id: "realesr-animevideov3-x2",
    name: "Real-ESRGAN Anime Video v3 x2",
    scale: 2,
    description: "Specialized for anime video frames and sequential images",
    category: "anime"
  },
  "realesr-animevideov3-x3": {
    id: "realesr-animevideov3-x3",
    name: "Real-ESRGAN Anime Video v3 x3",
    scale: 3,
    description: "3x upscaling for anime video content",
    category: "anime"
  },
  "realesr-animevideov3-x4": {
    id: "realesr-animevideov3-x4",
    name: "Real-ESRGAN Anime Video v3 x4",
    scale: 4,
    description: "4x upscaling for anime video content",
    category: "anime"
  },
  
  // NMKD Models (High Quality)
  "4x-nmkd-siax-200k": {
    id: "4x-nmkd-siax-200k",
    name: "NMKD Siax 200k",
    scale: 4,
    description: "Universal upscaler for clean and slightly compressed images (JPEG quality 75+)",
    category: "general"
  },
  "4x-nmkd-superscale-sp-178000-g": {
    id: "4x-nmkd-superscale-sp-178000-g",
    name: "NMKD Superscale SP",
    scale: 4,
    description: "Perfect upscaling of clean (artifact-free) real-world images",
    category: "photo"
  },
  
  // Specialized Models by Community Contributors
  "uniscale-restore": {
    id: "uniscale-restore",
    name: "Uniscale Restore",
    scale: 4,
    description: "Restoration-focused model by Kim2091",
    category: "restoration"
  },
  "4x-lsdir": {
    id: "4x-lsdir",
    name: "LSDIR x4",
    scale: 4,
    description: "High-quality upscaling model by Phhofm",
    category: "general"
  },
  "4x-lsdir-plus-c": {
    id: "4x-lsdir-plus-c",
    name: "LSDIR Plus C x4",
    scale: 4,
    description: "Enhanced LSDIR model with color improvements by Phhofm",
    category: "general"
  },
  "4x-lsdir-compact-c3": {
    id: "4x-lsdir-compact-c3",
    name: "LSDIR Compact C3 x4",
    scale: 4,
    description: "Compact SRVGGNET model for faster inference by Phhofm",
    category: "fast"
  },
  "4x-nomos8k-sc": {
    id: "4x-nomos8k-sc",
    name: "Nomos8k SC x4",
    scale: 4,
    description: "High-resolution training model by Phhofm",
    category: "general"
  },
  "4x-hfa2k": {
    id: "4x-hfa2k",
    name: "HFA2k x4",
    scale: 4,
    description: "High-frequency analysis model by Phhofm",
    category: "general"
  },
  
  // Special Models
  "unknown-2-0-1": {
    id: "unknown-2-0-1",
    name: "Unknown v2.0.1",
    scale: 4,
    description: "Mystery model accidentally included in v2.0.1 - surprisingly good results",
    category: "experimental"
  }
} as const;

export type UpscalingModelId = keyof typeof UPSCALING_MODELS;

// Comprehensive Upscaling Parameters Schema (Complete Upscayl Feature Set)
export const UpscalingParams = z.object({
  // Core Model Selection
  model: z.string().default("realesrgan-x4plus").describe("AI upscaling model to use"),
  modelCategory: z.enum(["general", "anime", "photo", "restoration", "fast", "experimental"]).optional().describe("Model category filter"),
  
  // Output Dimensions
  scale: z.number().min(1).max(8).optional().describe("Custom scale factor (overrides model default)"),
  customWidth: z.number().optional().describe("Target width in pixels (alternative to scale)"),
  customHeight: z.number().optional().describe("Target height in pixels (alternative to scale)"),
  
  // Performance Settings
  tileSize: z.number().min(32).max(1024).default(512).describe("Tile size for processing large images (smaller = better quality, larger = faster)"),
  gpuId: z.string().optional().describe("GPU device ID for acceleration (0, 1, 2, etc.)"),
  cpuThreads: z.number().min(1).max(32).default(4).describe("Number of CPU threads for processing"),
  
  // Output Format & Quality
  format: z.enum(["png", "jpg", "jpeg", "webp", "tiff", "bmp"]).default("png").describe("Output image format"),
  compression: z.number().min(0).max(100).default(90).describe("Compression quality for lossy formats"),
  
  // Advanced Processing Options
  ttaMode: z.boolean().default(false).describe("Test-time augmentation for better quality (slower processing)"),
  preserveMetadata: z.boolean().default(true).describe("Preserve original image metadata (EXIF, ICC profiles)"),
  denoise: z.boolean().default(true).describe("Apply denoising during upscaling"),
  face_enhance: z.boolean().default(false).describe("Enable face enhancement (if supported by model)"),
  
  // Upscayl-Specific Features
  seamlessTextures: z.boolean().default(false).describe("Enable seamless texture processing for tiled images"),
  alphaChannel: z.boolean().default(true).describe("Preserve alpha channel transparency"),
  colorProfile: z.enum(["srgb", "adobe-rgb", "prophoto-rgb", "auto"]).default("auto").describe("Color profile handling"),
  
  // Batch Processing
  batchMode: z.boolean().default(false).describe("Enable batch processing optimizations"),
  outputNaming: z.enum(["suffix", "prefix", "folder", "custom"]).default("suffix").describe("Output file naming convention"),
  customSuffix: z.string().default("_upscaled").describe("Custom suffix for output files"),
  
  // Memory Management
  memoryLimit: z.number().min(512).max(32768).default(4096).describe("Memory limit in MB for processing"),
  enableMemoryOptimization: z.boolean().default(true).describe("Enable memory optimization for large images"),
  
  // Post-Processing
  postProcessing: z.object({
    sharpen: z.boolean().default(false).describe("Apply sharpening filter after upscaling"),
    sharpenAmount: z.number().min(0).max(2).default(0.5).describe("Sharpening intensity"),
    colorCorrection: z.boolean().default(false).describe("Apply automatic color correction"),
    contrastEnhancement: z.boolean().default(false).describe("Enhance contrast after upscaling")
  }).default({})
});

export type UpscalingParamsType = {
  // Core Model Selection
  model: string;
  modelCategory?: "general" | "anime" | "photo" | "restoration" | "fast" | "experimental";
  
  // Output Dimensions
  scale?: number;
  customWidth?: number;
  customHeight?: number;
  
  // Performance Settings
  tileSize: number;
  gpuId?: string;
  cpuThreads: number;
  
  // Output Format & Quality
  format: "png" | "jpg" | "jpeg" | "webp" | "tiff" | "bmp";
  compression: number;
  
  // Advanced Processing Options
  ttaMode: boolean;
  preserveMetadata: boolean;
  denoise: boolean;
  face_enhance: boolean;
  
  // Upscayl-Specific Features
  seamlessTextures: boolean;
  alphaChannel: boolean;
  colorProfile: "srgb" | "adobe-rgb" | "prophoto-rgb" | "auto";
  
  // Batch Processing
  batchMode: boolean;
  outputNaming: "suffix" | "prefix" | "folder" | "custom";
  customSuffix: string;
  
  // Memory Management
  memoryLimit: number;
  enableMemoryOptimization: boolean;
  
  // Post-Processing
  postProcessing: {
    sharpen: boolean;
    sharpenAmount: number;
    colorCorrection: boolean;
    contrastEnhancement: boolean;
  };
};

// Cross-platform binary paths (Complete Upscayl Integration)
function getUpscalerBinaryPath(): string {
  const platform = os.platform();
  const arch = os.arch();
  
  // Upscayl uses different binary names based on platform
  let binaryName: string;
  
  switch (platform) {
    case 'win32':
      binaryName = 'upscayl-realesrgan.exe';
      break;
    case 'darwin':
      binaryName = 'upscayl-realesrgan';
      break;
    case 'linux':
      binaryName = 'upscayl-realesrgan';
      break;
    default:
      binaryName = 'upscayl-realesrgan';
  }
  
  // Multiple possible binary locations (matching Upscayl's structure)
  const possiblePaths = [
    // Bundled with application
    path.join(__dirname, '..', '..', '..', 'resources', 'upscaler', platform, arch, binaryName),
    // System installation
    path.join(process.cwd(), 'resources', 'upscaler', binaryName),
    // Development mode
    path.join(__dirname, '..', '..', '..', 'bin', binaryName),
    // Global installation
    binaryName // Will use PATH
  ];
  
  // Return first existing path
  for (const binPath of possiblePaths) {
    if (fs.existsSync(binPath)) {
      return binPath;
    }
  }
  
  return possiblePaths[0]; // Default fallback
}

function getModelsPath(): string {
  // Multiple possible model directories (matching Upscayl's structure)
  const possiblePaths = [
    // Bundled models
    path.join(__dirname, '..', '..', '..', 'resources', 'upscaler', 'models'),
    // User custom models directory
    path.join(os.homedir(), '.upscayl', 'models'),
    // System models
    path.join(process.cwd(), 'models'),
    // Development models
    path.join(__dirname, '..', '..', '..', 'models')
  ];
  
  // Return first existing path
  for (const modelPath of possiblePaths) {
    if (fs.existsSync(modelPath)) {
      return modelPath;
    }
  }
  
  // Create default path if none exist
  const defaultPath = possiblePaths[0];
  fs.mkdirSync(defaultPath, { recursive: true });
  return defaultPath;
}

// Comprehensive GPU and System Capability Detection (Upscayl-style)
async function checkSystemCapabilities(): Promise<{
  hasVulkan: boolean;
  hasOpenCL: boolean;
  gpuDevices: string[];
  systemInfo: {
    platform: string;
    arch: string;
    totalMemory: number;
    freeMemory: number;
    cpuCores: number;
  };
  supportedFormats: string[];
}> {
  return new Promise(async (resolve) => {
    const platform = os.platform();
    const arch = os.arch();
    
    // System information
    const systemInfo = {
      platform,
      arch,
      totalMemory: Math.round(os.totalmem() / 1024 / 1024), // MB
      freeMemory: Math.round(os.freemem() / 1024 / 1024), // MB
      cpuCores: os.cpus().length
    };
    
    // Detect GPU capabilities (simplified)
    let hasVulkan = false;
    let hasOpenCL = false;
    let gpuDevices: string[] = [];
    
    try {
      // Try to detect Vulkan support
      const { exec } = await import('child_process');
      const { promisify } = await import('util');
      const execAsync = promisify(exec);
      
      if (platform === 'win32') {
        // Windows GPU detection
        try {
          const { stdout } = await execAsync('wmic path win32_VideoController get name', { timeout: 5000 });
          const gpuLines = stdout.split('\n').filter(line => line.trim() && !line.includes('Name'));
          gpuDevices = gpuLines.map((line, index) => index.toString());
          hasVulkan = gpuLines.some(line => 
            line.toLowerCase().includes('nvidia') || 
            line.toLowerCase().includes('amd') || 
            line.toLowerCase().includes('intel')
          );
        } catch {
          gpuDevices = ['0']; // Fallback
        }
      } else if (platform === 'darwin') {
        // macOS GPU detection
        try {
          const { stdout } = await execAsync('system_profiler SPDisplaysDataType', { timeout: 5000 });
          hasVulkan = stdout.includes('Metal') || stdout.includes('AMD') || stdout.includes('NVIDIA');
          gpuDevices = ['0']; // macOS typically has one main GPU
        } catch {
          gpuDevices = ['0'];
        }
      } else {
        // Linux GPU detection
        try {
          const { stdout } = await execAsync('lspci | grep -i vga', { timeout: 5000 });
          const gpuLines = stdout.split('\n').filter(line => line.trim());
          gpuDevices = gpuLines.map((line, index) => index.toString());
          hasVulkan = gpuLines.some(line => 
            line.toLowerCase().includes('nvidia') || 
            line.toLowerCase().includes('amd')
          );
        } catch {
          gpuDevices = ['0'];
        }
      }
      
      hasOpenCL = hasVulkan; // Simplified assumption
      
    } catch (error) {
      // Fallback values
      hasVulkan = true;
      hasOpenCL = true;
      gpuDevices = ['0'];
    }
    
    // Supported formats (based on Sharp capabilities)
    const supportedFormats = ['png', 'jpg', 'jpeg', 'webp', 'tiff', 'bmp'];
    
    resolve({
      hasVulkan,
      hasOpenCL,
      gpuDevices,
      systemInfo,
      supportedFormats
    });
  });
}

// Generate comprehensive upscaling command arguments (Complete Upscayl Feature Set)
function getUpscalingArguments(params: {
  inputPath: string;
  outputPath: string;
  model: string;
  scale?: number;
  customWidth?: number;
  customHeight?: number;
  tileSize: number;
  gpuId?: string;
  cpuThreads: number;
  ttaMode: boolean;
  denoise: boolean;
  face_enhance: boolean;
  seamlessTextures: boolean;
  alphaChannel: boolean;
  memoryLimit: number;
  enableMemoryOptimization: boolean;
}): string[] {
  const {
    inputPath,
    outputPath,
    model,
    scale,
    customWidth,
    customHeight,
    tileSize,
    gpuId,
    cpuThreads,
    ttaMode,
    denoise,
    face_enhance,
    seamlessTextures,
    alphaChannel,
    memoryLimit,
    enableMemoryOptimization
  } = params;

  const modelsPath = getModelsPath();
  const args: string[] = [];

  // Input and output
  args.push('-i', inputPath);
  args.push('-o', outputPath);

  // Model
  args.push('-n', model);
  args.push('-m', modelsPath);

  // Scale or custom dimensions
  if (customWidth && customHeight) {
    args.push('-w', customWidth.toString());
    args.push('-h', customHeight.toString());
  } else if (scale) {
    args.push('-s', scale.toString());
  }

  // Tile size for memory management
  args.push('-t', tileSize.toString());

  // GPU device
  if (gpuId) {
    args.push('-g', gpuId);
  }

  // CPU threads
  if (cpuThreads > 1) {
    args.push('-j', cpuThreads.toString());
  }

  // Memory management
  if (enableMemoryOptimization) {
    args.push('--memory-limit', memoryLimit.toString());
  }

  // Advanced options
  if (ttaMode) {
    args.push('-x'); // TTA mode for better quality
  }

  if (denoise) {
    args.push('-d'); // Denoise
  }

  if (face_enhance) {
    args.push('-f'); // Face enhancement
  }

  if (seamlessTextures) {
    args.push('--seamless'); // Seamless texture processing
  }

  if (alphaChannel) {
    args.push('--preserve-alpha'); // Preserve transparency
  }

  // Output format (PNG for quality, will convert later if needed)
  args.push('-f', 'png');

  return args;
}

// Main upscaling function
export async function upscaleImage(
  inputPath: string,
  outputPath: string,
  params: UpscalingParamsType,
  onProgress?: (progress: number, message: string) => void
): Promise<{
  success: boolean;
  outputPath: string;
  originalSize: { width: number; height: number };
  upscaledSize: { width: number; height: number };
  processingTime: number;
  model: string;
  error?: string;
}> {
  const startTime = Date.now();
  
  try {
    // Validate input file
    if (!fs.existsSync(inputPath)) {
      throw new Error(`Input file not found: ${inputPath}`);
    }

    // Get original image metadata
    const originalMeta = await sharp(inputPath).metadata();
    const originalSize = {
      width: originalMeta.width || 0,
      height: originalMeta.height || 0
    };

    // Check system capabilities
    const systemCaps = await checkSystemCapabilities();
    onProgress?.(10, "Checking system capabilities...");

    // Determine output dimensions
    let targetScale = params.scale;
    let targetWidth = params.customWidth;
    let targetHeight = params.customHeight;

    if (!targetWidth && !targetHeight && !targetScale) {
      // Use model default scale
      const modelInfo = UPSCALING_MODELS[params.model as UpscalingModelId];
      targetScale = modelInfo?.scale || 4;
    }

    // Calculate expected output size
    let expectedWidth: number;
    let expectedHeight: number;

    if (targetWidth && targetHeight) {
      expectedWidth = targetWidth;
      expectedHeight = targetHeight;
    } else if (targetScale) {
      expectedWidth = originalSize.width * targetScale;
      expectedHeight = originalSize.height * targetScale;
    } else {
      expectedWidth = originalSize.width * 4; // Default 4x
      expectedHeight = originalSize.height * 4;
    }

    onProgress?.(20, "Preparing upscaling process...");

    // Ensure output directory exists
    const outputDir = path.dirname(outputPath);
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    // Get upscaler binary path
    const binaryPath = getUpscalerBinaryPath();
    
    // Check if binary exists (in a real implementation)
    if (!fs.existsSync(binaryPath)) {
      // Fallback to software-based upscaling using Sharp
      onProgress?.(30, "Hardware upscaler not available, using software fallback...");
      return await fallbackUpscaling(inputPath, outputPath, params, originalSize, expectedWidth, expectedHeight, startTime, onProgress);
    }

    // Generate command arguments
    const args = getUpscalingArguments({
      inputPath,
      outputPath,
      model: params.model,
      scale: targetScale,
      customWidth: targetWidth,
      customHeight: targetHeight,
      tileSize: params.tileSize,
      gpuId: params.gpuId || (systemCaps.gpuDevices[0] || '0'),
      cpuThreads: params.cpuThreads || systemCaps.systemInfo.cpuCores,
      ttaMode: params.ttaMode,
      denoise: params.denoise,
      face_enhance: params.face_enhance,
      seamlessTextures: params.seamlessTextures || false,
      alphaChannel: params.alphaChannel !== false,
      memoryLimit: params.memoryLimit || Math.min(systemCaps.systemInfo.freeMemory * 0.8, 4096),
      enableMemoryOptimization: params.enableMemoryOptimization !== false
    });

    onProgress?.(40, "Starting AI upscaling process...");

    // Execute upscaling
    const result = await executeUpscaling(binaryPath, args, onProgress);
    
    if (!result.success) {
      throw new Error(result.error || "Upscaling process failed");
    }

    // Verify output file
    if (!fs.existsSync(outputPath)) {
      throw new Error("Upscaling completed but output file not found");
    }

    // Get final image metadata
    const finalMeta = await sharp(outputPath).metadata();
    const upscaledSize = {
      width: finalMeta.width || expectedWidth,
      height: finalMeta.height || expectedHeight
    };

    // Apply post-processing if requested
    if (params.postProcessing.sharpen || params.postProcessing.colorCorrection || params.postProcessing.contrastEnhancement) {
      onProgress?.(85, "Applying post-processing...");
      await applyPostProcessing(outputPath, params.postProcessing);
    }

    // Handle format conversion and compression if needed
    if (params.format !== 'png') {
      onProgress?.(90, "Converting output format...");
      await convertImageFormat(outputPath, params.format, params.compression, params.colorProfile);
    }

    // Preserve metadata if requested
    if (params.preserveMetadata) {
      onProgress?.(95, "Preserving metadata...");
      await copyImageMetadata(inputPath, outputPath);
    }

    onProgress?.(100, "Upscaling completed successfully!");

    const processingTime = Date.now() - startTime;

    return {
      success: true,
      outputPath,
      originalSize,
      upscaledSize,
      processingTime,
      model: params.model
    };

  } catch (error) {
    const processingTime = Date.now() - startTime;
    
    return {
      success: false,
      outputPath,
      originalSize: { width: 0, height: 0 },
      upscaledSize: { width: 0, height: 0 },
      processingTime,
      model: params.model,
      error: (error as Error).message
    };
  }
}

// Execute the upscaling process
async function executeUpscaling(
  binaryPath: string,
  args: string[],
  onProgress?: (progress: number, message: string) => void
): Promise<{ success: boolean; error?: string }> {
  return new Promise((resolve) => {
    const process = spawn(binaryPath, args, {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stderr = '';
    let stdout = '';

    process.stdout?.on('data', (data: Buffer) => {
      stdout += data.toString();
      
      // Parse progress from output (Real-ESRGAN typically outputs progress)
      const progressMatch = data.toString().match(/(\d+)%/);
      if (progressMatch) {
        const progress = Math.min(40 + parseInt(progressMatch[1]) * 0.5, 90);
        onProgress?.(progress, `Processing: ${progressMatch[1]}%`);
      }
    });

    process.stderr?.on('data', (data: Buffer) => {
      stderr += data.toString();
    });

    process.on('close', (code) => {
      if (code === 0) {
        resolve({ success: true });
      } else {
        resolve({ 
          success: false, 
          error: `Upscaling process exited with code ${code}: ${stderr}` 
        });
      }
    });

    process.on('error', (error) => {
      resolve({ 
        success: false, 
        error: `Failed to start upscaling process: ${error.message}` 
      });
    });
  });
}

// Software fallback using Sharp (basic bicubic upscaling)
async function fallbackUpscaling(
  inputPath: string,
  outputPath: string,
  params: UpscalingParamsType,
  originalSize: { width: number; height: number },
  targetWidth: number,
  targetHeight: number,
  startTime: number,
  onProgress?: (progress: number, message: string) => void
): Promise<{
  success: boolean;
  outputPath: string;
  originalSize: { width: number; height: number };
  upscaledSize: { width: number; height: number };
  processingTime: number;
  model: string;
  error?: string;
}> {
  try {
    onProgress?.(40, "Starting software-based upscaling...");
    let pipeline = sharp(inputPath);

    // Apply basic upscaling with Sharp
    pipeline = pipeline.resize(targetWidth, targetHeight, {
      kernel: sharp.kernel.lanczos3, // High-quality resampling
      fit: 'fill'
    });

    onProgress?.(70, "Applying quality enhancements...");
    // Apply sharpening to improve perceived quality
    pipeline = pipeline.sharpen(1.0); // Use simple sigma parameter

    onProgress?.(90, "Saving upscaled image...");
    // Save the result
    await pipeline.toFile(outputPath);

    const processingTime = Date.now() - startTime;
    
    return {
      success: true,
      outputPath,
      originalSize,
      upscaledSize: { width: targetWidth, height: targetHeight },
      processingTime,
      model: `${params.model} (software fallback)`
    };
  } catch (error) {
    const processingTime = Date.now() - startTime;
    
    return {
      success: false,
      outputPath,
      originalSize,
      upscaledSize: { width: 0, height: 0 },
      processingTime,
      model: params.model,
      error: (error as Error).message
    };
  }
}

// Apply comprehensive post-processing (Upscayl-style enhancements)
async function applyPostProcessing(
  imagePath: string,
  postProcessing: {
    sharpen: boolean;
    sharpenAmount: number;
    colorCorrection: boolean;
    contrastEnhancement: boolean;
  }
): Promise<void> {
  if (!postProcessing.sharpen && !postProcessing.colorCorrection && !postProcessing.contrastEnhancement) {
    return; // No post-processing needed
  }

  const tempPath = imagePath + '.postprocess';
  let pipeline = sharp(imagePath);

  // Apply sharpening
  if (postProcessing.sharpen) {
    pipeline = pipeline.sharpen(
      postProcessing.sharpenAmount, // sigma
      1, // flat
      2  // jagged
    );
  }

  // Apply color correction
  if (postProcessing.colorCorrection) {
    pipeline = pipeline.normalize(); // Auto-normalize colors
  }

  // Apply contrast enhancement
  if (postProcessing.contrastEnhancement) {
    pipeline = pipeline.modulate({
      brightness: 1.05,
      saturation: 1.1,
      hue: 0
    });
  }

  await pipeline.toFile(tempPath);
  fs.renameSync(tempPath, imagePath);
}

// Convert image format and apply compression with color profile support
async function convertImageFormat(
  imagePath: string,
  format: string,
  compression: number,
  colorProfile: string = 'auto'
): Promise<void> {
  const tempPath = imagePath + '.temp';
  
  let pipeline = sharp(imagePath);
  
  // Apply color profile if specified
  if (colorProfile !== 'auto') {
    switch (colorProfile) {
      case 'srgb':
        pipeline = pipeline.toColorspace('srgb');
        break;
      case 'adobe-rgb':
        // Adobe RGB would require ICC profile file
        break;
      case 'prophoto-rgb':
        // ProPhoto RGB would require ICC profile file
        break;
    }
  }
  
  switch (format.toLowerCase()) {
    case 'jpg':
    case 'jpeg':
      pipeline = pipeline.jpeg({ 
        quality: compression,
        progressive: true,
        mozjpeg: true
      });
      break;
    case 'webp':
      pipeline = pipeline.webp({ 
        quality: compression,
        effort: 6,
        lossless: compression >= 95
      });
      break;
    case 'tiff':
      pipeline = pipeline.tiff({ 
        compression: compression >= 90 ? 'lzw' : 'jpeg',
        quality: compression
      });
      break;
    case 'bmp':
      pipeline = pipeline.png({ compressionLevel: 0 }).toFormat('png'); // BMP via PNG
      break;
    case 'png':
    default:
      pipeline = pipeline.png({ 
        compressionLevel: Math.floor((100 - compression) / 10),
        progressive: true
      });
      break;
  }
  
  await pipeline.toFile(tempPath);
  
  // Replace original with converted version
  fs.renameSync(tempPath, imagePath);
}

// Copy metadata from source to destination
async function copyImageMetadata(sourcePath: string, destPath: string): Promise<void> {
  try {
    // This is a simplified metadata copying
    // In a real implementation, you'd use exiftool or similar
    const sourceMeta = await sharp(sourcePath).metadata();
    
    if (sourceMeta.exif || sourceMeta.icc) {
      const pipeline = sharp(destPath);
      
      if (sourceMeta.icc) {
        // Copy ICC profile for color accuracy
        // Convert Buffer to base64 string if needed, or use Sharp's built-in metadata handling
        pipeline.withMetadata();
      }
      
      await pipeline.toFile(destPath + '.meta');
      fs.renameSync(destPath + '.meta', destPath);
    }
  } catch (error) {
    // Metadata copying is optional, don't fail the entire process
    console.warn('Failed to copy metadata:', error);
  }
}

// Batch upscaling function
export async function batchUpscaleImages(
  inputPaths: string[],
  outputDir: string,
  params: UpscalingParamsType,
  onProgress?: (overall: number, current: string, itemProgress: number) => void
): Promise<{
  results: Array<{
    inputPath: string;
    outputPath: string;
    success: boolean;
    error?: string;
    processingTime: number;
  }>;
  totalProcessingTime: number;
}> {
  const startTime = Date.now();
  const results: Array<{
    inputPath: string;
    outputPath: string;
    success: boolean;
    error?: string;
    processingTime: number;
  }> = [];

  // Ensure output directory exists
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  for (let i = 0; i < inputPaths.length; i++) {
    const inputPath = inputPaths[i];
    const fileName = path.basename(inputPath, path.extname(inputPath));
    const outputPath = path.join(outputDir, `${fileName}_upscaled_${params.model}.${params.format}`);
    
    const overallProgress = (i / inputPaths.length) * 100;
    onProgress?.(overallProgress, `Processing ${fileName}...`, 0);
    
    const itemStartTime = Date.now();
    
    try {
      const result = await upscaleImage(
        inputPath,
        outputPath,
        params,
        (itemProgress, message) => {
          onProgress?.(overallProgress, message, itemProgress);
        }
      );
      
      results.push({
        inputPath,
        outputPath,
        success: result.success,
        error: result.error,
        processingTime: Date.now() - itemStartTime
      });
      
    } catch (error) {
      results.push({
        inputPath,
        outputPath,
        success: false,
        error: (error as Error).message,
        processingTime: Date.now() - itemStartTime
      });
    }
  }

  const totalProcessingTime = Date.now() - startTime;
  
  return {
    results,
    totalProcessingTime
  };
}

// Comprehensive natural language processing for upscaling commands (Complete Upscayl Feature Set)
export function parseUpscalingCommand(command: string): Partial<UpscalingParamsType> {
  const params: Partial<UpscalingParamsType> = {
    postProcessing: {
      sharpen: false,
      sharpenAmount: 0.5,
      colorCorrection: false,
      contrastEnhancement: false
    }
  };
  
  const lowerCommand = command.toLowerCase();
  
  // Extract model preferences with comprehensive matching
  if (lowerCommand.includes('anime') || lowerCommand.includes('cartoon') || lowerCommand.includes('manga')) {
    if (lowerCommand.includes('video') || lowerCommand.includes('frame')) {
      params.model = 'realesr-animevideov3-x4';
    } else {
      params.model = 'realesrgan-x4plus-anime';
    }
  } else if (lowerCommand.includes('photo') || lowerCommand.includes('realistic') || lowerCommand.includes('portrait')) {
    if (lowerCommand.includes('clean') || lowerCommand.includes('perfect')) {
      params.model = '4x-nmkd-superscale-sp-178000-g';
    } else {
      params.model = 'realesrgan-x4plus';
    }
  } else if (lowerCommand.includes('restore') || lowerCommand.includes('repair') || lowerCommand.includes('fix')) {
    params.model = 'uniscale-restore';
  } else if (lowerCommand.includes('fast') || lowerCommand.includes('quick') || lowerCommand.includes('speed')) {
    params.model = '4x-lsdir-compact-c3';
  } else if (lowerCommand.includes('lightweight') || lowerCommand.includes('v3')) {
    params.model = 'realesrgan-general-x4-v3';
  } else if (lowerCommand.includes('experimental') || lowerCommand.includes('unknown')) {
    params.model = 'unknown-2-0-1';
  }
  
  // Extract scale with multiple patterns
  const scalePatterns = [
    /(\d+)x/i,
    /(\d+) times/i,
    /scale.*?(\d+)/i,
    /upscale.*?(\d+)/i
  ];
  
  for (const pattern of scalePatterns) {
    const match = lowerCommand.match(pattern);
    if (match) {
      params.scale = parseInt(match[1]);
      break;
    }
  }
  
  // Handle special scale keywords
  if (lowerCommand.includes('double') || lowerCommand.includes('twice')) {
    params.scale = 2;
  } else if (lowerCommand.includes('triple')) {
    params.scale = 3;
  } else if (lowerCommand.includes('quadruple')) {
    params.scale = 4;
  }
  
  // Extract dimensions
  const dimensionMatch = lowerCommand.match(/(\d+)\s*[x×]\s*(\d+)/);
  if (dimensionMatch) {
    params.customWidth = parseInt(dimensionMatch[1]);
    params.customHeight = parseInt(dimensionMatch[2]);
  }
  
  // Extract quality and performance preferences
  if (lowerCommand.includes('high quality') || lowerCommand.includes('best quality') || lowerCommand.includes('maximum quality')) {
    params.ttaMode = true;
    params.tileSize = 256; // Smaller tiles for better quality
    params.enableMemoryOptimization = true;
  } else if (lowerCommand.includes('fast') || lowerCommand.includes('quick') || lowerCommand.includes('speed')) {
    params.ttaMode = false;
    params.tileSize = 1024; // Larger tiles for speed
    params.enableMemoryOptimization = false;
  } else if (lowerCommand.includes('balanced') || lowerCommand.includes('medium')) {
    params.ttaMode = false;
    params.tileSize = 512;
    params.enableMemoryOptimization = true;
  }
  
  // Extract format preferences
  if (lowerCommand.includes('png')) params.format = 'png';
  else if (lowerCommand.includes('jpg') || lowerCommand.includes('jpeg')) params.format = 'jpg';
  else if (lowerCommand.includes('webp')) params.format = 'webp';
  else if (lowerCommand.includes('tiff') || lowerCommand.includes('tif')) params.format = 'tiff';
  else if (lowerCommand.includes('bmp')) params.format = 'bmp';
  
  // Extract compression/quality settings
  const qualityMatch = lowerCommand.match(/quality[:\s]*(\d+)/i);
  if (qualityMatch) {
    params.compression = parseInt(qualityMatch[1]);
  } else if (lowerCommand.includes('lossless') || lowerCommand.includes('perfect')) {
    params.compression = 100;
  } else if (lowerCommand.includes('compressed') || lowerCommand.includes('small')) {
    params.compression = 70;
  }
  
  // Extract special features
  if (lowerCommand.includes('denoise') || lowerCommand.includes('clean up') || lowerCommand.includes('noise reduction')) {
    params.denoise = true;
  }
  
  if (lowerCommand.includes('face') || lowerCommand.includes('portrait') || lowerCommand.includes('people')) {
    params.face_enhance = true;
  }
  
  if (lowerCommand.includes('seamless') || lowerCommand.includes('tile') || lowerCommand.includes('texture')) {
    params.seamlessTextures = true;
  }
  
  if (lowerCommand.includes('transparent') || lowerCommand.includes('alpha') || lowerCommand.includes('transparency')) {
    params.alphaChannel = true;
  }
  
  // Extract post-processing options
  if (lowerCommand.includes('sharpen') || lowerCommand.includes('sharp')) {
    params.postProcessing!.sharpen = true;
    const sharpenMatch = lowerCommand.match(/sharpen[:\s]*(\d+(?:\.\d+)?)/i);
    if (sharpenMatch) {
      params.postProcessing!.sharpenAmount = parseFloat(sharpenMatch[1]);
    }
  }
  
  if (lowerCommand.includes('color correct') || lowerCommand.includes('normalize colors')) {
    params.postProcessing!.colorCorrection = true;
  }
  
  if (lowerCommand.includes('enhance contrast') || lowerCommand.includes('boost contrast')) {
    params.postProcessing!.contrastEnhancement = true;
  }
  
  // Extract color profile preferences
  if (lowerCommand.includes('srgb')) params.colorProfile = 'srgb';
  else if (lowerCommand.includes('adobe rgb')) params.colorProfile = 'adobe-rgb';
  else if (lowerCommand.includes('prophoto')) params.colorProfile = 'prophoto-rgb';
  
  // Extract memory and performance settings
  const memoryMatch = lowerCommand.match(/memory[:\s]*(\d+)\s*(?:mb|gb)?/i);
  if (memoryMatch) {
    let memory = parseInt(memoryMatch[1]);
    if (lowerCommand.includes('gb')) memory *= 1024;
    params.memoryLimit = memory;
  }
  
  const threadsMatch = lowerCommand.match(/threads?[:\s]*(\d+)/i);
  if (threadsMatch) {
    params.cpuThreads = parseInt(threadsMatch[1]);
  }
  
  // Extract GPU preferences
  const gpuMatch = lowerCommand.match(/gpu[:\s]*(\d+)/i);
  if (gpuMatch) {
    params.gpuId = gpuMatch[1];
  }
  
  return params;
}

// Model recommendation system based on content analysis
export function recommendModel(imagePath: string, userPreferences?: Partial<UpscalingParamsType>): Promise<string> {
  return new Promise(async (resolve) => {
    try {
      const metadata = await sharp(imagePath).metadata();
      const stats = await sharp(imagePath).stats();
      
      // Analyze image characteristics
      const isLowRes = (metadata.width || 0) < 512 || (metadata.height || 0) < 512;
      const hasAlpha = metadata.hasAlpha;
      const channels = metadata.channels || 3;
      
      // Simple heuristics for model recommendation
      if (userPreferences?.modelCategory === 'anime') {
        resolve('realesrgan-x4plus-anime');
      } else if (userPreferences?.modelCategory === 'photo') {
        resolve('4x-nmkd-superscale-sp-178000-g');
      } else if (userPreferences?.modelCategory === 'fast') {
        resolve('4x-lsdir-compact-c3');
      } else if (isLowRes && channels === 3) {
        // Likely a photo or artwork
        resolve('realesrgan-x4plus');
      } else if (hasAlpha) {
        // Has transparency, good for graphics
        resolve('realesrgan-x2plus');
      } else {
        // Default general purpose
        resolve('realesrgan-x4plus');
      }
    } catch {
      resolve('realesrgan-x4plus'); // Safe default
    }
  });
}

// Get available models by category
export function getModelsByCategory(category?: string): typeof UPSCALING_MODELS[keyof typeof UPSCALING_MODELS][] {
  if (!category) {
    return Object.values(UPSCALING_MODELS);
  }
  
  return Object.values(UPSCALING_MODELS).filter(model => 
    model.category === category
  );
}

// Validate upscaling parameters
export function validateUpscalingParams(params: Partial<UpscalingParamsType>): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (params.scale && (params.scale < 1 || params.scale > 8)) {
    errors.push('Scale must be between 1 and 8');
  }
  
  if (params.tileSize && (params.tileSize < 32 || params.tileSize > 1024)) {
    errors.push('Tile size must be between 32 and 1024');
  }
  
  if (params.compression && (params.compression < 0 || params.compression > 100)) {
    errors.push('Compression must be between 0 and 100');
  }
  
  if (params.memoryLimit && params.memoryLimit < 512) {
    errors.push('Memory limit must be at least 512 MB');
  }
  
  if (params.cpuThreads && (params.cpuThreads < 1 || params.cpuThreads > 32)) {
    errors.push('CPU threads must be between 1 and 32');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

export default {
  upscaleImage,
  batchUpscaleImages,
  parseUpscalingCommand,
  recommendModel,
  getModelsByCategory,
  validateUpscalingParams,
  UPSCALING_MODELS,
  UpscalingParams
};
