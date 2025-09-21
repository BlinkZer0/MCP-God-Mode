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

// AI Upscaling Models (based on Upscayl/Real-ESRGAN)
export const UPSCALING_MODELS = {
  "realesrgan-x4plus": {
    id: "realesrgan-x4plus",
    name: "Real-ESRGAN x4plus",
    scale: 4,
    description: "General purpose 4x upscaling model, good for photos and artwork"
  },
  "realesrgan-x4plus-anime": {
    id: "realesrgan-x4plus-anime",
    name: "Real-ESRGAN x4plus Anime",
    scale: 4,
    description: "Optimized for anime and cartoon images"
  },
  "realesrgan-x2plus": {
    id: "realesrgan-x2plus",
    name: "Real-ESRGAN x2plus",
    scale: 2,
    description: "2x upscaling model for moderate enhancement"
  },
  "esrgan-x4": {
    id: "esrgan-x4",
    name: "ESRGAN x4",
    scale: 4,
    description: "Classic ESRGAN model for 4x upscaling"
  },
  "waifu2x-cunet": {
    id: "waifu2x-cunet",
    name: "Waifu2x CUNet",
    scale: 2,
    description: "Waifu2x model optimized for anime/artwork"
  }
} as const;

export type UpscalingModelId = keyof typeof UPSCALING_MODELS;

// Upscaling Parameters Schema
export const UpscalingParams = z.object({
  model: z.string().default("realesrgan-x4plus").describe("AI upscaling model to use"),
  scale: z.number().min(1).max(8).optional().describe("Custom scale factor (overrides model default)"),
  customWidth: z.number().optional().describe("Target width in pixels (alternative to scale)"),
  customHeight: z.number().optional().describe("Target height in pixels (alternative to scale)"),
  tileSize: z.number().min(32).max(1024).default(512).describe("Tile size for processing large images"),
  gpuId: z.string().optional().describe("GPU device ID for acceleration"),
  format: z.enum(["png", "jpg", "jpeg", "webp", "tiff"]).default("png").describe("Output image format"),
  compression: z.number().min(0).max(100).default(90).describe("Compression quality for lossy formats"),
  ttaMode: z.boolean().default(false).describe("Test-time augmentation for better quality (slower)"),
  preserveMetadata: z.boolean().default(true).describe("Preserve original image metadata"),
  denoise: z.boolean().default(true).describe("Apply denoising during upscaling"),
  face_enhance: z.boolean().default(false).describe("Enable face enhancement (if supported by model)")
});

export type UpscalingParamsType = {
  model: string;
  scale?: number;
  customWidth?: number;
  customHeight?: number;
  tileSize: number;
  gpuId?: string;
  format: "png" | "jpg" | "jpeg" | "webp" | "tiff";
  compression: number;
  ttaMode: boolean;
  preserveMetadata: boolean;
  denoise: boolean;
  face_enhance: boolean;
};

// Cross-platform binary paths
function getUpscalerBinaryPath(): string {
  const platform = os.platform();
  const arch = os.arch();
  
  // These would be the actual binary paths in a real implementation
  // For now, we'll use a placeholder that would need to be populated with actual binaries
  const binaryName = platform === 'win32' ? 'realesrgan-ncnn-vulkan.exe' : 'realesrgan-ncnn-vulkan';
  
  // In a real implementation, these binaries would be bundled with the application
  const binaryDir = path.join(__dirname, '..', '..', '..', 'resources', 'upscaler', platform, arch);
  return path.join(binaryDir, binaryName);
}

function getModelsPath(): string {
  // Path to AI models directory
  return path.join(__dirname, '..', '..', '..', 'resources', 'upscaler', 'models');
}

// Validate GPU availability
async function checkGPUSupport(): Promise<{ hasVulkan: boolean; hasOpenCL: boolean; gpuDevices: string[] }> {
  return new Promise((resolve) => {
    // In a real implementation, this would check for Vulkan/OpenCL support
    // For now, we'll assume basic GPU support is available
    resolve({
      hasVulkan: true,
      hasOpenCL: true,
      gpuDevices: ['0'] // Default GPU device
    });
  });
}

// Generate upscaling command arguments
function getUpscalingArguments(params: {
  inputPath: string;
  outputPath: string;
  model: string;
  scale?: number;
  customWidth?: number;
  customHeight?: number;
  tileSize: number;
  gpuId?: string;
  ttaMode: boolean;
  denoise: boolean;
  face_enhance: boolean;
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
    ttaMode,
    denoise,
    face_enhance
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

  // Additional options
  if (ttaMode) {
    args.push('-x'); // TTA mode
  }

  if (denoise) {
    args.push('-d'); // Denoise
  }

  if (face_enhance) {
    args.push('-f'); // Face enhancement
  }

  // Format (handled by output extension)
  args.push('-f', 'png'); // Default to PNG for quality

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

    // Check GPU support
    const gpuInfo = await checkGPUSupport();
    onProgress?.(10, "Checking GPU support...");

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
      return await fallbackUpscaling(inputPath, outputPath, params, originalSize, expectedWidth, expectedHeight, startTime);
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
      gpuId: params.gpuId || (gpuInfo.gpuDevices[0] || '0'),
      ttaMode: params.ttaMode,
      denoise: params.denoise,
      face_enhance: params.face_enhance
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

    // Handle format conversion and compression if needed
    if (params.format !== 'png') {
      onProgress?.(90, "Converting output format...");
      await convertImageFormat(outputPath, params.format, params.compression);
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
  startTime: number
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
    let pipeline = sharp(inputPath);

    // Apply basic upscaling with Sharp
    pipeline = pipeline.resize(targetWidth, targetHeight, {
      kernel: sharp.kernel.lanczos3, // High-quality resampling
      fit: 'fill'
    });

    // Apply sharpening to improve perceived quality
    pipeline = pipeline.sharpen({ sigma: 1.0 });

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

// Convert image format and apply compression
async function convertImageFormat(
  imagePath: string,
  format: string,
  compression: number
): Promise<void> {
  const tempPath = imagePath + '.temp';
  
  let pipeline = sharp(imagePath);
  
  switch (format.toLowerCase()) {
    case 'jpg':
    case 'jpeg':
      pipeline = pipeline.jpeg({ quality: compression });
      break;
    case 'webp':
      pipeline = pipeline.webp({ quality: compression });
      break;
    case 'tiff':
      pipeline = pipeline.tiff({ compression: 'lzw' });
      break;
    case 'png':
    default:
      pipeline = pipeline.png({ compressionLevel: Math.floor(compression / 10) });
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

// Natural language processing for upscaling commands
export function parseUpscalingCommand(command: string): Partial<UpscalingParamsType> {
  const params: Partial<UpscalingParamsType> = {};
  
  // Extract model preferences
  if (command.includes('anime') || command.includes('cartoon')) {
    params.model = 'realesrgan-x4plus-anime';
  } else if (command.includes('photo') || command.includes('realistic')) {
    params.model = 'realesrgan-x4plus';
  } else if (command.includes('2x') || command.includes('double')) {
    params.model = 'realesrgan-x2plus';
  }
  
  // Extract scale
  const scaleMatch = command.match(/(\d+)x/i);
  if (scaleMatch) {
    params.scale = parseInt(scaleMatch[1]);
  }
  
  // Extract dimensions
  const dimensionMatch = command.match(/(\d+)\s*[x×]\s*(\d+)/);
  if (dimensionMatch) {
    params.customWidth = parseInt(dimensionMatch[1]);
    params.customHeight = parseInt(dimensionMatch[2]);
  }
  
  // Extract quality preferences
  if (command.includes('high quality') || command.includes('best quality')) {
    params.ttaMode = true;
    params.tileSize = 256; // Smaller tiles for better quality
  } else if (command.includes('fast') || command.includes('quick')) {
    params.ttaMode = false;
    params.tileSize = 1024; // Larger tiles for speed
  }
  
  // Extract format
  if (command.includes('png')) params.format = 'png';
  else if (command.includes('jpg') || command.includes('jpeg')) params.format = 'jpg';
  else if (command.includes('webp')) params.format = 'webp';
  
  // Extract special features
  if (command.includes('denoise') || command.includes('clean up')) {
    params.denoise = true;
  }
  
  if (command.includes('face') || command.includes('portrait')) {
    params.face_enhance = true;
  }
  
  return params;
}

export default {
  upscaleImage,
  batchUpscaleImages,
  parseUpscalingCommand,
  UPSCALING_MODELS,
  UpscalingParams
};
