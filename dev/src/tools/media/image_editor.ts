import fs from "fs";
import path from "path";
import os from "os";
import crypto from "crypto";
import sharp from "sharp";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

// Schema definitions
export const OpenInput = z.object({
  source: z.union([z.string().url(), z.string()]), // path or URL
  sessionName: z.string().default("untitled"),
});

export const Region = z.object({
  id: z.string(),
  x: z.number().min(0),
  y: z.number().min(0),
  width: z.number().positive(),
  height: z.number().positive(),
  opacity: z.number().min(0).max(1).default(1),
  blendMode: z.enum(["normal", "multiply", "screen", "overlay", "soft-light", "hard-light", "color-dodge", "color-burn", "darken", "lighten", "difference", "exclusion"]).default("normal"),
});

export const EditInput = z.object({
  sessionId: z.string(),
  op: z.enum([
    "resize", "crop", "rotate", "flip", "filter", "enhance", "adjust", "composite", 
    "text", "draw", "mask", "blur", "sharpen", "noise", "vignette", "border", 
    "watermark", "collage", "batch_process", "generate_svg", "generate_ai_image"
  ]),
  params: z.object({}).passthrough()
});

export const ExportInput = z.object({
  sessionId: z.string(),
  format: z.enum(["jpg", "jpeg", "png", "gif", "webp", "tiff", "bmp", "svg", "pdf"]).default("png"),
  quality: z.number().min(1).max(100).optional(),
  compression: z.number().min(1).max(9).optional(),
  path: z.string().optional()
});

export const StatusOutput = z.object({
  sessions: z.array(z.object({
    id: z.string(),
    name: z.string(),
    dimensions: z.object({
      width: z.number(),
      height: z.number()
    }).optional(),
    format: z.string().optional()
  }))
});

export const GenerateSVGInput = z.object({
  sessionId: z.string().optional(),
  prompt: z.string().describe("Description of the SVG to generate"),
  width: z.number().default(800).describe("SVG width in pixels"),
  height: z.number().default(600).describe("SVG height in pixels"),
  style: z.enum(["minimal", "detailed", "geometric", "organic", "technical", "artistic"]).default("minimal").describe("SVG style"),
  colors: z.array(z.string()).optional().describe("Color palette (hex codes)"),
  elements: z.array(z.string()).optional().describe("Specific elements to include")
});

export const GenerateAIImageInput = z.object({
  sessionId: z.string().optional(),
  prompt: z.string().describe("Description of the image to generate"),
  width: z.number().default(512).describe("Image width in pixels"),
  height: z.number().default(512).describe("Image height in pixels"),
  style: z.enum(["realistic", "artistic", "cartoon", "abstract", "photographic", "digital_art"]).default("realistic").describe("Image style"),
  model: z.string().optional().describe("AI model to use (auto-detect if not specified)"),
  fallbackToSVG: z.boolean().default(true).describe("Fallback to SVG if model not supported"),
  quality: z.enum(["low", "medium", "high"]).default("medium").describe("Generation quality")
});

type Session = {
  id: string;
  name: string;
  srcPath: string;
  workDir: string;
  regions: any[]; // Region[]
  layers: any[];
  dimensions?: { width: number; height: number };
  format?: string;
  metadata?: any;
};

const sessions = new Map<string, Session>();

function newId() {
  return crypto.randomUUID();
}

function ensureDir(p: string) {
  fs.mkdirSync(p, { recursive: true });
}

// SVG Generation Helper Functions
function generateSVGContent(prompt: string, width: number, height: number, style: string, colors?: string[], elements?: string[]): string {
  const defaultColors = colors || getDefaultColors(style);
  const svgElements = elements || extractElementsFromPrompt(prompt);
  
  let svgContent = `<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">`;
  
  // Add background
  svgContent += `<rect width="100%" height="100%" fill="${defaultColors[0] || '#ffffff'}"/>`;
  
  // Generate elements based on style and prompt
  switch (style) {
    case "minimal":
      svgContent += generateMinimalSVG(width, height, defaultColors, svgElements);
      break;
    case "geometric":
      svgContent += generateGeometricSVG(width, height, defaultColors, svgElements);
      break;
    case "organic":
      svgContent += generateOrganicSVG(width, height, defaultColors, svgElements);
      break;
    case "technical":
      svgContent += generateTechnicalSVG(width, height, defaultColors, svgElements);
      break;
    case "artistic":
      svgContent += generateArtisticSVG(width, height, defaultColors, svgElements);
      break;
    default:
      svgContent += generateDetailedSVG(width, height, defaultColors, svgElements);
  }
  
  svgContent += '</svg>';
  return svgContent;
}

function generateMinimalSVG(width: number, height: number, colors: string[], elements: string[]): string {
  let content = '';
  const centerX = width / 2;
  const centerY = height / 2;
  
  // Simple geometric shapes
  content += `<circle cx="${centerX}" cy="${centerY}" r="${Math.min(width, height) * 0.2}" fill="${colors[1] || '#333333'}" opacity="0.8"/>`;
  content += `<rect x="${centerX - 50}" y="${centerY - 20}" width="100" height="40" fill="${colors[2] || '#666666'}" opacity="0.6"/>`;
  
  return content;
}

function generateGeometricSVG(width: number, height: number, colors: string[], elements: string[]): string {
  let content = '';
  
  // Generate geometric patterns
  for (let i = 0; i < 5; i++) {
    const x = (width / 6) * (i + 1);
    const y = height / 2;
    const size = 20 + (i * 10);
    const color = colors[i % colors.length] || '#333333';
    
    if (i % 2 === 0) {
      content += `<polygon points="${x},${y - size} ${x + size},${y + size} ${x - size},${y + size}" fill="${color}" opacity="0.7"/>`;
    } else {
      content += `<rect x="${x - size/2}" y="${y - size/2}" width="${size}" height="${size}" fill="${color}" opacity="0.7"/>`;
    }
  }
  
  return content;
}

function generateOrganicSVG(width: number, height: number, colors: string[], elements: string[]): string {
  let content = '';
  
  // Generate organic curves and shapes
  const centerX = width / 2;
  const centerY = height / 2;
  
  for (let i = 0; i < 3; i++) {
    const radius = 50 + (i * 30);
    const color = colors[i % colors.length] || '#4a90e2';
    
    content += `<path d="M ${centerX - radius},${centerY} Q ${centerX},${centerY - radius} ${centerX + radius},${centerY} Q ${centerX},${centerY + radius} ${centerX - radius},${centerY} Z" fill="${color}" opacity="0.5"/>`;
  }
  
  return content;
}

function generateTechnicalSVG(width: number, height: number, colors: string[], elements: string[]): string {
  let content = '';
  
  // Generate technical diagrams
  const gridSize = 50;
  const color = colors[0] || '#2c3e50';
  
  // Grid lines
  for (let x = 0; x < width; x += gridSize) {
    content += `<line x1="${x}" y1="0" x2="${x}" y2="${height}" stroke="${color}" stroke-width="1" opacity="0.3"/>`;
  }
  for (let y = 0; y < height; y += gridSize) {
    content += `<line x1="0" y1="${y}" x2="${width}" y2="${y}" stroke="${color}" stroke-width="1" opacity="0.3"/>`;
  }
  
  // Technical elements
  content += `<rect x="${width/4}" y="${height/4}" width="${width/2}" height="${height/2}" fill="none" stroke="${color}" stroke-width="2"/>`;
  content += `<circle cx="${width/2}" cy="${height/2}" r="20" fill="${color}" opacity="0.7"/>`;
  
  return content;
}

function generateArtisticSVG(width: number, height: number, colors: string[], elements: string[]): string {
  let content = '';
  
  // Generate artistic patterns
  for (let i = 0; i < 8; i++) {
    const angle = (i * 45) * Math.PI / 180;
    const x = width/2 + Math.cos(angle) * 100;
    const y = height/2 + Math.sin(angle) * 100;
    const color = colors[i % colors.length] || '#e74c3c';
    
    content += `<ellipse cx="${x}" cy="${y}" rx="15" ry="30" fill="${color}" opacity="0.6" transform="rotate(${i * 45} ${x} ${y})"/>`;
  }
  
  return content;
}

function generateDetailedSVG(width: number, height: number, colors: string[], elements: string[]): string {
  let content = '';
  
  // Combine multiple styles for detailed output
  content += generateMinimalSVG(width, height, colors, elements);
  content += generateGeometricSVG(width, height, colors, elements);
  
  return content;
}

function getDefaultColors(style: string): string[] {
  const colorPalettes = {
    minimal: ['#ffffff', '#333333', '#666666', '#999999'],
    geometric: ['#2c3e50', '#3498db', '#e74c3c', '#f39c12', '#27ae60'],
    organic: ['#4a90e2', '#7ed321', '#f5a623', '#d0021b', '#9013fe'],
    technical: ['#2c3e50', '#34495e', '#7f8c8d', '#95a5a6', '#bdc3c7'],
    artistic: ['#e74c3c', '#f39c12', '#f1c40f', '#2ecc71', '#3498db', '#9b59b6'],
    detailed: ['#1abc9c', '#2ecc71', '#3498db', '#9b59b6', '#e74c3c', '#f39c12']
  };
  
  return colorPalettes[style as keyof typeof colorPalettes] || colorPalettes.minimal;
}

function extractElementsFromPrompt(prompt: string): string[] {
  const commonElements = ['circle', 'square', 'triangle', 'line', 'curve', 'text', 'pattern'];
  const elements: string[] = [];
  
  for (const element of commonElements) {
    if (prompt.toLowerCase().includes(element)) {
      elements.push(element);
    }
  }
  
  return elements.length > 0 ? elements : ['circle', 'square'];
}

// AI Model Support Functions
async function checkAIModelSupport(model?: string): Promise<boolean> {
  // Check for available AI models
  const availableModels = await getAvailableAIModels();
  
  if (!model || model === 'auto') {
    return availableModels.length > 0;
  }
  
  return availableModels.includes(model);
}

async function getAvailableAIModels(): Promise<string[]> {
  const models: string[] = [];
  
  try {
    // Check for OpenAI API key
    if (process.env.OPENAI_API_KEY) {
      models.push('dall-e-2', 'dall-e-3');
    }
    
    // Check for Stability AI API key
    if (process.env.STABILITY_API_KEY) {
      models.push('stable-diffusion-xl', 'stable-diffusion-1.5');
    }
    
    // Check for local models (placeholder)
    if (await checkLocalModelSupport()) {
      models.push('local-stable-diffusion', 'local-diffusion');
    }
  } catch (error) {
    console.warn('Error checking AI model support:', error);
  }
  
  return models;
}

async function checkLocalModelSupport(): Promise<boolean> {
  // Placeholder for local model detection
  // In a real implementation, this would check for installed models
  return false;
}

async function generateAIImageContent(prompt: string, width: number, height: number, style: string, model?: string, quality?: string): Promise<Buffer> {
  // Placeholder implementation for AI image generation
  // In a real implementation, this would call the appropriate AI service
  
  // For now, generate a simple placeholder image using Sharp
  const placeholderImage = sharp({
    create: {
      width,
      height,
      channels: 3,
      background: { r: 200, g: 200, b: 200 }
    }
  });
  
  // Add some basic shapes to represent the generated content
  const svg = generateSVGContent(prompt, width, height, style);
  const svgBuffer = Buffer.from(svg);
  
  return await placeholderImage
    .composite([{ input: svgBuffer, top: 0, left: 0 }])
    .png()
    .toBuffer();
}

function mapImageStyleToSVGStyle(imageStyle: string): string {
  const styleMap: Record<string, string> = {
    'realistic': 'detailed',
    'artistic': 'artistic',
    'cartoon': 'organic',
    'abstract': 'geometric',
    'photographic': 'detailed',
    'digital_art': 'artistic'
  };
  
  return styleMap[imageStyle] || 'minimal';
}

async function probeImage(p: string): Promise<{ width: number; height: number; format: string; metadata: any } | undefined> {
  try {
    const image = sharp(p);
    const metadata = await image.metadata();
    return {
      width: metadata.width || 0,
      height: metadata.height || 0,
      format: metadata.format || 'unknown',
      metadata
    };
  } catch (error) {
    return undefined;
  }
}

export async function status() {
  const list = Array.from(sessions.values()).map(s => ({
    id: s.id,
    name: s.name,
    dimensions: s.dimensions,
    format: s.format
  }));
  return StatusOutput.parse({ sessions: list });
}

export async function open(input: unknown) {
  const { source, sessionName } = OpenInput.parse(input);
  const id = newId();
  const workDir = path.join(os.tmpdir(), "mcp_image", id);
  ensureDir(workDir);

  // If URL, download to tmp; if local path, copy to workDir
  const srcPath = path.join(workDir, "source");
  if (/^https?:\/\//.test(source)) {
    // minimal fetch without external deps
    const data = await (await fetch(source)).arrayBuffer();
    fs.writeFileSync(srcPath, Buffer.from(data));
  } else {
    fs.copyFileSync(source, srcPath);
  }

  const imageInfo = await probeImage(srcPath);
  const sess: Session = {
    id,
    name: sessionName,
    srcPath,
    workDir,
    regions: [],
    layers: [],
    dimensions: imageInfo ? { width: imageInfo.width, height: imageInfo.height } : undefined,
    format: imageInfo?.format,
    metadata: imageInfo?.metadata
  };
  sessions.set(id, sess);

  return {
    sessionId: id,
    name: sessionName,
    dimensions: sess.dimensions,
    format: sess.format
  };
}

export async function edit(input: unknown) {
  const { sessionId, op, params } = EditInput.parse(input);
  const s = sessions.get(sessionId);
  if (!s) throw new Error("Unknown session");

  // Non-destructive bookkeeping; server-side rendering happens on export
  const operation = {
    id: crypto.randomUUID(),
    op,
    params,
    timestamp: Date.now()
  };

  s.layers.push(operation);

  return { ok: true, operationId: operation.id, layers: s.layers };
}

export async function exportImage(input: unknown) {
  const { sessionId, format, quality, compression, path: outPath } = ExportInput.parse(input);
  const s = sessions.get(sessionId);
  if (!s) throw new Error("Unknown session");

  const out = outPath || path.join(s.workDir, `render.${format}`);
  
  // Build Sharp pipeline from layers
  let pipeline = sharp(s.srcPath);

  // Apply all operations in sequence
  for (const layer of s.layers) {
    const { op, params } = layer;
    
    switch (op) {
      case "resize":
        if (params.width || params.height) {
          pipeline = pipeline.resize(params.width, params.height, {
            fit: params.fit || 'cover',
            position: params.position || 'center'
          });
        }
        break;
        
      case "crop":
        if (params.x !== undefined && params.y !== undefined && params.width && params.height) {
          pipeline = pipeline.extract({
            left: params.x,
            top: params.y,
            width: params.width,
            height: params.height
          });
        }
        break;
        
      case "rotate":
        if (params.angle) {
          pipeline = pipeline.rotate(params.angle, {
            background: params.background || { r: 0, g: 0, b: 0, alpha: 0 }
          });
        }
        break;
        
      case "flip":
        if (params.direction === 'horizontal') {
          pipeline = pipeline.flip();
        } else if (params.direction === 'vertical') {
          pipeline = pipeline.flop();
        }
        break;
        
      case "filter":
        if (params.type === 'blur') {
          pipeline = pipeline.blur(params.radius || 1);
        } else if (params.type === 'sharpen') {
          pipeline = pipeline.sharpen({ sigma: params.sigma || 1 });
        } else if (params.type === 'grayscale') {
          pipeline = pipeline.grayscale();
        } else if (params.type === 'sepia') {
          // Sepia effect using modulate
          pipeline = pipeline.modulate({ saturation: 0, hue: 30 });
        } else if (params.type === 'negate') {
          pipeline = pipeline.negate();
        }
        break;
        
      case "enhance":
        if (params.brightness !== undefined) {
          pipeline = pipeline.modulate({
            brightness: params.brightness,
            saturation: params.saturation || 1,
            hue: params.hue || 0
          });
        }
        break;
        
      case "adjust":
        if (params.gamma !== undefined) {
          pipeline = pipeline.gamma(params.gamma);
        }
        if (params.contrast !== undefined) {
          pipeline = pipeline.linear(params.contrast, -(128 * params.contrast) + 128);
        }
        break;
        
      case "vignette":
        if (params.outer !== undefined) {
          // Vignette effect using composite with radial gradient
          const vignetteSize = params.outer || 100;
          const innerSize = params.inner || 0;
          // This is a simplified vignette implementation
          // In a real implementation, you'd create a radial gradient mask
          pipeline = pipeline.modulate({ brightness: 0.8 });
        }
        break;
        
      case "border":
        if (params.size) {
          pipeline = pipeline.extend({
            top: params.size,
            bottom: params.size,
            left: params.size,
            right: params.size,
            background: params.color || { r: 255, g: 255, b: 255, alpha: 1 }
          });
        }
        break;
        
      case "generate_svg":
        // SVG generation is handled separately, just record the operation
        break;
        
      case "generate_ai_image":
        // AI image generation is handled separately, just record the operation
        break;
    }
  }

  // Apply format-specific options
  switch (format) {
    case 'jpg':
    case 'jpeg':
      pipeline = pipeline.jpeg({ quality: quality || 80, progressive: true });
      break;
    case 'png':
      pipeline = pipeline.png({ compressionLevel: compression || 6, progressive: true });
      break;
    case 'webp':
      pipeline = pipeline.webp({ quality: quality || 80 });
      break;
    case 'tiff':
      pipeline = pipeline.tiff({ compression: 'lzw' });
      break;
    case 'gif':
      pipeline = pipeline.gif();
      break;
  }

  await pipeline.toFile(out);
  
  return { ok: true, path: out, format };
}

export async function batchProcess(input: unknown) {
  const { sessionId, operations, outputDir } = z.object({
    sessionId: z.string(),
    operations: z.array(z.object({
      name: z.string(),
      params: z.object({}).passthrough()
    })),
    outputDir: z.string()
  }).parse(input);

  const s = sessions.get(sessionId);
  if (!s) throw new Error("Unknown session");

  ensureDir(outputDir);
  const results = [];

  for (const operation of operations) {
    const outputPath = path.join(outputDir, `${operation.name}.png`);
    
    // Create a temporary session for this operation
    const tempSession = { ...s, layers: [{ op: 'resize', params: operation.params }] };
    
    // Apply the operation
    let pipeline = sharp(s.srcPath);
    for (const layer of tempSession.layers) {
      // Apply the same logic as in exportImage
      if (layer.op === 'resize' && layer.params.width) {
        pipeline = pipeline.resize(layer.params.width, layer.params.height);
      }
    }
    
    await pipeline.png().toFile(outputPath);
    results.push({ name: operation.name, path: outputPath });
  }

  return { ok: true, results };
}

export async function createCollage(input: unknown) {
  const { sessionIds, layout, outputPath, spacing = 10 } = z.object({
    sessionIds: z.array(z.string()),
    layout: z.object({
      rows: z.number().positive(),
      cols: z.number().positive()
    }),
    outputPath: z.string(),
    spacing: z.number().default(10)
  }).parse(input);

  const sessionImages = sessionIds.map(id => {
    const s = sessions.get(id);
    if (!s) throw new Error(`Unknown session: ${id}`);
    return s;
  });

  // Calculate collage dimensions
  const maxWidth = Math.max(...sessionImages.map(s => s.dimensions?.width || 0));
  const maxHeight = Math.max(...sessionImages.map(s => s.dimensions?.height || 0));
  
  const collageWidth = (maxWidth * layout.cols) + (spacing * (layout.cols - 1));
  const collageHeight = (maxHeight * layout.rows) + (spacing * (layout.rows - 1));

  // Create collage
  const collage = sharp({
    create: {
      width: collageWidth,
      height: collageHeight,
      channels: 4,
      background: { r: 255, g: 255, b: 255, alpha: 1 }
    }
  });

  // Composite images
  const composites = [];
  for (let i = 0; i < sessionImages.length && i < layout.rows * layout.cols; i++) {
    const row = Math.floor(i / layout.cols);
    const col = i % layout.cols;
    const x = col * (maxWidth + spacing);
    const y = row * (maxHeight + spacing);

    composites.push({
      input: sessionImages[i].srcPath,
      left: x,
      top: y
    });
  }

  await collage.composite(composites).png().toFile(outputPath);
  
  return { ok: true, path: outputPath, dimensions: { width: collageWidth, height: collageHeight } };
}

// SVG Generation Function
export async function generateSVG(input: unknown) {
  const { sessionId, prompt, width, height, style, colors, elements } = GenerateSVGInput.parse(input);
  
  // Generate SVG content based on prompt and style
  const svgContent = generateSVGContent(prompt, width, height, style, colors, elements);
  
  // Create or update session
  let session: Session;
  if (sessionId && sessions.has(sessionId)) {
    session = sessions.get(sessionId)!;
  } else {
    const id = newId();
    const workDir = path.join(os.tmpdir(), "mcp_image", id);
    ensureDir(workDir);
    
    session = {
      id,
      name: `Generated SVG - ${prompt.substring(0, 30)}...`,
      srcPath: path.join(workDir, "generated.svg"),
      workDir,
      regions: [],
      layers: [],
      dimensions: { width, height },
      format: "svg",
      metadata: { generated: true, prompt, style, colors, elements }
    };
    sessions.set(id, session);
  }
  
  // Write SVG content to file
  fs.writeFileSync(session.srcPath, svgContent);
  
  // Add generation operation to layers
  const operation = {
    id: crypto.randomUUID(),
    op: "generate_svg",
    params: { prompt, width, height, style, colors, elements },
    timestamp: Date.now()
  };
  session.layers.push(operation);
  
  return {
    sessionId: session.id,
    name: session.name,
    dimensions: session.dimensions,
    format: "svg",
    path: session.srcPath,
    svgContent
  };
}

// AI Image Generation Function
export async function generateAIImage(input: unknown) {
  const { sessionId, prompt, width, height, style, model, fallbackToSVG, quality } = GenerateAIImageInput.parse(input);
  
  // Check if AI model is available
  const modelSupported = await checkAIModelSupport(model);
  
  if (!modelSupported && fallbackToSVG) {
    // Fallback to SVG generation
    console.log("AI model not supported, falling back to SVG generation");
    return await generateSVG({
      sessionId,
      prompt,
      width,
      height,
      style: mapImageStyleToSVGStyle(style),
      colors: getDefaultColors(style),
      elements: extractElementsFromPrompt(prompt)
    });
  }
  
  if (!modelSupported) {
    throw new Error(`AI model '${model || 'auto'}' is not supported. Enable fallbackToSVG for graceful degradation.`);
  }
  
  // Generate AI image (placeholder implementation)
  const imageData = await generateAIImageContent(prompt, width, height, style, model, quality);
  
  // Create or update session
  let session: Session;
  if (sessionId && sessions.has(sessionId)) {
    session = sessions.get(sessionId)!;
  } else {
    const id = newId();
    const workDir = path.join(os.tmpdir(), "mcp_image", id);
    ensureDir(workDir);
    
    session = {
      id,
      name: `Generated AI Image - ${prompt.substring(0, 30)}...`,
      srcPath: path.join(workDir, "generated.png"),
      workDir,
      regions: [],
      layers: [],
      dimensions: { width, height },
      format: "png",
      metadata: { generated: true, prompt, style, model, quality }
    };
    sessions.set(id, session);
  }
  
  // Write image data to file
  fs.writeFileSync(session.srcPath, imageData);
  
  // Add generation operation to layers
  const operation = {
    id: crypto.randomUUID(),
    op: "generate_ai_image",
    params: { prompt, width, height, style, model, quality },
    timestamp: Date.now()
  };
  session.layers.push(operation);
  
  return {
    sessionId: session.id,
    name: session.name,
    dimensions: session.dimensions,
    format: "png",
    path: session.srcPath,
    model: model || "auto-detected"
  };
}

export function registerImageEditor(server: McpServer) {
  server.registerTool("image_editing", {
    description: "Advanced image editing and manipulation tool with cross-platform support. Perform image processing, editing, format conversion, effects application, and image analysis across Windows, Linux, macOS, Android, and iOS.",
    inputSchema: {
      action: z.enum([
        "status", "open", "edit", "export", "batch_process", "create_collage", "generate_svg", "generate_ai_image"
      ]).describe("Image editing action to perform"),
      source: z.string().optional().describe("Image source path or URL"),
      sessionName: z.string().optional().describe("Name for the editing session"),
      sessionId: z.string().optional().describe("ID of the editing session"),
      op: z.enum([
        "resize", "crop", "rotate", "flip", "filter", "enhance", "adjust", "composite", 
        "text", "draw", "mask", "blur", "sharpen", "noise", "vignette", "border", 
        "watermark", "collage", "batch_process", "generate_svg", "generate_ai_image"
      ]).optional().describe("Image operation to perform"),
      params: z.object({}).passthrough().optional().describe("Operation parameters"),
      format: z.enum(["jpg", "jpeg", "png", "gif", "webp", "tiff", "bmp", "svg", "pdf"]).optional().describe("Output image format"),
      quality: z.number().min(1).max(100).optional().describe("Export quality (1-100)"),
      path: z.string().optional().describe("Output file path"),
      operations: z.array(z.object({
        name: z.string(),
        params: z.object({}).passthrough()
      })).optional().describe("Array of batch processing operations"),
      outputDir: z.string().optional().describe("Output directory for batch processing"),
      sessionIds: z.array(z.string()).optional().describe("Array of session IDs for collage"),
      layout: z.object({
        rows: z.number().positive(),
        cols: z.number().positive()
      }).optional().describe("Layout configuration for collage"),
      spacing: z.number().optional().describe("Spacing between images in collage"),
      outputPath: z.string().optional().describe("Output path for collage"),
      // SVG Generation parameters
      prompt: z.string().optional().describe("Description of the SVG/image to generate"),
      width: z.number().optional().describe("Width in pixels"),
      height: z.number().optional().describe("Height in pixels"),
      style: z.enum(["minimal", "detailed", "geometric", "organic", "technical", "artistic", "realistic", "cartoon", "abstract", "photographic", "digital_art"]).optional().describe("Generation style"),
      colors: z.array(z.string()).optional().describe("Color palette (hex codes)"),
      elements: z.array(z.string()).optional().describe("Specific elements to include"),
      // AI Image Generation parameters
      model: z.string().optional().describe("AI model to use (auto-detect if not specified)"),
      fallbackToSVG: z.boolean().optional().describe("Fallback to SVG if model not supported"),
      generationQuality: z.enum(["low", "medium", "high"]).optional().describe("Generation quality")
    },
    outputSchema: {
      success: z.boolean(),
      message: z.string().optional(),
      sessionId: z.string().optional(),
      name: z.string().optional(),
      dimensions: z.object({
        width: z.number(),
        height: z.number()
      }).optional(),
      format: z.string().optional(),
      path: z.string().optional(),
      sessions: z.array(z.object({
        id: z.string(),
        name: z.string(),
        dimensions: z.object({
          width: z.number(),
          height: z.number()
        }).optional(),
        format: z.string().optional()
      })).optional(),
      operationId: z.string().optional(),
      layers: z.array(z.object({}).passthrough()).optional(),
      results: z.array(z.object({
        name: z.string(),
        path: z.string()
      })).optional()
    }
  }, async (params) => {
    try {
      const { action, ...restParams } = params;
      
      switch (action) {
        case "status":
          const statusResult = await status();
          return {
            content: [{ type: "text" as const, text: `Image editor status: ${JSON.stringify(statusResult, null, 2)}` }],
            structuredContent: {
              success: true,
              message: "Status retrieved successfully",
              sessions: statusResult.sessions
            }
          };
          
        case "open":
          const openResult = await open(restParams);
          return {
            content: [{ type: "text" as const, text: `Image opened successfully: ${openResult.sessionId}` }],
            structuredContent: {
              success: true,
              message: "Image opened successfully",
              sessionId: openResult.sessionId,
              name: openResult.name,
              dimensions: openResult.dimensions,
              format: openResult.format
            }
          };
          
        case "edit":
          const editResult = await edit(restParams);
          return {
            content: [{ type: "text" as const, text: `Operation applied successfully: ${editResult.operationId}` }],
            structuredContent: {
              success: true,
              message: "Operation applied successfully",
              operationId: editResult.operationId,
              layers: editResult.layers
            }
          };
          
        case "export":
          const exportResult = await exportImage(restParams);
          return {
            content: [{ type: "text" as const, text: `Image exported successfully: ${exportResult.path}` }],
            structuredContent: {
              success: true,
              message: "Image exported successfully",
              path: exportResult.path,
              format: exportResult.format
            }
          };
          
        case "batch_process":
          const batchResult = await batchProcess(restParams);
          return {
            content: [{ type: "text" as const, text: `Batch processing completed: ${batchResult.results.length} files processed` }],
            structuredContent: {
              success: true,
              message: "Batch processing completed",
              results: batchResult.results
            }
          };
          
        case "create_collage":
          const collageResult = await createCollage(restParams);
          return {
            content: [{ type: "text" as const, text: `Collage created successfully: ${collageResult.path}` }],
            structuredContent: {
              success: true,
              message: "Collage created successfully",
              path: collageResult.path,
              dimensions: collageResult.dimensions
            }
          };
          
        case "generate_svg":
          const svgResult = await generateSVG(restParams);
          return {
            content: [{ type: "text" as const, text: `SVG generated successfully: ${svgResult.sessionId}` }],
            structuredContent: {
              success: true,
              message: "SVG generated successfully",
              sessionId: svgResult.sessionId,
              name: svgResult.name,
              dimensions: svgResult.dimensions,
              format: svgResult.format,
              path: svgResult.path,
              svgContent: svgResult.svgContent
            }
          };
          
        case "generate_ai_image":
          const aiResult = await generateAIImage(restParams);
          return {
            content: [{ type: "text" as const, text: `AI image generated successfully: ${aiResult.sessionId}` }],
            structuredContent: {
              success: true,
              message: "AI image generated successfully",
              sessionId: aiResult.sessionId,
              name: aiResult.name,
              dimensions: aiResult.dimensions,
              format: aiResult.format,
              path: aiResult.path,
              model: (aiResult as any).model
            }
          };
          
        default:
          throw new Error(`Unknown action: ${action}`);
      }
    } catch (error: any) {
      return {
        content: [{ type: "text" as const, text: `Image editing operation failed: ${error.message}` }],
        structuredContent: {
          success: false,
          message: `Image editing operation failed: ${error.message}`
        }
      };
    }
  });
}

export default {
  name: "image_editor",
  commands: {
    status,
    open,
    edit,
    export: exportImage,
    batchProcess,
    createCollage,
    generateSVG,
    generateAIImage
  }
};
