#!/usr/bin/env node

import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.MEDIA_EDITOR_PORT || 3001;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from the media web directory
app.use(express.static(path.join(__dirname, 'web')));

// Enhanced Media Editor route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'web/enhanced-multimedia-editor.html'));
});

// API endpoint for media editor
app.get('/api/status', (req, res) => {
  res.json({
    service: 'Enhanced Media Editor',
    version: '1.0.0',
    status: 'running',
    features: [
      'SVG Generation',
      'Bitmap Image Generation', 
      'AI Image Generation',
      'Video Editing (Kdenlive-inspired)',
      'Audio Editing (Audacity-inspired)',
      'Image Editing (GIMP-inspired)'
    ]
  });
});

// Start the server
app.listen(port, () => {
  console.log(`🎬 Enhanced Media Editor running on http://localhost:${port}`);
  console.log(`📱 Access the editor at: http://localhost:${port}`);
  console.log(`🔗 API status: http://localhost:${port}/api/status`);
});

// Handle server errors
app.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    console.log(`⚠️ Port ${port} is already in use. Trying port ${port + 1}...`);
    app.listen(port + 1);
  } else {
    console.error('Server error:', error);
  }
});
