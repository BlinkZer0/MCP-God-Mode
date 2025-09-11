// Sample WebSocket server for testing RF_sense_mmwave point cloud viewer
// Run with: node ws_point_server.js
// Connects to: ws://localhost:8787/points

import http from 'http';
import { WebSocketServer } from 'ws';

const server = http.createServer();
const wss = new WebSocketServer({ server });

console.log('🚀 RF mmWave Point Cloud WebSocket Server');
console.log('📡 Listening on ws://localhost:8787/points');
console.log('🎯 Sending synthetic point cloud data...');

wss.on('connection', (ws) => {
  console.log('✅ Client connected');
  
  // Demo: emit a tiny random cloud every 100ms
  const iv = setInterval(() => {
    const N = 2000;
    const xyz = new Array(N * 3);
    const intensity = new Array(N);
    
    // Generate points in a room-like environment
    for (let i = 0; i < N; i++) {
      // Create some structure: floor, walls, moving objects
      const type = Math.random();
      
      if (type < 0.3) {
        // Floor points
        xyz[3*i] = (Math.random() - 0.5) * 4;
        xyz[3*i+1] = -1.0;
        xyz[3*i+2] = (Math.random() - 0.5) * 4;
        intensity[i] = 0.1 + Math.random() * 0.2;
      } else if (type < 0.6) {
        // Wall points
        const wall = Math.floor(Math.random() * 4);
        switch (wall) {
          case 0: // front wall
            xyz[3*i] = (Math.random() - 0.5) * 4;
            xyz[3*i+1] = -1 + Math.random() * 2;
            xyz[3*i+2] = 2;
            break;
          case 1: // back wall
            xyz[3*i] = (Math.random() - 0.5) * 4;
            xyz[3*i+1] = -1 + Math.random() * 2;
            xyz[3*i+2] = -2;
            break;
          case 2: // left wall
            xyz[3*i] = -2;
            xyz[3*i+1] = -1 + Math.random() * 2;
            xyz[3*i+2] = (Math.random() - 0.5) * 4;
            break;
          case 3: // right wall
            xyz[3*i] = 2;
            xyz[3*i+1] = -1 + Math.random() * 2;
            xyz[3*i+2] = (Math.random() - 0.5) * 4;
            break;
        }
        intensity[i] = 0.2 + Math.random() * 0.3;
      } else {
        // Moving objects (people, furniture)
        const time = Date.now() * 0.001;
        const objType = Math.floor(Math.random() * 3);
        
        switch (objType) {
          case 0: // Moving person
            const px = Math.sin(time + Math.random()) * 1.5;
            const pz = Math.cos(time + Math.random()) * 1.5;
            xyz[3*i] = px + (Math.random() - 0.5) * 0.3;
            xyz[3*i+1] = -0.4 + (Math.random() - 0.5) * 0.9;
            xyz[3*i+2] = pz + (Math.random() - 0.5) * 0.3;
            intensity[i] = 0.6 + Math.random() * 0.3;
            break;
          case 1: // Static furniture
            xyz[3*i] = (Math.random() - 0.5) * 1.5;
            xyz[3*i+1] = -0.8 + Math.random() * 0.4;
            xyz[3*i+2] = (Math.random() - 0.5) * 1.5;
            intensity[i] = 0.4 + Math.random() * 0.2;
            break;
          case 2: // Floating objects
            xyz[3*i] = (Math.random() - 0.5) * 3;
            xyz[3*i+1] = Math.sin(time * 2 + Math.random()) * 0.5;
            xyz[3*i+2] = (Math.random() - 0.5) * 3;
            intensity[i] = 0.7 + Math.random() * 0.2;
            break;
        }
      }
    }
    
    // Send as JSON frame
    const frame = {
      xyz: xyz,
      intensity: intensity,
      src: "wifi",
      t: Date.now(),
      frameId: Math.floor(Date.now() / 100)
    };
    
    try {
      ws.send(JSON.stringify(frame) + "\n");
    } catch (err) {
      console.log('❌ Client disconnected');
      clearInterval(iv);
    }
  }, 100);
  
  ws.on('close', () => {
    console.log('❌ Client disconnected');
    clearInterval(iv);
  });
  
  ws.on('error', (err) => {
    console.log('❌ WebSocket error:', err.message);
    clearInterval(iv);
  });
});

server.listen(8787, () => {
  console.log('🌐 Server running on http://localhost:8787');
  console.log('📋 Open dev/pointcloud_viewer_offline.html in your browser');
  console.log('🔗 Connect to ws://localhost:8787/points');
  console.log('⏹️  Press Ctrl+C to stop');
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down server...');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});
