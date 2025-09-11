const CACHE_NAME = 'mcp-audio-editor-v1';
const urlsToCache = [
  '/viewer/audio/',
  '/viewer/audio/index.html',
  '/viewer/audio/app.js',
  '/viewer/audio/manifest.json',
  '/viewer/audio/sw.js'
];

// Install event
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('Opened cache');
        return cache.addAll(urlsToCache);
      })
  );
});

// Fetch event
self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request)
      .then((response) => {
        // Return cached version or fetch from network
        if (response) {
          return response;
        }
        
        // Clone the request
        const fetchRequest = event.request.clone();
        
        return fetch(fetchRequest).then((response) => {
          // Check if we received a valid response
          if (!response || response.status !== 200 || response.type !== 'basic') {
            return response;
          }
          
          // Clone the response
          const responseToCache = response.clone();
          
          caches.open(CACHE_NAME)
            .then((cache) => {
              cache.put(event.request, responseToCache);
            });
          
          return response;
        });
      })
  );
});

// Activate event
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            console.log('Deleting old cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});

// Background sync for offline audio processing
self.addEventListener('sync', (event) => {
  if (event.tag === 'audio-processing') {
    event.waitUntil(processOfflineAudio());
  }
});

// Push notifications for audio processing completion
self.addEventListener('push', (event) => {
  const options = {
    body: event.data ? event.data.text() : 'Audio processing completed',
    icon: '/viewer/audio/icon-192.png',
    badge: '/viewer/audio/icon-192.png',
    vibrate: [100, 50, 100],
    data: {
      dateOfArrival: Date.now(),
      primaryKey: 1
    },
    actions: [
      {
        action: 'explore',
        title: 'Open Editor',
        icon: '/viewer/audio/icon-192.png'
      },
      {
        action: 'close',
        title: 'Close',
        icon: '/viewer/audio/icon-192.png'
      }
    ]
  };
  
  event.waitUntil(
    self.registration.showNotification('MCP Audio Editor', options)
  );
});

// Notification click handler
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  
  if (event.action === 'explore') {
    event.waitUntil(
      clients.openWindow('/viewer/audio')
    );
  }
});

// Audio processing functions
async function processOfflineAudio() {
  try {
    // Get pending audio processing tasks from IndexedDB
    const pendingTasks = await getPendingAudioTasks();
    
    for (const task of pendingTasks) {
      try {
        await processAudioTask(task);
        await removePendingAudioTask(task.id);
      } catch (error) {
        console.error('Failed to process audio task:', error);
      }
    }
  } catch (error) {
    console.error('Background sync failed:', error);
  }
}

async function getPendingAudioTasks() {
  // This would typically use IndexedDB to store pending tasks
  // For now, return empty array
  return [];
}

async function processAudioTask(task) {
  // Process audio task offline
  console.log('Processing audio task:', task);
}

async function removePendingAudioTask(taskId) {
  // Remove completed task from IndexedDB
  console.log('Removing completed task:', taskId);
}

// Audio file handling
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'AUDIO_PROCESSING') {
    handleAudioProcessing(event.data);
  }
});

async function handleAudioProcessing(data) {
  try {
    // Process audio data
    const result = await processAudioData(data.audioData, data.operations);
    
    // Send result back to main thread
    self.clients.matchAll().then(clients => {
      clients.forEach(client => {
        client.postMessage({
          type: 'AUDIO_PROCESSING_RESULT',
          result: result
        });
      });
    });
  } catch (error) {
    // Send error back to main thread
    self.clients.matchAll().then(clients => {
      clients.forEach(client => {
        client.postMessage({
          type: 'AUDIO_PROCESSING_ERROR',
          error: error.message
        });
      });
    });
  }
}

async function processAudioData(audioData, operations) {
  // Simulate audio processing
  return {
    success: true,
    processedAudio: audioData,
    operations: operations
  };
}
