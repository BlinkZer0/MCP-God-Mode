// Enhanced Media Editor Service Worker
// Provides offline functionality and caching for the multimedia editing suite

const CACHE_NAME = 'enhanced-media-editor-v1.0.0';
const STATIC_CACHE = 'enhanced-static-v1.0.0';
const DYNAMIC_CACHE = 'enhanced-dynamic-v1.0.0';

// Files to cache for offline functionality
const STATIC_FILES = [
    '/enhanced_media_editor.html',
    '/enhanced-media-app.js',
    '/enhanced-media-styles.css',
    '/enhanced-manifest.json',
    '/icons/icon-16x16.png',
    '/icons/icon-32x32.png',
    '/icons/icon-192x192.png',
    '/icons/icon-512x512.png',
    // External dependencies
    'https://unpkg.com/react@18/umd/react.development.js',
    'https://unpkg.com/react-dom@18/umd/react-dom.development.js',
    'https://unpkg.com/@babel/standalone/babel.min.js',
    'https://unpkg.com/fabric@5.3.0/dist/fabric.min.js',
    'https://unpkg.com/wavesurfer.js@7/dist/wavesurfer.js',
    'https://unpkg.com/wavesurfer.js@7/dist/plugins/spectrogram.esm.js',
    'https://unpkg.com/wavesurfer.js@7/dist/plugins/timeline.esm.js',
    'https://unpkg.com/wavesurfer.js@7/dist/plugins/regions.esm.js',
    'https://unpkg.com/lucide@latest/dist/umd/lucide.js'
];

// Install event - cache static files
self.addEventListener('install', event => {
    console.log('Enhanced Media Editor SW: Installing...');
    
    event.waitUntil(
        caches.open(STATIC_CACHE)
            .then(cache => {
                console.log('Enhanced Media Editor SW: Caching static files');
                return cache.addAll(STATIC_FILES);
            })
            .then(() => {
                console.log('Enhanced Media Editor SW: Static files cached successfully');
                return self.skipWaiting();
            })
            .catch(error => {
                console.error('Enhanced Media Editor SW: Failed to cache static files:', error);
            })
    );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
    console.log('Enhanced Media Editor SW: Activating...');
    
    event.waitUntil(
        caches.keys()
            .then(cacheNames => {
                return Promise.all(
                    cacheNames.map(cacheName => {
                        if (cacheName !== STATIC_CACHE && cacheName !== DYNAMIC_CACHE) {
                            console.log('Enhanced Media Editor SW: Deleting old cache:', cacheName);
                            return caches.delete(cacheName);
                        }
                    })
                );
            })
            .then(() => {
                console.log('Enhanced Media Editor SW: Activated successfully');
                return self.clients.claim();
            })
    );
});

// Fetch event - serve cached content when offline
self.addEventListener('fetch', event => {
    const { request } = event;
    const url = new URL(request.url);
    
    // Skip non-GET requests
    if (request.method !== 'GET') {
        return;
    }
    
    // Skip chrome-extension and other non-http requests
    if (!url.protocol.startsWith('http')) {
        return;
    }
    
    event.respondWith(
        caches.match(request)
            .then(response => {
                // Return cached version if available
                if (response) {
                    console.log('Enhanced Media Editor SW: Serving from cache:', request.url);
                    return response;
                }
                
                // Otherwise, fetch from network
                return fetch(request)
                    .then(fetchResponse => {
                        // Don't cache if not a valid response
                        if (!fetchResponse || fetchResponse.status !== 200 || fetchResponse.type !== 'basic') {
                            return fetchResponse;
                        }
                        
                        // Clone the response
                        const responseToCache = fetchResponse.clone();
                        
                        // Cache dynamic content
                        caches.open(DYNAMIC_CACHE)
                            .then(cache => {
                                // Only cache certain types of content
                                if (shouldCache(request.url)) {
                                    console.log('Enhanced Media Editor SW: Caching dynamic content:', request.url);
                                    cache.put(request, responseToCache);
                                }
                            });
                        
                        return fetchResponse;
                    })
                    .catch(error => {
                        console.log('Enhanced Media Editor SW: Network request failed:', request.url, error);
                        
                        // Return offline page for navigation requests
                        if (request.destination === 'document') {
                            return caches.match('/enhanced_media_editor.html');
                        }
                        
                        // Return a generic offline response for other requests
                        return new Response('Offline content not available', {
                            status: 503,
                            statusText: 'Service Unavailable',
                            headers: new Headers({
                                'Content-Type': 'text/plain'
                            })
                        });
                    });
            })
    );
});

// Message event - handle messages from the main thread
self.addEventListener('message', event => {
    const { type, payload } = event.data;
    
    switch (type) {
        case 'SKIP_WAITING':
            self.skipWaiting();
            break;
            
        case 'CACHE_MEDIA':
            cacheMediaFile(payload.url, payload.blob);
            break;
            
        case 'CLEAR_CACHE':
            clearCache();
            break;
            
        case 'GET_CACHE_SIZE':
            getCacheSize().then(size => {
                event.ports[0].postMessage({ type: 'CACHE_SIZE', size });
            });
            break;
            
        default:
            console.log('Enhanced Media Editor SW: Unknown message type:', type);
    }
});

// Helper function to determine if a URL should be cached
function shouldCache(url) {
    const urlObj = new URL(url);
    
    // Cache API endpoints
    if (urlObj.pathname.startsWith('/api/enhanced_media_editor/')) {
        return true;
    }
    
    // Cache media files
    const mediaExtensions = ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.mp4', '.avi', '.mov', '.mkv', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg'];
    const hasMediaExtension = mediaExtensions.some(ext => urlObj.pathname.toLowerCase().endsWith(ext));
    
    if (hasMediaExtension) {
        return true;
    }
    
    // Cache external CDN resources
    if (urlObj.hostname.includes('unpkg.com') || urlObj.hostname.includes('cdnjs.cloudflare.com')) {
        return true;
    }
    
    return false;
}

// Cache a media file
async function cacheMediaFile(url, blob) {
    try {
        const cache = await caches.open(DYNAMIC_CACHE);
        const response = new Response(blob);
        await cache.put(url, response);
        console.log('Enhanced Media Editor SW: Cached media file:', url);
    } catch (error) {
        console.error('Enhanced Media Editor SW: Failed to cache media file:', error);
    }
}

// Clear all caches
async function clearCache() {
    try {
        const cacheNames = await caches.keys();
        await Promise.all(
            cacheNames.map(cacheName => caches.delete(cacheName))
        );
        console.log('Enhanced Media Editor SW: All caches cleared');
    } catch (error) {
        console.error('Enhanced Media Editor SW: Failed to clear caches:', error);
    }
}

// Get cache size
async function getCacheSize() {
    try {
        const cacheNames = await caches.keys();
        let totalSize = 0;
        
        for (const cacheName of cacheNames) {
            const cache = await caches.open(cacheName);
            const keys = await cache.keys();
            
            for (const key of keys) {
                const response = await cache.match(key);
                if (response) {
                    const blob = await response.blob();
                    totalSize += blob.size;
                }
            }
        }
        
        return totalSize;
    } catch (error) {
        console.error('Enhanced Media Editor SW: Failed to get cache size:', error);
        return 0;
    }
}

// Background sync for offline media processing
self.addEventListener('sync', event => {
    if (event.tag === 'background-sync-media') {
        event.waitUntil(processOfflineMedia());
    }
});

// Process media files that were queued while offline
async function processOfflineMedia() {
    try {
        // Get queued media operations from IndexedDB
        const operations = await getQueuedOperations();
        
        for (const operation of operations) {
            try {
                await processMediaOperation(operation);
                await removeQueuedOperation(operation.id);
            } catch (error) {
                console.error('Enhanced Media Editor SW: Failed to process queued operation:', error);
            }
        }
    } catch (error) {
        console.error('Enhanced Media Editor SW: Failed to process offline media:', error);
    }
}

// Get queued operations from IndexedDB
async function getQueuedOperations() {
    // This would integrate with IndexedDB to get queued operations
    // For now, return empty array
    return [];
}

// Process a media operation
async function processMediaOperation(operation) {
    // This would handle the actual media processing
    // For now, just log the operation
    console.log('Enhanced Media Editor SW: Processing operation:', operation);
}

// Remove a queued operation from IndexedDB
async function removeQueuedOperation(operationId) {
    // This would remove the operation from IndexedDB
    // For now, just log the removal
    console.log('Enhanced Media Editor SW: Removing queued operation:', operationId);
}

// Push notification handling
self.addEventListener('push', event => {
    if (event.data) {
        const data = event.data.json();
        
        const options = {
            body: data.body,
            icon: '/icons/icon-192x192.png',
            badge: '/icons/icon-32x32.png',
            vibrate: [100, 50, 100],
            data: {
                dateOfArrival: Date.now(),
                primaryKey: data.primaryKey
            },
            actions: [
                {
                    action: 'explore',
                    title: 'Open Editor',
                    icon: '/icons/icon-32x32.png'
                },
                {
                    action: 'close',
                    title: 'Close',
                    icon: '/icons/icon-32x32.png'
                }
            ]
        };
        
        event.waitUntil(
            self.registration.showNotification(data.title, options)
        );
    }
});

// Notification click handling
self.addEventListener('notificationclick', event => {
    event.notification.close();
    
    if (event.action === 'explore') {
        event.waitUntil(
            clients.openWindow('/enhanced_media_editor.html')
        );
    }
});

console.log('Enhanced Media Editor SW: Service Worker loaded successfully');
