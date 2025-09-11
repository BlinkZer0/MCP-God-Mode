// Image Editor Service Worker
const CACHE_NAME = 'image-editor-v1';
const STATIC_CACHE = 'image-editor-static-v1';
const DYNAMIC_CACHE = 'image-editor-dynamic-v1';

// Files to cache for offline functionality
const STATIC_FILES = [
    '/viewer/image',
    '/viewer/image/index.html',
    '/viewer/image/app.js',
    '/viewer/image/styles.css',
    '/viewer/image/manifest.json',
    '/viewer/image/icons/icon-192x192.png',
    '/viewer/image/icons/icon-512x512.png'
];

// External resources to cache
const EXTERNAL_RESOURCES = [
    'https://unpkg.com/react@18/umd/react.development.js',
    'https://unpkg.com/react-dom@18/umd/react-dom.development.js',
    'https://unpkg.com/@babel/standalone/babel.min.js',
    'https://unpkg.com/fabric@5.3.0/dist/fabric.min.js',
    'https://unpkg.com/lucide@latest/dist/umd/lucide.js'
];

// Install event - cache static files
self.addEventListener('install', (event) => {
    console.log('Service Worker: Installing...');
    
    event.waitUntil(
        caches.open(STATIC_CACHE)
            .then((cache) => {
                console.log('Service Worker: Caching static files');
                return cache.addAll(STATIC_FILES);
            })
            .then(() => {
                console.log('Service Worker: Static files cached');
                return self.skipWaiting();
            })
            .catch((error) => {
                console.error('Service Worker: Failed to cache static files', error);
            })
    );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
    console.log('Service Worker: Activating...');
    
    event.waitUntil(
        caches.keys()
            .then((cacheNames) => {
                return Promise.all(
                    cacheNames.map((cacheName) => {
                        if (cacheName !== STATIC_CACHE && cacheName !== DYNAMIC_CACHE) {
                            console.log('Service Worker: Deleting old cache', cacheName);
                            return caches.delete(cacheName);
                        }
                    })
                );
            })
            .then(() => {
                console.log('Service Worker: Activated');
                return self.clients.claim();
            })
    );
});

// Fetch event - serve from cache or network
self.addEventListener('fetch', (event) => {
    const { request } = event;
    const url = new URL(request.url);
    
    // Skip non-GET requests
    if (request.method !== 'GET') {
        return;
    }
    
    // Handle API requests
    if (url.pathname.startsWith('/api/image/')) {
        event.respondWith(
            fetch(request)
                .then((response) => {
                    // Cache successful API responses
                    if (response.ok) {
                        const responseClone = response.clone();
                        caches.open(DYNAMIC_CACHE)
                            .then((cache) => {
                                cache.put(request, responseClone);
                            });
                    }
                    return response;
                })
                .catch(() => {
                    // Return cached response if network fails
                    return caches.match(request);
                })
        );
        return;
    }
    
    // Handle static files
    if (STATIC_FILES.includes(url.pathname) || url.pathname === '/viewer/image') {
        event.respondWith(
            caches.match(request)
                .then((cachedResponse) => {
                    if (cachedResponse) {
                        return cachedResponse;
                    }
                    
                    return fetch(request)
                        .then((response) => {
                            if (response.ok) {
                                const responseClone = response.clone();
                                caches.open(STATIC_CACHE)
                                    .then((cache) => {
                                        cache.put(request, responseClone);
                                    });
                            }
                            return response;
                        });
                })
        );
        return;
    }
    
    // Handle external resources
    if (EXTERNAL_RESOURCES.some(resource => request.url.startsWith(resource))) {
        event.respondWith(
            caches.match(request)
                .then((cachedResponse) => {
                    if (cachedResponse) {
                        return cachedResponse;
                    }
                    
                    return fetch(request)
                        .then((response) => {
                            if (response.ok) {
                                const responseClone = response.clone();
                                caches.open(DYNAMIC_CACHE)
                                    .then((cache) => {
                                        cache.put(request, responseClone);
                                    });
                            }
                            return response;
                        });
                })
        );
        return;
    }
    
    // Handle image files
    if (request.destination === 'image') {
        event.respondWith(
            caches.match(request)
                .then((cachedResponse) => {
                    if (cachedResponse) {
                        return cachedResponse;
                    }
                    
                    return fetch(request)
                        .then((response) => {
                            if (response.ok) {
                                const responseClone = response.clone();
                                caches.open(DYNAMIC_CACHE)
                                    .then((cache) => {
                                        cache.put(request, responseClone);
                                    });
                            }
                            return response;
                        });
                })
        );
        return;
    }
    
    // Default: try network first, fallback to cache
    event.respondWith(
        fetch(request)
            .then((response) => {
                if (response.ok) {
                    const responseClone = response.clone();
                    caches.open(DYNAMIC_CACHE)
                        .then((cache) => {
                            cache.put(request, responseClone);
                        });
                }
                return response;
            })
            .catch(() => {
                return caches.match(request);
            })
    );
});

// Background sync for offline operations
self.addEventListener('sync', (event) => {
    console.log('Service Worker: Background sync', event.tag);
    
    if (event.tag === 'image-export') {
        event.waitUntil(
            // Handle offline image exports
            handleOfflineExport()
        );
    }
});

// Handle offline image export
async function handleOfflineExport() {
    try {
        // Get pending exports from IndexedDB
        const pendingExports = await getPendingExports();
        
        for (const exportData of pendingExports) {
            try {
                // Process the export
                await processOfflineExport(exportData);
                
                // Remove from pending list
                await removePendingExport(exportData.id);
            } catch (error) {
                console.error('Failed to process offline export:', error);
            }
        }
    } catch (error) {
        console.error('Background sync failed:', error);
    }
}

// Message handling for communication with main thread
self.addEventListener('message', (event) => {
    const { type, data } = event.data;
    
    switch (type) {
        case 'SKIP_WAITING':
            self.skipWaiting();
            break;
            
        case 'CACHE_IMAGE':
            cacheImage(data.url, data.blob);
            break;
            
        case 'GET_CACHE_SIZE':
            getCacheSize().then((size) => {
                event.ports[0].postMessage({ size });
            });
            break;
            
        case 'CLEAR_CACHE':
            clearCache().then(() => {
                event.ports[0].postMessage({ success: true });
            });
            break;
            
        default:
            console.log('Unknown message type:', type);
    }
});

// Cache an image blob
async function cacheImage(url, blob) {
    try {
        const cache = await caches.open(DYNAMIC_CACHE);
        const response = new Response(blob, {
            headers: {
                'Content-Type': 'image/png'
            }
        });
        await cache.put(url, response);
    } catch (error) {
        console.error('Failed to cache image:', error);
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
            
            for (const request of keys) {
                const response = await cache.match(request);
                if (response) {
                    const blob = await response.blob();
                    totalSize += blob.size;
                }
            }
        }
        
        return totalSize;
    } catch (error) {
        console.error('Failed to get cache size:', error);
        return 0;
    }
}

// Clear all caches
async function clearCache() {
    try {
        const cacheNames = await caches.keys();
        await Promise.all(
            cacheNames.map(cacheName => caches.delete(cacheName))
        );
    } catch (error) {
        console.error('Failed to clear cache:', error);
    }
}

// IndexedDB helpers for offline operations
async function getPendingExports() {
    // Implementation would depend on your IndexedDB setup
    return [];
}

async function processOfflineExport(exportData) {
    // Implementation for processing offline exports
    console.log('Processing offline export:', exportData);
}

async function removePendingExport(id) {
    // Implementation for removing completed exports
    console.log('Removing pending export:', id);
}
