// Multimedia Tool Service Worker
const CACHE_NAME = 'multimedia-tool-v1';
const STATIC_CACHE = 'multimedia-static-v1';
const DYNAMIC_CACHE = 'multimedia-dynamic-v1';

// Files to cache for offline functionality
const STATIC_FILES = [
    '/viewer/multimedia',
    '/viewer/multimedia/multimedia.html',
    '/viewer/multimedia/multimedia-styles.css',
    '/viewer/multimedia/multimedia-app.js',
    '/viewer/multimedia/multimedia-manifest.json',
    // External dependencies
    'https://unpkg.com/react@18/umd/react.development.js',
    'https://unpkg.com/react-dom@18/umd/react-dom.development.js',
    'https://unpkg.com/@babel/standalone/babel.min.js',
    'https://unpkg.com/fabric@5.3.0/dist/fabric.min.js',
    'https://unpkg.com/wavesurfer.js@7/dist/wavesurfer.js',
    'https://unpkg.com/wavesurfer.js@7/dist/plugins/spectrogram.esm.js',
    'https://unpkg.com/lucide@latest/dist/umd/lucide.js'
];

// API endpoints to cache
const API_ENDPOINTS = [
    '/api/multimedia/status',
    '/api/multimedia/sessions',
    '/api/multimedia/projects'
];

// Install event - cache static files
self.addEventListener('install', event => {
    console.log('Multimedia Tool SW: Installing...');
    
    event.waitUntil(
        caches.open(STATIC_CACHE)
            .then(cache => {
                console.log('Multimedia Tool SW: Caching static files');
                return cache.addAll(STATIC_FILES);
            })
            .then(() => {
                console.log('Multimedia Tool SW: Static files cached');
                return self.skipWaiting();
            })
            .catch(error => {
                console.error('Multimedia Tool SW: Failed to cache static files', error);
            })
    );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
    console.log('Multimedia Tool SW: Activating...');
    
    event.waitUntil(
        caches.keys()
            .then(cacheNames => {
                return Promise.all(
                    cacheNames.map(cacheName => {
                        if (cacheName !== STATIC_CACHE && cacheName !== DYNAMIC_CACHE) {
                            console.log('Multimedia Tool SW: Deleting old cache', cacheName);
                            return caches.delete(cacheName);
                        }
                    })
                );
            })
            .then(() => {
                console.log('Multimedia Tool SW: Activated');
                return self.clients.claim();
            })
    );
});

// Fetch event - serve from cache or network
self.addEventListener('fetch', event => {
    const { request } = event;
    const url = new URL(request.url);
    
    // Skip non-GET requests
    if (request.method !== 'GET') {
        return;
    }
    
    // Handle API requests
    if (url.pathname.startsWith('/api/multimedia/')) {
        event.respondWith(handleApiRequest(request));
        return;
    }
    
    // Handle static file requests
    if (url.pathname.startsWith('/viewer/multimedia/') || 
        url.pathname === '/viewer/multimedia') {
        event.respondWith(handleStaticRequest(request));
        return;
    }
    
    // Handle external dependencies
    if (url.hostname === 'unpkg.com') {
        event.respondWith(handleExternalRequest(request));
        return;
    }
});

// Handle API requests with network-first strategy
async function handleApiRequest(request) {
    try {
        // Try network first
        const networkResponse = await fetch(request);
        
        if (networkResponse.ok) {
            // Cache successful responses
            const cache = await caches.open(DYNAMIC_CACHE);
            cache.put(request, networkResponse.clone());
        }
        
        return networkResponse;
    } catch (error) {
        console.log('Multimedia Tool SW: Network failed, trying cache', error);
        
        // Fall back to cache
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }
        
        // Return offline response for API calls
        return new Response(
            JSON.stringify({
                error: 'Offline',
                message: 'No internet connection available',
                offline: true
            }),
            {
                status: 503,
                statusText: 'Service Unavailable',
                headers: { 'Content-Type': 'application/json' }
            }
        );
    }
}

// Handle static file requests with cache-first strategy
async function handleStaticRequest(request) {
    // Try cache first
    const cachedResponse = await caches.match(request);
    if (cachedResponse) {
        return cachedResponse;
    }
    
    try {
        // Fall back to network
        const networkResponse = await fetch(request);
        
        if (networkResponse.ok) {
            // Cache the response
            const cache = await caches.open(STATIC_CACHE);
            cache.put(request, networkResponse.clone());
        }
        
        return networkResponse;
    } catch (error) {
        console.log('Multimedia Tool SW: Network failed for static file', error);
        
        // Return offline page for HTML requests
        if (request.headers.get('accept')?.includes('text/html')) {
            return new Response(
                `
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Multimedia Tool - Offline</title>
                    <style>
                        body { 
                            font-family: -apple-system, BlinkMacSystemFont, sans-serif; 
                            text-align: center; 
                            padding: 2rem; 
                            background: #f8fafc; 
                        }
                        .offline-container { 
                            max-width: 400px; 
                            margin: 0 auto; 
                            padding: 2rem; 
                            background: white; 
                            border-radius: 0.5rem; 
                            box-shadow: 0 1px 3px rgba(0,0,0,0.1); 
                        }
                        .offline-icon { 
                            font-size: 4rem; 
                            margin-bottom: 1rem; 
                        }
                        h1 { 
                            color: #1e293b; 
                            margin-bottom: 1rem; 
                        }
                        p { 
                            color: #64748b; 
                            margin-bottom: 2rem; 
                        }
                        .retry-btn { 
                            background: #3b82f6; 
                            color: white; 
                            border: none; 
                            padding: 0.75rem 1.5rem; 
                            border-radius: 0.5rem; 
                            cursor: pointer; 
                            font-size: 1rem; 
                        }
                        .retry-btn:hover { 
                            background: #2563eb; 
                        }
                    </style>
                </head>
                <body>
                    <div class="offline-container">
                        <div class="offline-icon">📱</div>
                        <h1>You're Offline</h1>
                        <p>The Multimedia Tool is not available without an internet connection.</p>
                        <button class="retry-btn" onclick="window.location.reload()">
                            Try Again
                        </button>
                    </div>
                </body>
                </html>
                `,
                {
                    status: 200,
                    statusText: 'OK',
                    headers: { 'Content-Type': 'text/html' }
                }
            );
        }
        
        // Return generic error for other requests
        return new Response('Offline', { status: 503 });
    }
}

// Handle external dependency requests
async function handleExternalRequest(request) {
    // Try cache first
    const cachedResponse = await caches.match(request);
    if (cachedResponse) {
        return cachedResponse;
    }
    
    try {
        // Fall back to network
        const networkResponse = await fetch(request);
        
        if (networkResponse.ok) {
            // Cache external dependencies
            const cache = await caches.open(STATIC_CACHE);
            cache.put(request, networkResponse.clone());
        }
        
        return networkResponse;
    } catch (error) {
        console.log('Multimedia Tool SW: Failed to fetch external dependency', error);
        return new Response('External dependency unavailable', { status: 503 });
    }
}

// Background sync for offline actions
self.addEventListener('sync', event => {
    if (event.tag === 'multimedia-sync') {
        console.log('Multimedia Tool SW: Background sync triggered');
        event.waitUntil(handleBackgroundSync());
    }
});

async function handleBackgroundSync() {
    try {
        // Sync any pending operations when back online
        console.log('Multimedia Tool SW: Syncing pending operations');
        
        // This would typically sync any queued operations
        // For now, just log that sync occurred
        console.log('Multimedia Tool SW: Background sync completed');
    } catch (error) {
        console.error('Multimedia Tool SW: Background sync failed', error);
    }
}

// Push notifications for multimedia events
self.addEventListener('push', event => {
    if (event.data) {
        const data = event.data.json();
        console.log('Multimedia Tool SW: Push notification received', data);
        
        const options = {
            body: data.body || 'Multimedia Tool notification',
            icon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" fill="%233b82f6"/><text x="50" y="60" font-size="50" text-anchor="middle" fill="white">🎨</text></svg>',
            badge: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" fill="%233b82f6"/><text x="50" y="60" font-size="50" text-anchor="middle" fill="white">🎨</text></svg>',
            tag: 'multimedia-notification',
            data: data,
            actions: [
                {
                    action: 'open',
                    title: 'Open Multimedia Tool',
                    icon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" fill="%2310b981"/><text x="50" y="60" font-size="50" text-anchor="middle" fill="white">🎨</text></svg>'
                },
                {
                    action: 'dismiss',
                    title: 'Dismiss',
                    icon: 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" fill="%236b7280"/><text x="50" y="60" font-size="50" text-anchor="middle" fill="white">✕</text></svg>'
                }
            ]
        };
        
        event.waitUntil(
            self.registration.showNotification(data.title || 'Multimedia Tool', options)
        );
    }
});

// Handle notification clicks
self.addEventListener('notificationclick', event => {
    console.log('Multimedia Tool SW: Notification clicked', event);
    
    event.notification.close();
    
    if (event.action === 'open' || !event.action) {
        event.waitUntil(
            clients.openWindow('/viewer/multimedia')
        );
    }
});

// Message handling for communication with main thread
self.addEventListener('message', event => {
    console.log('Multimedia Tool SW: Message received', event.data);
    
    if (event.data && event.data.type === 'SKIP_WAITING') {
        self.skipWaiting();
    }
    
    if (event.data && event.data.type === 'GET_VERSION') {
        event.ports[0].postMessage({ version: CACHE_NAME });
    }
});

console.log('Multimedia Tool SW: Service worker loaded');
