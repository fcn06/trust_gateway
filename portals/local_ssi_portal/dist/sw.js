// Minimal Service Worker for PWA compliance
const CACHE_NAME = 'lianxi-v1';

self.addEventListener('install', (event) => {
    console.log('[Service Worker] Install');
});

self.addEventListener('fetch', (event) => {
    // Simple pass-through for now
    event.respondWith(fetch(event.request));
});
