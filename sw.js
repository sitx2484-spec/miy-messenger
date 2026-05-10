// Echo Messenger — Service Worker v2
const CACHE = 'echo-v2';
const STATIC = ['/', '/manifest.json', '/icon.svg'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(STATIC).catch(()=>{})));
  self.skipWaiting();
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))));
  self.clients.claim();
});
self.addEventListener('fetch', e => {
  if(e.request.method!=='GET'||e.request.url.includes('/api/')||e.request.url.includes('/ws'))return;
  e.respondWith(fetch(e.request).then(r=>{if(r.ok)caches.open(CACHE).then(c=>c.put(e.request,r.clone()));return r;}).catch(()=>caches.match(e.request)));
});

// Push notifications
self.addEventListener('push', e => {
  const d=e.data?.json()||{};
  const isCall=d.type==='call';
  e.waitUntil(self.registration.showNotification(
    isCall?`📞 Вам дзвонить ${d.callerName||'Хтось'}`:(d.title||'Echo'),{
      body:isCall?'Натисни щоб відповісти':(d.body||'Нове повідомлення'),
      icon:d.icon||'/icon.svg',badge:'/icon.svg',
      tag:isCall?'call':('msg-'+(d.chatKey||'')),
      requireInteraction:isCall,
      vibrate:isCall?[200,100,200,100,200]:[150,50,150],
      actions:isCall?[{action:'accept',title:'📞 Прийняти'},{action:'reject',title:'📵 Відхилити'}]:[{action:'open',title:'💬 Відкрити'}],
      data:{url:'/',...d},
    }
  ));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const d=e.notification.data||{};
  e.waitUntil(clients.matchAll({type:'window',includeUncontrolled:true}).then(wcs=>{
    const ec=wcs.find(c=>c.url.includes(self.location.origin));
    if(ec){ec.focus();
      if(e.action==='accept')ec.postMessage({type:'sw_accept_call'});
      else if(e.action==='reject')ec.postMessage({type:'sw_reject_call'});
      else ec.postMessage({type:'sw_open_chat',chatKey:d.chatKey});
    }else clients.openWindow('/');
  }));
});
self.addEventListener('notificationclose',e=>{
  if(e.notification.tag==='call')clients.matchAll({type:'window'}).then(wcs=>wcs.forEach(c=>c.postMessage({type:'sw_reject_call'})));
});
