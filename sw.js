const V='mart-drive-v2.4.0';
const SHELL=['./','index.html','terms_conditions.html','privacy_policy.html','manifest.webmanifest','icons/icon 192.jpg','icons/icon 512.jpg'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(V).then(c=>Promise.all(SHELL.map(u=>c.add(u).catch(()=>{})))).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==V).map(x=>caches.delete(x)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',e=>{
  const r=e.request;if(r.method!=='GET')return;
  const u=new URL(r.url);if(u.origin!==location.origin)return; // Firebase / Google APIs always go to the network (Firestore has its own offline cache)
  if(r.mode==='navigate'){
    e.respondWith(fetch(r).then(res=>{const cp=res.clone();caches.open(V).then(c=>c.put(r,cp));return res})
      .catch(()=>caches.match(r,{ignoreSearch:true}).then(m=>m||caches.match('index.html'))));
    return;
  }
  e.respondWith(caches.match(r).then(m=>{
    const net=fetch(r).then(res=>{if(res.ok){const cp=res.clone();caches.open(V).then(c=>c.put(r,cp))}return res}).catch(()=>m);
    return m||net;
  }));
});
/* Web push (Firebase Cloud Messaging) */
self.addEventListener('push',e=>{
  let d={};try{d=e.data?e.data.json():{}}catch{}
  const n=d.notification||d.data||{};
  e.waitUntil(self.registration.showNotification(n.title||'MART Drive',{body:n.body||'',icon:'icons/icon 192.jpg',badge:'icons/icon 192.jpg',data:{url:n.click_action||'./'}}));
});
self.addEventListener('notificationclick',e=>{
  e.notification.close();
  e.waitUntil(clients.matchAll({type:'window',includeUncontrolled:true}).then(l=>{for(const c of l){if('focus' in c)return c.focus()}return clients.openWindow(e.notification.data?.url||'./')}));
});
