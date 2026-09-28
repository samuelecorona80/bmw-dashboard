import { handleBmwDirect, runBmwDirectFetch, serveBmwDirectPage } from './bmw-direct.js';

/**
 * BMW X3 M40d — Cloudflare Worker + D1
 * Complete port from Google Apps Script
 * Handles POST (data ingestion) and GET (dashboard + API)
 */

const FUEL_TANK_CAPACITY_L = 62;
const DIESEL_PRICE_EUR = 2.294; // €/L self service - aggiornare periodicamente
const DIESEL_PRICE_DATE = '2026-09-18';

const AUTH_COOKIE = 'bmw_session';

function b64urlEncodeBytes(bytes) {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

function b64urlDecodeBytes(value) {
  const s = value.replace(/-/g,'+').replace(/_/g,'/');
  const padded = s + '='.repeat((4 - s.length % 4) % 4);
  const raw = atob(padded);
  return Uint8Array.from(raw, ch => ch.charCodeAt(0));
}

function cookieValue(request, name) {
  const header = request.headers.get('Cookie') || '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0,i).trim() === name) return part.slice(i+1).trim();
  }
  return null;
}

async function authKey(env) {
  const secret = env.SITE_PASSWORD;
  if (!secret) return null;
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode('bmw-dashboard-session-v1|' + secret),
    {name:'HMAC',hash:'SHA-256'},
    false,
    ['sign','verify']
  );
}

async function createSessionToken(env, user, remember) {
  const key = await authKey(env);
  if (!key) return null;
  const ttl = remember ? 30 * 86400 : 12 * 3600;
  const payload = user + '|' + Math.floor(Date.now()/1000 + ttl);
  const payloadBytes = new TextEncoder().encode(payload);
  const sig = await crypto.subtle.sign('HMAC', key, payloadBytes);
  return b64urlEncodeBytes(payloadBytes) + '.' + b64urlEncodeBytes(sig);
}

async function validSession(request, env) {
  const expectedUser = env.SITE_USER || 'samuele';
  const key = await authKey(env);
  if (!key) return false;
  const token = cookieValue(request, AUTH_COOKIE);
  if (!token || !token.includes('.')) return false;
  try {
    const [p,s] = token.split('.',2);
    const payloadBytes = b64urlDecodeBytes(p);
    const sigBytes = b64urlDecodeBytes(s);
    const ok = await crypto.subtle.verify('HMAC', key, sigBytes, payloadBytes);
    if (!ok) return false;
    const payload = new TextDecoder().decode(payloadBytes);
    const split = payload.lastIndexOf('|');
    if (split < 0) return false;
    const user = payload.slice(0,split);
    const exp = Number(payload.slice(split+1));
    return user === expectedUser && Number.isFinite(exp) && exp > Math.floor(Date.now()/1000);
  } catch (_) {
    return false;
  }
}

function safeNext(value) {
  const v = String(value || '/');
  return v.startsWith('/') && !v.startsWith('//') ? v : '/';
}

function loginPage(next='/', error='') {
  const esc = s => String(s||'').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
  const errorHtml = error ? '<div class="error">'+esc(error)+'</div>' : '';
  return new Response(`<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#07111d">
<title>Accesso · BMW X3 M40d</title>
<style>
:root{--bg:#07111d;--card:#102239;--line:#31506d;--text:#f4f7fb;--muted:#9fb2c7;--blue:#4b98ff;--red:#ff7c7c}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(circle at 20% 0,#173b65 0,transparent 38%),linear-gradient(180deg,#091827,var(--bg));color:var(--text)}
body{display:grid;place-items:center;padding:24px}.wrap{width:min(420px,100%)}.brand{text-align:center;margin-bottom:22px}.roundel{width:64px;height:64px;margin:0 auto 14px;border:3px solid #fff;border-radius:50%;background:conic-gradient(#fff 0 25%,#2494ff 0 50%,#fff 0 75%,#2494ff 0);box-shadow:0 0 0 3px #17202c inset}.brand h1{font-size:25px;margin:0 0 6px}.brand p{margin:0;color:var(--muted);font-size:14px}.card{background:rgba(16,34,57,.94);border:1px solid var(--line);border-radius:22px;padding:22px;box-shadow:0 24px 70px rgba(0,0,0,.35)}label{display:block;font-size:13px;color:var(--muted);margin:13px 0 6px}input[type=text],input[type=password]{width:100%;border:1px solid var(--line);border-radius:12px;background:#091827;color:var(--text);padding:14px 15px;font-size:16px;outline:none}input:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(75,152,255,.14)}.remember{display:flex;align-items:center;gap:10px;margin:16px 0;color:#c8d6e5;font-size:14px}.remember input{width:19px;height:19px}.btn{width:100%;border:0;border-radius:13px;background:var(--blue);color:white;font-weight:750;font-size:16px;padding:14px;cursor:pointer}.error{background:rgba(255,124,124,.12);border:1px solid rgba(255,124,124,.35);color:#ffb1b1;border-radius:10px;padding:10px 12px;font-size:13px;margin-bottom:12px}.note{text-align:center;color:var(--muted);font-size:12px;margin-top:14px;line-height:1.45}
</style>
</head>
<body>
<div class="wrap">
  <div class="brand"><div class="roundel"></div><h1>BMW X3 M40d</h1><p>Dashboard personale</p></div>
  <form class="card" method="post" action="/login">
    ${errorHtml}
    <input type="hidden" name="next" value="${esc(safeNext(next))}">
    <label for="user">Utente</label>
    <input id="user" name="username" type="text" value="samuele" autocomplete="username" autocapitalize="none" required>
    <label for="pass">Password</label>
    <input id="pass" name="password" type="password" autocomplete="current-password" required autofocus>
    <label class="remember"><input type="checkbox" name="remember" value="1" checked> Ricordami su questo dispositivo per 30 giorni</label>
    <button class="btn" type="submit">Accedi</button>
    <div class="note">La sessione è salvata in un cookie sicuro e HttpOnly.</div>
  </form>
</div>
</body>
</html>`, {status:200,headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'}});
}

async function handleLogin(request, env) {
  if (!env.SITE_PASSWORD) return new Response('SITE_PASSWORD non configurata', {status:503});
  let form;
  try { form = await request.formData(); } catch (_) { return loginPage('/', 'Richiesta non valida'); }
  const expectedUser = env.SITE_USER || 'samuele';
  const user = String(form.get('username') || '');
  const pass = String(form.get('password') || '');
  const remember = form.get('remember') === '1';
  const next = safeNext(form.get('next'));
  if (user !== expectedUser || pass !== env.SITE_PASSWORD) return loginPage(next, 'Utente o password non corretti');
  const token = await createSessionToken(env, expectedUser, remember);
  const attrs = ['Path=/','HttpOnly','Secure','SameSite=Lax'];
  if (remember) attrs.push('Max-Age=2592000');
  return new Response(null, {
    status:303,
    headers:{'Location':next,'Set-Cookie':AUTH_COOKIE+'='+token+'; '+attrs.join('; '),'Cache-Control':'no-store'}
  });
}

function logoutResponse() {
  return new Response(null, {
    status:303,
    headers:{'Location':'/login','Set-Cookie':AUTH_COOKIE+'=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0','Cache-Control':'no-store'}
  });
}

function unauthenticatedApi() {
  return new Response(JSON.stringify({error:'authentication_required'}), {
    status:401,
    headers:{'Content-Type':'application/json','Cache-Control':'no-store'}
  });
}

export default {
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(runBmwDirectFetch(env));
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });

    try {
      if (path === '/login' && request.method === 'POST') return await handleLogin(request, env);
      if (path === '/login' && request.method === 'GET') {
        if (await validSession(request, env)) return Response.redirect(url.origin + '/', 303);
        return loginPage(url.searchParams.get('next') || '/');
      }
      if (path === '/logout' && request.method === 'GET') return logoutResponse();

      if (path === '/bmw-direct' && request.method === 'GET') {
        if (!(await validSession(request, env))) return loginPage(path);
        return serveBmwDirectPage();
      }

      if (path.startsWith('/api/bmw-direct/')) {
        if (!(await validSession(request, env))) return unauthenticatedApi();
        return await handleBmwDirect(request, env, path);
      }

      // Only the dedicated ingestion endpoint is allowed without a browser session.
      // It must present the configured BMW_WRITE_TOKEN as a Bearer token.
      const isTelemetryPost = request.method === 'POST' && path === '/api/ingest';
      if (isTelemetryPost) {
        if (!env.BMW_WRITE_TOKEN) return jsonResponse({error:'ingest_secret_missing'}, 503, cors);
        const auth = request.headers.get('Authorization') || '';
        const expected = 'Bearer ' + env.BMW_WRITE_TOKEN;
        if (auth !== expected) return jsonResponse({error:'unauthorized_ingest'}, 401, cors);
        return await handlePost(request, env, cors);
      }

      if (!(await validSession(request, env))) {
        if (path.startsWith('/api/')) return unauthenticatedApi();
        return loginPage(path + url.search);
      }

      if (request.method === 'POST') {
        if (path === '/update-price') return updatePrice(request, env, cors);
        return jsonResponse({error:'not_found'}, 404, cors);
      }
      if (path === '/api/data')      return await handleGetData(env, cors);
      if (path === '/api/analytics') return await handleGetAnalytics(env, parseInt(url.searchParams.get('days') || '30'), cors);
      if (path === '/api/dump')      return await handleDump(env, cors);
      if (path === '/fuel') return serveFuel();
      if (path === '/api/fuel') return serveFuelData(env, cors);
      if (path === '/car.jpg') return serveCarImage();
      if (path === '/history') return serveHistory();
      if (path === '/api/history') return serveHistoryData(env, cors, request);
      if (path === '/locations') return serveLocations();
      if (path === '/api/locations') return serveLocationsData(env, cors);
      if (path === '/api/prices') return servePrices(env, cors);
      if (path === '/update-price' && request.method === 'POST') return updatePrice(request, env, cors);
      if (path === '/vehicle-info') return serveVehicleInfo();
      if (path === '/trips') return serveTrips();
      if (path === '/api/trips') return serveTripsData(env, cors);
      return serveDashboard();
    } catch (err) {
      return jsonResponse({ status: 'ERROR', error: err.message, stack: err.stack }, 500, cors);
    }
  }
};

function jsonResponse(data, status = 200, cors = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...cors, 'Content-Type': 'application/json' }
  });
}

function dateKeyInRome(value = new Date()) {
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return String(value || '').substring(0, 10);
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Rome', year: 'numeric', month: '2-digit', day: '2-digit'
  }).formatToParts(d);
  const get = type => (parts.find(p => p.type === type) || {}).value || '';
  return `${get('year')}-${get('month')}-${get('day')}`;
}


function haversineKm(aLat,aLng,bLat,bLng){
  const R=6371, rad=x=>x*Math.PI/180;
  const dLat=rad(bLat-aLat), dLng=rad(bLng-aLng);
  const s=Math.sin(dLat/2)**2+Math.cos(rad(aLat))*Math.cos(rad(bLat))*Math.sin(dLng/2)**2;
  return 2*R*Math.asin(Math.sqrt(s));
}

async function getLocationLabel(db, location){
  if(!location || !Number.isFinite(Number(location.lat)) || !Number.isFinite(Number(location.lng))) return null;
  try{
    await db.exec('CREATE TABLE IF NOT EXISTS bmw_geocode_cache (cache_key TEXT PRIMARY KEY, lat REAL, lng REAL, label TEXT, display_name TEXT, fetched_at TEXT)');
    const lat=Number(location.lat), lng=Number(location.lng);
    const key=lat.toFixed(4)+','+lng.toFixed(4);
    const cached=await db.prepare('SELECT label, display_name, fetched_at FROM bmw_geocode_cache WHERE cache_key=?').bind(key).first();
    if(cached && cached.fetched_at && Date.now()-Date.parse(cached.fetched_at)<7*86400000){
      return {label:cached.label||cached.display_name, displayName:cached.display_name||cached.label, source:'cache'};
    }
    const u='https://nominatim.openstreetmap.org/reverse?format=jsonv2&addressdetails=1&zoom=18&lat='+encodeURIComponent(lat)+'&lon='+encodeURIComponent(lng);
    const r=await fetch(u,{headers:{'Accept':'application/json','Accept-Language':'it','User-Agent':'samuele-bmw-dashboard/1.0'}});
    if(!r.ok) return cached?{label:cached.label||cached.display_name,displayName:cached.display_name||cached.label,source:'cache'}:null;
    const x=await r.json(), a=x.address||{};
    const poi=a.amenity||a.shop||a.tourism||a.leisure||a.office||a.building||null;
    const road=a.road||a.pedestrian||a.residential||a.path||a.cycleway||null;
    const house=a.house_number||null;
    const locality=a.city||a.town||a.village||a.municipality||a.suburb||null;
    let label=poi || [road,house].filter(Boolean).join(' ');
    if(label && locality && !String(label).includes(locality)) label += ' · '+locality;
    if(!label) label=x.name||x.display_name||null;
    const fetchedAt=new Date().toISOString();
    await db.prepare('INSERT INTO bmw_geocode_cache(cache_key,lat,lng,label,display_name,fetched_at) VALUES(?,?,?,?,?,?) ON CONFLICT(cache_key) DO UPDATE SET lat=excluded.lat,lng=excluded.lng,label=excluded.label,display_name=excluded.display_name,fetched_at=excluded.fetched_at')
      .bind(key,lat,lng,label,x.display_name||label,fetchedAt).run();
    return {label,displayName:x.display_name||label,source:'OpenStreetMap'};
  }catch(_){return null}
}

async function getLocalDieselPrice(location){
  if(!location || !Number.isFinite(Number(location.lat)) || !Number.isFinite(Number(location.lng))) return null;
  try{
    const [stationsRes,updateRes]=await Promise.all([
      fetch('https://carburanti.samuelecorona.it/data/stations.json',{cf:{cacheTtl:1800,cacheEverything:true}}),
      fetch('https://carburanti.samuelecorona.it/data/last_update.json',{cf:{cacheTtl:1800,cacheEverything:true}})
    ]);
    if(!stationsRes.ok) return null;
    const stations=await stationsRes.json(), candidates=[];
    for(const s of stations){
      const price=s?.prezzi?.Gasolio?.self;
      if(!Number.isFinite(Number(price))||!Number.isFinite(Number(s.lat))||!Number.isFinite(Number(s.lng))) continue;
      const km=haversineKm(Number(location.lat),Number(location.lng),Number(s.lat),Number(s.lng));
      if(km<=12) candidates.push({price:Number(price),km});
    }
    if(!candidates.length) return null;
    candidates.sort((a,b)=>a.km-b.km);
    const prices=candidates.slice(0,12).map(x=>x.price).sort((a,b)=>a-b);
    const mid=Math.floor(prices.length/2), median=prices.length%2?prices[mid]:(prices[mid-1]+prices[mid])/2;
    let updatedAt=null;
    if(updateRes.ok){try{const u=await updateRes.json();updatedAt=u.updated_at||u.timestamp||u.date||u.last_update||null}catch(_){}}
    return {priceEur:Math.round(median*1000)/1000,updatedAt,stationCount:prices.length,radiusKm:12,source:'Carburanti Italia',cheapestEur:Math.round(Math.min(...prices)*1000)/1000};
  }catch(_){return null}
}

// ─────────────────────────────────────────────
// POST handler — receives snapshot data
// ─────────────────────────────────────────────
async function handlePost(request, env, cors) {
  const body = await request.json();
  const snapshotTs = body.snapshot_timestamp || new Date().toISOString();
  const snapshotDate = dateKeyInRome(snapshotTs);
  const entities = body.entities || [];
  const triggerReason = body.trigger_reason || 'scheduled';

  const db = env.DB;

  // 1. Read current state for dedup
  const currentRows = await db.prepare('SELECT entity_id, value, bmw_timestamp, last_updated, last_changed, attributes_json FROM bmw_current').all();
  const prevMap = {};
  const eventTs = (obj, fallback='') => obj?.bmw_timestamp || obj?.bmwTimestamp || obj?.last_updated || obj?.lastUpdated || obj?.last_changed || obj?.lastChanged || fallback || '';
  const tsMs = v => { const n=Date.parse(v||''); return Number.isFinite(n)?n:null; };
  for (const r of currentRows.results) {
    prevMap[r.entity_id] = {
      state: r.value,
      bmwTimestamp: r.bmw_timestamp || '',
      lastUpdated: r.last_updated || '',
      lastChanged: r.last_changed || ''
    };
  }

  // 2. Write raw (deduplicated)
  let newRows = 0, skipped = 0;
  const rawBatch = [];
  for (const ent of entities) {
    const prev = prevMap[ent.entity_id];
    if (prev && prev.state === String(ent.state) && prev.bmwTimestamp === (ent.bmw_timestamp || '')) {
      skipped++;
      continue;
    }
    rawBatch.push(db.prepare(
      `INSERT INTO bmw_raw_daily (snapshot_timestamp, entity_id, friendly_name, state, unit, device_class, last_changed, last_updated, attributes_json, bmw_timestamp, trigger_reason)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      snapshotTs, ent.entity_id, ent.friendly_name || '', String(ent.state),
      ent.unit || '', ent.device_class || '', ent.last_changed || '', ent.last_updated || '',
      JSON.stringify(ent.attributes || {}), ent.bmw_timestamp || '', triggerReason
    ));
    newRows++;
  }
  if (rawBatch.length > 0) await db.batch(rawBatch);

  // 3. Merge bmw_current without allowing an older scheduled snapshot
  // to overwrite a newer BMW/MQTT event.
  const acceptedEntities = [];
  let rejectedStale = 0;
  const currentBatch = [];
  for (const ent of entities) {
    const prev = prevMap[ent.entity_id];
    const incomingStamp = eventTs(ent, snapshotTs);
    const prevStamp = eventTs(prev);
    const incomingMs = tsMs(incomingStamp);
    const prevMs = tsMs(prevStamp);

    // If both timestamps are known, never move an entity backwards in time.
    // If timestamps are equal, keep the existing value unless the entity is new.
    const isOlder = prev && incomingMs !== null && prevMs !== null && incomingMs < prevMs;
    const sameStampDifferentValue = prev && incomingMs !== null && prevMs !== null &&
      incomingMs === prevMs && String(ent.state) !== String(prev.state);

    if (isOlder || sameStampDifferentValue) {
      rejectedStale++;
      continue;
    }

    acceptedEntities.push(ent);
    currentBatch.push(db.prepare(
      `INSERT INTO bmw_current
       (entity_id, category, friendly_name, value, unit, last_changed, last_updated, bmw_timestamp, attributes_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(entity_id) DO UPDATE SET
         category=excluded.category,
         friendly_name=excluded.friendly_name,
         value=excluded.value,
         unit=excluded.unit,
         last_changed=excluded.last_changed,
         last_updated=excluded.last_updated,
         bmw_timestamp=excluded.bmw_timestamp,
         attributes_json=excluded.attributes_json`
    ).bind(
      ent.entity_id, ent.category || '', ent.friendly_name || '', String(ent.state),
      ent.unit || '', ent.last_changed || '', ent.last_updated || '',
      ent.bmw_timestamp || '', JSON.stringify(ent.attributes || {})
    ));
  }
  if (currentBatch.length) await db.batch(currentBatch);

  // 4. Update entities map
  const entBatch = [];
  for (const ent of entities) {
    entBatch.push(db.prepare(
      `INSERT INTO bmw_entities (entity_id, friendly_name, device, integration, category, unit, first_seen, last_seen, included_in_daily)
       VALUES (?, ?, ?, 'bavariandata', ?, ?, ?, ?, 'Yes')
       ON CONFLICT(entity_id) DO UPDATE SET last_seen = excluded.last_seen`
    ).bind(
      ent.entity_id, ent.friendly_name || '', ent.device || '',
      ent.category || '', ent.unit || '', snapshotTs, snapshotTs
    ));
  }
  await db.batch(entBatch);

  // 5. Upsert daily using only values that passed freshness checks.
  await upsertDaily(db, snapshotTs, snapshotDate, acceptedEntities);

  return jsonResponse({
    status: 'OK', snapshot: snapshotTs, date: snapshotDate,
    trigger: triggerReason, rawNew: newRows, rawSkipped: skipped,
    entities: entities.length, accepted: acceptedEntities.length, rejectedStale
  }, 200, cors);
}

// ─────────────────────────────────────────────
// Upsert BMW Daily — one row per calendar day
// ─────────────────────────────────────────────
async function upsertDaily(db, snapshotTs, snapshotDate, entities) {
  // Build column→value map from entities
  const vals = {};
  let currentMileage = null;
  for (const ent of entities) {
    const col = ent.column_name || ent.friendly_name || ent.entity_id;
    vals[col] = ent.state;
    if (ent.entity_id === 'sensor.x3_m40d_vehicle_mileage') {
      const km = parseFloat(ent.state);
      if (!isNaN(km)) currentMileage = km;
    }
  }

  // Check existing row for this date
  const existing = await db.prepare(
    'SELECT id, data_json, mileage_start_km, mileage_km, daily_distance_km, fuel_percent, fuel_litres, range_km, lock_state FROM bmw_daily WHERE snapshot_date = ?'
  ).bind(snapshotDate).first();

  let mileageStart = existing ? existing.mileage_start_km : null;
  let mileageEnd = existing ? existing.mileage_km : null;
  if (currentMileage !== null) {
    // Odometer is monotonic. Never let a stale lower value corrupt a day.
    if (mileageStart === null) mileageStart = currentMileage;
    if (mileageEnd === null || currentMileage > mileageEnd) mileageEnd = currentMileage;
  }
  const dailyDistance = (mileageStart !== null && mileageEnd !== null && mileageEnd >= mileageStart)
    ? mileageEnd - mileageStart
    : (existing ? existing.daily_distance_km : null);

  // Extract key metrics
  const mileageKm = mileageEnd;
  const parsedFuelPercent = parseFloat(vals['X3 M40d Range Tank level (%)'] || vals['Fuel %'] || '');
  const parsedFuelLitres = parseFloat(vals['X3 M40d Range Tank level'] || vals['Fuel L'] || '');
  const parsedRangeKm = parseFloat(vals['X3 M40d Range Total range (last sent)'] || vals['Range km'] || '');
  const fuelPercent = Number.isFinite(parsedFuelPercent) ? parsedFuelPercent : (existing ? existing.fuel_percent : null);
  const fuelLitres = Number.isFinite(parsedFuelLitres) ? parsedFuelLitres : (existing ? existing.fuel_litres : null);
  const rangeKm = Number.isFinite(parsedRangeKm) ? parsedRangeKm : (existing ? existing.range_km : null);
  const lockState = vals['X3 M40d Doors lock'] || vals['Lock State'] || (existing ? existing.lock_state : null);

  // Merge with existing data_json
  let dataJson = {};
  if (existing && existing.data_json) {
    try { dataJson = JSON.parse(existing.data_json); } catch(e) {}
  }
  Object.assign(dataJson, vals);

  if (existing) {
    await db.prepare(
      `UPDATE bmw_daily SET snapshot_timestamp=?, data_json=?, mileage_km=?, mileage_start_km=?,
       daily_distance_km=?, fuel_percent=?, fuel_litres=?, range_km=?, lock_state=?, updated_at=datetime('now')
       WHERE id=?`
    ).bind(snapshotTs, JSON.stringify(dataJson), mileageKm, mileageStart,
      dailyDistance, fuelPercent, fuelLitres, rangeKm, lockState, existing.id).run();
  } else {
    await db.prepare(
      `INSERT INTO bmw_daily (snapshot_timestamp, snapshot_date, data_json, mileage_km, mileage_start_km,
       daily_distance_km, fuel_percent, fuel_litres, range_km, lock_state)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(snapshotTs, snapshotDate, JSON.stringify(dataJson), mileageKm, mileageStart,
      dailyDistance, fuelPercent, fuelLitres, rangeKm, lockState).run();
  }
}

// ─────────────────────────────────────────────
// GET /api/data — Dashboard payload
// ─────────────────────────────────────────────
async function handleGetData(env, cors) {
  const db = env.DB;

  // Read current entities
  const currentRows = await db.prepare('SELECT * FROM bmw_current').all();
  const current = {};
  const rows = currentRows.results;  // ← needed by CBS/GPS parsing below
  for (const r of rows) {
    current[r.entity_id] = {
      category: r.category, friendlyName: r.friendly_name, entityId: r.entity_id,
      value: r.value, unit: r.unit, lastChanged: r.last_changed,
      lastUpdated: r.last_updated, bmwTimestamp: r.bmw_timestamp,
      attributes_json: r.attributes_json
    };
  }

  // Read daily history (last 60 rows)
  const dailyRows = await db.prepare(
    'SELECT * FROM bmw_daily ORDER BY snapshot_date DESC LIMIT 60'
  ).all();
  const latestSnapshotTimestamp = dailyRows.results.length ? dailyRows.results[0].snapshot_timestamp : null;
  const history = dailyRows.results.reverse().map(r => {
    const d = r.data_json ? JSON.parse(r.data_json) : {};
    const n = v => { const x = parseFloat(String(v || '').replace(',','.')); return isFinite(x) ? x : null; };
    const bar = v => { const x = n(v); return x === null ? null : Math.round(x / 100 * 10) / 10; };
    return {
      timestamp: r.snapshot_timestamp,
      mileageKm: r.mileage_km,
      fuelPercent: r.fuel_percent,
      fuelLitres: r.fuel_litres,
      rangeKm: r.range_km,
      flBar: bar(d['X3 M40d Tire pressure (front left)'] || d['Front Left Pressure kPa']),
      frBar: bar(d['X3 M40d Tire pressure (front right)'] || d['Front Right Pressure kPa']),
      rlBar: bar(d['X3 M40d Tire pressure (rear left)'] || d['Rear Left Pressure kPa']),
      rrBar: bar(d['X3 M40d Tire pressure (rear right)'] || d['Rear Right Pressure kPa'])
    };
  });
  // Resolve odometer from all available feeds instead of trusting only the
  // current BMW/HA entity, which can remain stale after a drive.
  const todayRome = dateKeyInRome(new Date());
  const mileageEvents = [];
  const pushMileage = (km, timestamp, source) => {
    const n = Number(km);
    if (!Number.isFinite(n) || n <= 0 || !timestamp) return;
    mileageEvents.push({ km: n, timestamp, source, date: dateKeyInRome(timestamp) });
  };
  try {
    const rawMileage = await db.prepare(
      `SELECT snapshot_timestamp, state, bmw_timestamp, trigger_reason, attributes_json
       FROM bmw_raw_daily
       WHERE entity_id = 'sensor.x3_m40d_vehicle_mileage'
       ORDER BY snapshot_timestamp DESC LIMIT 400`
    ).all();
    for (const r of rawMileage.results) {
      let src = r.trigger_reason === 'cloudflare_direct' ? 'BMW CarData · Cloudflare' : 'Storico precedente';
      try {
        const a = r.attributes_json ? JSON.parse(r.attributes_json) : {};
        if (a && a.source === 'cloudflare_direct') src = 'BMW CarData · Cloudflare';
      } catch (_) {}
      pushMileage(r.state, r.bmw_timestamp || r.snapshot_timestamp, src);
    }
  } catch (_) {}
  try {
    const cardataMileage = await db.prepare(
      `SELECT c_timestamp, travelled_distance
       FROM bmw_cardata_raw
       WHERE travelled_distance IS NOT NULL
       ORDER BY c_timestamp DESC LIMIT 400`
    ).all();
    for (const r of cardataMileage.results) pushMileage(r.travelled_distance, r.c_timestamp, 'CarData');
  } catch (_) {}
  for (const r of dailyRows.results) {
    if (r.mileage_km !== null && r.mileage_km !== undefined) {
      pushMileage(r.mileage_km, r.snapshot_timestamp || (r.snapshot_date + 'T12:00:00Z'), 'Daily');
    }
  }

  const currentMileageEntity = current['sensor.x3_m40d_vehicle_mileage'];
  if (currentMileageEntity) {
    let currentMileageSource = 'Storico precedente';
    try {
      const a = currentMileageEntity.attributes_json ? JSON.parse(currentMileageEntity.attributes_json) : {};
      if (a && a.source === 'cloudflare_direct') currentMileageSource = 'BMW CarData · Cloudflare';
    } catch (_) {}
    pushMileage(
      currentMileageEntity.value,
      currentMileageEntity.bmw_timestamp || currentMileageEntity.last_updated || new Date().toISOString(),
      currentMileageSource
    );
  }

  mileageEvents.sort((a,b) => new Date(a.timestamp) - new Date(b.timestamp));
  const maxMileageInfo = events => {
    if (!events.length) return null;
    const maxKm = Math.max(...events.map(e => e.km));
    const matching = events.filter(e => Math.abs(e.km - maxKm) < 0.01)
      .sort((a,b) => new Date(a.timestamp) - new Date(b.timestamp));
    return { km:maxKm, firstSeen:matching[0]||null, lastSeen:matching[matching.length-1]||null };
  };
  const currentMileageInfo = maxMileageInfo(mileageEvents);
  const currentMileageEvent = currentMileageInfo ? currentMileageInfo.lastSeen : null;
  const currentMileageChangedAt = currentMileageInfo && currentMileageInfo.firstSeen ? currentMileageInfo.firstSeen.timestamp : null;
  const beforeTodayInfo = maxMileageInfo(mileageEvents.filter(e => e.date < todayRome));
  const beforeTodayEvent = beforeTodayInfo ? beforeTodayInfo.lastSeen : null;
  let resolvedDailyKm = null;
  let resolvedDailyKmSource = null;
  let resolvedDailyKmTimestamp = null;

  const mileageAgeHours = currentMileageChangedAt
    ? Math.max(0, (Date.now() - new Date(currentMileageChangedAt).getTime()) / 3600000)
    : null;

  const progress = [];
  let runningMax = null;
  for (const e of mileageEvents) {
    if (runningMax === null || e.km > runningMax + 0.01) {
      runningMax = e.km;
      progress.push(e);
    }
  }
  let lastMovement = null;
  if (progress.length >= 2) {
    const last = progress[progress.length - 1];
    const prev = progress[progress.length - 2];
    const moved = last.km - prev.km;
    if (moved > 0 && moved < 1000) lastMovement = { distanceKm: Math.round(moved * 10) / 10, timestamp: last.timestamp, source: last.source, odometerKm: last.km };
  }

  // "Km oggi" = increments actually observed during today's Rome calendar day.
  // Never bridge yesterday -> today: that can assign a late/unobserved previous-day
  // drive to today (the previous implementation was doing exactly that).
  const todayProgress = progress.filter(e => e.date === todayRome);
  if (todayProgress.length >= 2) {
    let total = 0;
    for (let i = 1; i < todayProgress.length; i++) {
      const d = todayProgress[i].km - todayProgress[i-1].km;
      if (d > 0 && d < 500) total += d;
    }
    resolvedDailyKm = Math.round(total * 10) / 10;
    const latestToday = todayProgress[todayProgress.length - 1];
    resolvedDailyKmSource = latestToday.source || 'BMW CarData';
    resolvedDailyKmTimestamp = latestToday.timestamp;
  } else if (todayProgress.length === 1) {
    // We have today's current odometer but no same-day baseline yet.
    // Showing 0 or bridging from yesterday would both be misleading.
    resolvedDailyKm = null;
    resolvedDailyKmSource = todayProgress[0].source || 'BMW CarData';
    resolvedDailyKmTimestamp = todayProgress[0].timestamp;
  }

  let milestone81000 = null;
  if (currentMileageEvent) {
    const targetKm = 81000;
    const remainingKm = Math.max(0, targetKm - currentMileageEvent.km);
    const cutoff = Date.now() - 30 * 86400000;
    const recent = mileageEvents.filter(e => new Date(e.timestamp).getTime() >= cutoff && e.km <= currentMileageEvent.km);
    const earliest = recent.length ? recent[0] : null;
    let avgKmPerDay = null;
    if (earliest && currentMileageEvent.km >= earliest.km) {
      const spanDays = Math.max(1, (new Date(currentMileageEvent.timestamp) - new Date(earliest.timestamp)) / 86400000);
      avgKmPerDay = (currentMileageEvent.km - earliest.km) / spanDays;
      if (!(avgKmPerDay > 0)) avgKmPerDay = null;
    }
    let estimatedDate = null;
    if (remainingKm === 0) estimatedDate = currentMileageEvent.timestamp;
    else if (avgKmPerDay) estimatedDate = new Date(Date.now() + (remainingKm / avgKmPerDay) * 86400000).toISOString();
    milestone81000 = { targetKm, remainingKm: Math.round(remainingKm), avgKmPerDay: avgKmPerDay ? Math.round(avgKmPerDay * 10) / 10 : null, estimatedDate };
  }


  // Helper functions
  const row = id => current[id] || {};
  const state = id => row(id).value ?? null;
  const ts = id => row(id).bmwTimestamp || row(id).lastUpdated || null;
  const toNum = v => { if (v===null||v===undefined||v===''||v==='unknown'||v==='unavailable') return null; const n=Number(String(v).replace(',','.')); return isFinite(n)?n:null; };
  const kpaToBar = v => { const n=toNum(v); return n===null?null:Math.round(n/100*10)/10; };
  const isOff = id => String(state(id)).toLowerCase()==='off';
  const isClosed = id => String(state(id)).toLowerCase()==='closed';
  const validState = v => v!==null && v!==undefined && v!=='' && !['unknown','unavailable','none','null'].includes(String(v).toLowerCase());
  const triAllOff = ids => {
    const vals=ids.map(id=>state(id));
    if(!vals.some(validState)) return null;
    if(vals.some(v=>validState(v) && String(v).toLowerCase()!=='off')) return false;
    return vals.filter(validState).every(v=>String(v).toLowerCase()==='off');
  };
  const triAllClosed = ids => {
    const vals=ids.map(id=>state(id));
    if(!vals.some(validState)) return null;
    if(vals.some(v=>validState(v) && String(v).toLowerCase()!=='closed')) return false;
    return vals.filter(validState).every(v=>String(v).toLowerCase()==='closed');
  };
  const round_ = (v,d) => { const p=Math.pow(10,d||0); return Math.round((v+Number.EPSILON)*p)/p; };

  const mileageId = 'sensor.x3_m40d_vehicle_mileage';

  // Tyres
  const tyres = {
    frontLeft: kpaToBar(state('sensor.x3_m40d_tire_pressure_front_left')),
    frontRight: kpaToBar(state('sensor.x3_m40d_tire_pressure_front_right')),
    rearLeft: kpaToBar(state('sensor.x3_m40d_tire_pressure_rear_left')),
    rearRight: kpaToBar(state('sensor.x3_m40d_tire_pressure_rear_right')),
    targetFrontLeft: kpaToBar(state('sensor.x3_m40d_tire_pressure_target_front_left')),
    targetFrontRight: kpaToBar(state('sensor.x3_m40d_tire_pressure_target_front_right')),
    targetRearLeft: kpaToBar(state('sensor.x3_m40d_tire_pressure_target_rear_left')),
    targetRearRight: kpaToBar(state('sensor.x3_m40d_tire_pressure_target_rear_right')),
    bmwTimestamp: ts('sensor.x3_m40d_tire_pressure_front_left'),
    condition: state('sensor.x3_m40d_tyre_condition')
  };

  // Tyre alerts
  const delta = (value, target) => (value===null||target===null)?null:round_(value-target,1);
  const alertCheck = d => d!==null && Math.abs(d)>0.5;
  const deviations = {
    frontLeft: delta(tyres.frontLeft, tyres.targetFrontLeft),
    frontRight: delta(tyres.frontRight, tyres.targetFrontRight),
    rearLeft: delta(tyres.rearLeft, tyres.targetRearLeft),
    rearRight: delta(tyres.rearRight, tyres.targetRearRight)
  };
  const flags = {
    frontLeft: alertCheck(deviations.frontLeft),
    frontRight: alertCheck(deviations.frontRight),
    rearLeft: alertCheck(deviations.rearLeft),
    rearRight: alertCheck(deviations.rearRight)
  };
  tyres.alerts = { ...flags, any: Object.values(flags).some(Boolean), deviations };

  const previousTyreValue = key => {
    for (let i = history.length - 1; i >= 0; i--) {
      const h = history[i];
      if (dateKeyInRome(h.timestamp) >= todayRome) continue;
      if (h[key] !== null && h[key] !== undefined) return h[key];
    }
    return null;
  };
  const tyreTrend = {
    frontLeft: delta(tyres.frontLeft, previousTyreValue('flBar')),
    frontRight: delta(tyres.frontRight, previousTyreValue('frBar')),
    rearLeft: delta(tyres.rearLeft, previousTyreValue('rlBar')),
    rearRight: delta(tyres.rearRight, previousTyreValue('rrBar'))
  };
  const trendFlags = Object.fromEntries(Object.entries(tyreTrend).map(([k,v]) => [k, v !== null && Math.abs(v) >= 0.2]));
  tyres.trend = tyreTrend;
  tyres.trendAlerts = { ...trendFlags, any: Object.values(trendFlags).some(Boolean) };

  // Trip
  const clamp = v => { const n=toNum(v); return n===null?0:Math.max(0,Math.min(100,n)); };
  const ecoPro = clamp(state('sensor.x3_m40d_trip_eco_pro_mode_share'));
  const ecoProPlus = clamp(state('sensor.x3_m40d_trip_eco_pro_plus_share'));
  const electric = clamp(state('sensor.x3_m40d_trip_electric_share'));
  const normal = Math.max(0, round_(100-ecoPro-ecoProPlus-electric, 1));
  const tripRaw = state('binary_sensor.x3_m40d_trip_in_progress');
  const tripInProgress = validState(tripRaw) ? String(tripRaw).toLowerCase()!=='off' : null;
  const trip = { ecoPro, ecoProPlus, electric, normal, inProgress: tripInProgress, totalReported: round_(ecoPro+ecoProPlus+electric,1) };

  // Analytics from history
  const analytics = computeDailyAnalytics(history);
  const refuels=[];
  for(let i=1;i<history.length;i++){
    const prev=history[i-1],curr=history[i],a=resolveFuelLitres(prev),b=resolveFuelLitres(curr);
    if(a===null||b===null) continue;
    const added=b-a;
    if(added>=8) refuels.push({timestamp:curr.timestamp,litresEstimated:Math.round(added*10)/10,odometerKm:curr.mileageKm});
  }
  const consumptionPoints=(analytics.consumption&&analytics.consumption.points)||[];
  const consumptionCoveredKm=consumptionPoints.reduce((s,p)=>s+(Number(p.deltaKm)||0),0);
  const consumptionConfidence=consumptionPoints.length>=8&&consumptionCoveredKm>=500?'alta':(consumptionPoints.length>=4&&consumptionCoveredKm>=200?'media':'bassa');
  const locationState = state('device_tracker.x3_m40d');
  const normalizeLocation = v => { if(!v) return 'Stato sconosciuto'; return String(v).toLowerCase()==='home'?'Home':String(v); };

  // GPS location
  let locationCoords = null;
  let locationTimestamp = null;
  try {
    const locRow = rows.find(r => r.entity_id === 'device_tracker.x3_m40d');
    if (locRow && locRow.attributes_json) {
      const a = JSON.parse(locRow.attributes_json);
      if (a.latitude && a.longitude) {
        locationCoords = { lat: a.latitude, lng: a.longitude, heading: a.heading || null };
        locationTimestamp = locRow.bmw_timestamp || locRow.last_updated || null;
      }
    }
    if (!locationCoords) {
      const lat = toNum(state('vehicle.cabin.infotainment.navigation.currentLocation.latitude'));
      const lng = toNum(state('vehicle.cabin.infotainment.navigation.currentLocation.longitude'));
      const heading = toNum(state('vehicle.cabin.infotainment.navigation.currentLocation.heading'));
      if (lat !== null && lng !== null) {
        locationCoords = { lat, lng, heading };
        locationTimestamp =
          ts('vehicle.cabin.infotainment.navigation.currentLocation.latitude') ||
          ts('vehicle.cabin.infotainment.navigation.currentLocation.longitude');
      }
    }
    if (!locationCoords) {
      const cdRow = await db.prepare('SELECT latitude, longitude, heading, c_timestamp FROM bmw_cardata_raw WHERE latitude IS NOT NULL ORDER BY c_timestamp DESC LIMIT 1').first();
      if (cdRow) {
        locationCoords = { lat: cdRow.latitude, lng: cdRow.longitude, heading: cdRow.heading || null };
        locationTimestamp = cdRow.c_timestamp || null;
      }
    }
  } catch(_) {}
  const locationLabel=await getLocationLabel(db, locationCoords);
  // Calculate distance this month from bmw_daily (more accurate than BMW entity)
  let distanceThisMonth = 0;
  try {
    const nowStr = dateKeyInRome(new Date());
    const monthStart = nowStr.substring(0, 8) + '01';
    const monthDailyRows = dailyRows.results.filter(r => r.snapshot_date >= monthStart && r.mileage_km);
    if (monthDailyRows.length > 0) {
      const startKms = monthDailyRows.map(r => r.mileage_start_km || r.mileage_km).filter(v => v);
      const endKms = monthDailyRows.map(r => r.mileage_km).filter(v => v);
      if (startKms.length && endKms.length) {
        distanceThisMonth = Math.max(...endKms) - Math.min(...startKms);
      }
    }
  } catch(_) { distanceThisMonth = toNum(state('sensor.x3_m40d_driving_distance_this_month')); }

  // Get latest diesel price from D1, then prefer local Gasolio Self from Carburanti Italia.
  let dieselPriceEur = DIESEL_PRICE_EUR;
  let dieselPriceDate = DIESEL_PRICE_DATE;
  let dieselPriceSource = 'Fallback';
  let dieselPriceMeta = null;
  try {
    const priceRow = await db.prepare('SELECT date, price_eur FROM diesel_prices ORDER BY date DESC LIMIT 1').first();
    if (priceRow) { dieselPriceEur = priceRow.price_eur; dieselPriceDate = priceRow.date; dieselPriceSource='D1'; }
  } catch(_) {}
  const localDiesel=await getLocalDieselPrice(locationCoords);
  if(localDiesel){
    dieselPriceEur=localDiesel.priceEur;
    dieselPriceDate=localDiesel.updatedAt||dateKeyInRome(new Date());
    dieselPriceSource=localDiesel.source;
    dieselPriceMeta=localDiesel;
  }

  const freshClass=(v,greenH,amberH)=>{
    if(!v)return 'unknown'; const d=new Date(v); if(Number.isNaN(d.getTime()))return 'unknown';
    const h=Math.max(0,(Date.now()-d.getTime())/3600000);
    return h<=greenH?'fresh':(h<=amberH?'stale':'old');
  };
  const lockFreshTs=ts('sensor.x3_m40d_doors_overall_state')||ts('sensor.wbatx91030lp62133_doors_lock')||ts('vehicle.cabin.door.status');
  const freshness={
    odometer:{timestamp:currentMileageChangedAt||null,status:freshClass(currentMileageChangedAt,24,72)},
    fuel:{timestamp:ts('sensor.x3_m40d_range_tank_level')||ts('sensor.x3_m40d_range_total_range_last_sent'),status:freshClass(ts('sensor.x3_m40d_range_tank_level')||ts('sensor.x3_m40d_range_total_range_last_sent'),24,72)},
    tyres:{timestamp:tyres.bmwTimestamp,status:freshClass(tyres.bmwTimestamp,72,168)},
    battery:{timestamp:ts('sensor.wbatx91030lp62133_battery_recharge_required'),status:freshClass(ts('sensor.wbatx91030lp62133_battery_recharge_required'),168,720)},
    location:{timestamp:locationTimestamp,status:freshClass(locationTimestamp,24,72)},
    security:{timestamp:lockFreshTs,status:freshClass(lockFreshTs,24,72)},
    pipeline:{timestamp:latestSnapshotTimestamp,status:freshClass(latestSnapshotTimestamp,4,12)}
  };
  const anomalies=[];
  if(freshness.odometer.status==='old') anomalies.push({severity:'warn',text:'Odometro non aggiornato da oltre 24 ore',timestamp:freshness.odometer.timestamp});
  if(freshness.battery.status==='old') anomalies.push({severity:'info',text:'Stato batteria 12V non recente',timestamp:freshness.battery.timestamp});
  if(freshness.security.status==='old') anomalies.push({severity:'info',text:'Stato chiusura vettura non recente',timestamp:freshness.security.timestamp});
  if(tyres.trendAlerts?.any) anomalies.push({severity:'warn',text:'Variazione pressione ≥0,2 bar rilevata',timestamp:tyres.bmwTimestamp});
  if(tyres.alerts?.any) anomalies.push({severity:'alert',text:'Pressione pneumatici fuori target',timestamp:tyres.bmwTimestamp});
  if(String(state('sensor.x3_m40d_doors_overall_state')||'').toUpperCase()==='UNLOCKED' && freshness.security.status!=='old' && freshness.security.status!=='unknown') anomalies.push({severity:'alert',text:'Vettura sbloccata',timestamp:lockFreshTs});
  const severityOrder={alert:0,warn:1,info:2,ok:3};
  anomalies.sort((a,b)=>(severityOrder[a.severity]??9)-(severityOrder[b.severity]??9));
  if(!anomalies.length) anomalies.push({severity:'ok',text:'Nessuna anomalia recente rilevata'});

  const payload = {
    generatedAt: new Date().toISOString(),
    vehicle: { name: 'BMW X3 M40d', generation: 'G01', subtitle: 'My Vehicle Dashboard' },
    core: {
      mileageKm: currentMileageEvent ? currentMileageEvent.km : toNum(state(mileageId)),
      mileageSource: currentMileageEvent ? currentMileageEvent.source : 'BMW/HA',
      mileageUpdatedAt: currentMileageChangedAt || (currentMileageEvent ? currentMileageEvent.timestamp : ts(mileageId)),
      mileageObservedAt: currentMileageEvent ? currentMileageEvent.timestamp : ts(mileageId),
      fuelPercent: toNum(state('sensor.x3_m40d_range_tank_level')),
      fuelLitres: toNum(state('sensor.x3_m40d_range_tank_level_2')),
      rangeKm: toNum(state('sensor.x3_m40d_range_total_range_last_sent')),
      fuelTimestamp: ts('sensor.x3_m40d_range_tank_level') || ts('sensor.x3_m40d_range_total_range_last_sent'),
      lastBmwTimestamp: ts(mileageId),
      lastHaUpdated: row(mileageId).lastUpdated || null,
      locationState
    },
    tyres,
    security: {
      lockState: state('sensor.x3_m40d_doors_overall_state') || state('sensor.wbatx91030lp62133_doors_lock'),
      doorsClosed: triAllOff(['binary_sensor.x3_m40d_door_state_front_driver','binary_sensor.x3_m40d_door_state_front_passenger','binary_sensor.x3_m40d_door_state_rear_driver','binary_sensor.x3_m40d_door_state_rear_passenger']),
      windowsClosed: triAllClosed(['sensor.x3_m40d_window_state_front_driver','sensor.x3_m40d_window_state_front_passenger','sensor.x3_m40d_window_state_rear_driver','sensor.x3_m40d_window_state_rear_passenger']),
      hoodClosed: triAllOff(['binary_sensor.x3_m40d_hood_state']),
      tailgateClosed: triAllOff(['binary_sensor.x3_m40d_tailgate_state','binary_sensor.x3_m40d_tailgate_door_state']),
      sunroofClosed: triAllClosed(['sensor.x3_m40d_sunroof_overall_state','sensor.x3_m40d_sunroof_state']),
      tripInProgress,
      lockTimestamp: ts('sensor.x3_m40d_doors_overall_state') || ts('sensor.wbatx91030lp62133_doors_lock') || ts('vehicle.cabin.door.status'),
      doorsTimestamp: ts('binary_sensor.x3_m40d_door_state_front_driver') || ts('vehicle.cabin.door.row1.driver.isOpen'),
      windowsTimestamp: ts('sensor.x3_m40d_window_state_front_driver') || ts('vehicle.cabin.window.row1.driver.status'),
      hoodTimestamp: ts('binary_sensor.x3_m40d_hood_state') || ts('vehicle.body.hood.isOpen'),
      tailgateTimestamp: ts('binary_sensor.x3_m40d_tailgate_state') || ts('vehicle.body.trunk.isOpen'),
      sunroofTimestamp: ts('sensor.x3_m40d_sunroof_overall_state') || ts('vehicle.cabin.sunroof.overallStatus')
    },
    battery12v: {
      rechargeRequired: toNum(state('sensor.wbatx91030lp62133_battery_recharge_required')),
      rawHealthState: state('sensor.wbatx91030lp62133_battery_health_state'),
      bmwTimestamp: ts('sensor.wbatx91030lp62133_battery_recharge_required')
    },
    climate: {
      preconditioningState: state('sensor.x3_m40d_preconditioning_state'),
      errorReason: state('sensor.x3_m40d_preconditioning_error_reason'),
      remainingMinutes: toNum(state('sensor.x3_m40d_preconditioning_remaining_time')),
      bmwTimestamp: ts('sensor.x3_m40d_preconditioning_state')
    },
    service: {
      cbs: state('sensor.wbatx91030lp62133_service_condition_based_services'),
      bmwTimestamp: ts('sensor.wbatx91030lp62133_service_condition_based_services'),
      items: (() => {
        try {
          const svc = rows.find(r => r.entity_id === 'sensor.wbatx91030lp62133_service_condition_based_services');
          if (svc && svc.attributes_json) {
            const attrs = JSON.parse(svc.attributes_json);
            return (attrs.items || []).map(i => ({
              title: i.title || 'Unknown',
              status: i.status || 'UNKNOWN',
              date: i.date || '-',
              kmRemaining: i.unitOfLengthRemaining || '-',
              description: i.description || '-'
            }));
          }
        } catch(e) {}
        return [];
      })()
    },
    trip,
    analytics,
    quick: {
      dailyKm: resolvedDailyKm,
      dailyKmSource: resolvedDailyKmSource,
      dailyKmUpdatedAt: resolvedDailyKmTimestamp,
      dailyKmStale: mileageAgeHours !== null ? mileageAgeHours > 6 : true,
      dailyKmBaseline: beforeTodayEvent ? beforeTodayEvent.km : null,
      consumptionL100: analytics.consumption.latest,
      ecoProPercent: ecoPro,
      vehicleState: tripInProgress===true ? 'In viaggio' : ((locationLabel && locationLabel.label) || normalizeLocation(locationState))
    },
    location: locationCoords ? { ...locationCoords, timestamp: locationTimestamp, label: locationLabel?.label || null, displayName: locationLabel?.displayName || null } : null,
    lastMovement,
    milestone81000,
    refuels:{count:refuels.length,last:refuels.length?refuels[refuels.length-1]:null,recent:refuels.slice(-5).reverse()},
    freshness,
    anomalies,
    consumptionQuality:{confidence:consumptionConfidence,coveredKm:Math.round(consumptionCoveredKm),samples:consumptionPoints.length},
    distanceThisMonth,
    distanceThisMonthPartial: Boolean(currentMileageChangedAt && dateKeyInRome(currentMileageChangedAt) < todayRome),
    distanceThisMonthThrough: currentMileageChangedAt || null,
    costs: {
      dieselPriceEur: dieselPriceEur,
      dieselPriceDate: dieselPriceDate,
      dieselPriceSource,
      dieselPriceMeta,
      costPerKm: analytics.consumption.average ? (analytics.consumption.average / 100 * dieselPriceEur) : null,
      costThisMonth: distanceThisMonth && analytics.consumption.average ? Math.round(distanceThisMonth * analytics.consumption.average / 100 * dieselPriceEur) : null
    },
    meta: {
      monitoredEntities: Object.keys(current).length,
      historyRows: history.length,
      tankCapacityLitres: FUEL_TANK_CAPACITY_L,
      latestSnapshotTimestamp
    },
    extra: {
      tripEcoPro: toNum(state('sensor.x3_m40d_trip_eco_pro_mode_share')),
      tripEcoProPlus: toNum(state('sensor.x3_m40d_trip_eco_pro_plus_share')),
      tripElectric: toNum(state('sensor.x3_m40d_trip_electric_share')),
      precondState: state('sensor.x3_m40d_preconditioning_state'),
      precondError: state('sensor.x3_m40d_preconditioning_error_reason'),
      precondTime: toNum(state('sensor.x3_m40d_preconditioning_remaining_time')),
      doorStatus: state('vehicle.cabin.door.status') || state('sensor.wbatx91030lp62133_doors_lock'),
      phoneConnected: state('vehicle.cabin.infotainment.isMobilePhoneConnected'),
      lightsOn: state('vehicle.body.lights.isRunningOn')
    },
    history
  };

  return jsonResponse(payload, 200, cors);
}

// ─────────────────────────────────────────────
// Compute daily analytics from history
// ─────────────────────────────────────────────
function computeDailyAnalytics(history) {
  if (!history || history.length < 2) {
    return {
      enoughHistory: false,
      dailyKm: { latest: null, average: null, points: [] },
      consumption: { latest: null, average: null, points: [], unit: 'L/100km' }
    };
  }
  const round_ = (v,d) => { const p=Math.pow(10,d||0); return Math.round((v+Number.EPSILON)*p)/p; };
  const kmPoints = [], consumptionPoints = [];

  for (let i = 1; i < history.length; i++) {
    const prev = history[i-1], curr = history[i];
    if (prev.mileageKm === null || curr.mileageKm === null) continue;
    const deltaKm = curr.mileageKm - prev.mileageKm;
    if (!(deltaKm > 0)) continue;
    kmPoints.push({ timestamp: curr.timestamp, value: round_(deltaKm, 1) });

    const prevFuelL = resolveFuelLitres(prev);
    const currFuelL = resolveFuelLitres(curr);
    if (prevFuelL === null || currFuelL === null) continue;
    const fuelUsedL = prevFuelL - currFuelL;
    if (!(fuelUsedL > 0)) continue;
    const l100 = (fuelUsedL / deltaKm) * 100;
    if (!isFinite(l100) || l100 <= 0) continue;
    consumptionPoints.push({ timestamp: curr.timestamp, value: round_(l100, 1), deltaKm: round_(deltaKm, 1), fuelUsedLitres: round_(fuelUsedL, 2) });
  }

  const avg = arr => arr.length ? arr.reduce((s,v) => s+v, 0) / arr.length : null;
  return {
    enoughHistory: kmPoints.length > 0,
    dailyKm: {
      latest: kmPoints.length ? kmPoints[kmPoints.length-1].value : null,
      average: kmPoints.length ? round_(avg(kmPoints.map(p=>p.value)), 1) : null,
      points: kmPoints
    },
    consumption: {
      latest: consumptionPoints.length ? consumptionPoints[consumptionPoints.length-1].value : null,
      average: consumptionPoints.length ? round_(avg(consumptionPoints.map(p=>p.value)), 1) : null,
      points: consumptionPoints,
      unit: 'L/100km'
    }
  };
}

function resolveFuelLitres(point) {
  if (point.fuelLitres !== null && point.fuelLitres !== undefined) return point.fuelLitres;
  if (point.fuelPercent !== null && point.fuelPercent !== undefined) return FUEL_TANK_CAPACITY_L * point.fuelPercent / 100;
  return null;
}

// ─────────────────────────────────────────────
// GET /api/analytics — Extended analytics
// ─────────────────────────────────────────────
async function handleGetAnalytics(env, days, cors) {
  const db = env.DB;
  const round_ = (v,d) => { const p=Math.pow(10,d||0); return Math.round((v+Number.EPSILON)*p)/p; };
  const toNum = v => { if(v===null||v===undefined||v===''||v==='unknown') return NaN; return parseFloat(String(v).replace(',','.')); };

  // Read all daily rows
  const dailyRows = await db.prepare('SELECT * FROM bmw_daily ORDER BY snapshot_date ASC').all();

  // Read cardata for mileage enrichment
  const cardataRows = await db.prepare(
    'SELECT c_timestamp, travelled_distance FROM bmw_cardata_raw WHERE travelled_distance IS NOT NULL ORDER BY c_timestamp ASC'
  ).all();

  // Build cardata daily map (UTC→Rome date)
  const cardataDaily = {};
  for (const r of cardataRows.results) {
    if (!r.c_timestamp || !r.travelled_distance) continue;
    const km = parseFloat(r.travelled_distance);
    if (isNaN(km)) continue;
    const dt = new Date(r.c_timestamp);
    if (isNaN(dt.getTime())) continue;
    const date = dt.toISOString().substring(0, 10); // Simplified UTC date
    if (!cardataDaily[date]) cardataDaily[date] = { firstKm: km, lastKm: km };
    else {
      if (km < cardataDaily[date].firstKm) cardataDaily[date].firstKm = km;
      if (km > cardataDaily[date].lastKm) cardataDaily[date].lastKm = km;
    }
  }
  for (const d in cardataDaily) cardataDaily[d].dailyKm = cardataDaily[d].lastKm - cardataDaily[d].firstKm;

  // Parse daily points
  const dailyPoints = [];
  for (const r of dailyRows.results) {
    const ts = r.snapshot_timestamp || '';
    const date = r.snapshot_date || ts.substring(0, 10);
    const d = r.data_json ? JSON.parse(r.data_json) : {};

    let mileageEnd = r.mileage_km;
    if (mileageEnd === null) {
      let v = toNum(d['Mileage km'] || d['X3 M40d Vehicle mileage']);
      if (!isNaN(v)) mileageEnd = v;
    }
    let fuelL = r.fuel_litres;
    if (fuelL === null) {
      let v = toNum(d['Fuel L'] || d['X3 M40d Range Tank level']);
      if (!isNaN(v)) fuelL = v;
    }
    if (isNaN(mileageEnd) || mileageEnd === 0 || mileageEnd === null) continue;

    const cd = cardataDaily[date];
    let dayStart, dayEnd, dailyDist;
    if (cd) {
      dayStart = cd.firstKm; dayEnd = cd.lastKm; dailyDist = cd.dailyKm;
    } else {
      const ms = r.mileage_start_km;
      dayStart = (ms !== null && ms !== undefined) ? ms : mileageEnd;
      dayEnd = mileageEnd;
      const dd = r.daily_distance_km;
      dailyDist = (dd !== null && dd !== undefined) ? dd : 0;
    }

    dailyPoints.push({ date, dayStart, dayEnd, dailyDist, fuelL, hasFuel: fuelL !== null && !isNaN(fuelL) });
  }
  if (dailyPoints.length < 1) return jsonResponse({ error: 'No valid data points' }, 200, cors);
  dailyPoints.sort((a, b) => a.date < b.date ? -1 : a.date > b.date ? 1 : 0);

  // Period filtering
  const today = new Date().toISOString().substring(0, 10);
  let periodStart, periodEnd, periodLabel, points;
  if (days > 0) {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - (days - 1));
    periodStart = cutoff.toISOString().substring(0, 10);
    periodEnd = today;
    points = dailyPoints.filter(p => p.date >= periodStart && p.date <= periodEnd);
    periodLabel = days + 'd';
  } else {
    periodStart = dailyPoints[0].date;
    periodEnd = today;
    points = dailyPoints;
    periodLabel = 'all';
  }
  if (points.length < 1) return jsonResponse({ error: 'No data in window', days, periodStart, periodEnd }, 200, cors);

  const first = points[0], last = points[points.length - 1];
  const calendarDays = days > 0 ? days : (Math.round((new Date(periodEnd) - new Date(periodStart)) / 86400000) + 1);
  const distanceKm = Math.round(last.dayEnd - first.dayStart);

  let observedDailyKm = 0, observedDrivingDays = 0;
  let longestDay = { date: '', km: 0 };
  const dailySeries = [];
  for (const p of points) {
    observedDailyKm += p.dailyDist;
    if (p.dailyDist > 0) observedDrivingDays++;
    if (p.dailyDist > longestDay.km) longestDay = { date: p.date, km: p.dailyDist };
    dailySeries.push({ date: p.date, km: Math.round(p.dailyDist) });
  }
  observedDailyKm = Math.round(observedDailyKm);
  const unallocatedGapKm = distanceKm - observedDailyKm;

  // Fuel analysis
  const REFUEL_THR = 2, NOISE_THR = 0.5;
  let fuelConsumed = 0, fuelCoveredKm = 0, hasUnresolved = false;
  const refuelEvents = [];
  for (let i = 1; i < points.length; i++) {
    const prev = points[i-1], curr = points[i];
    if (curr.hasFuel && prev.hasFuel) {
      const raw = prev.fuelL - curr.fuelL;
      const interDayKm = curr.dayEnd - prev.dayEnd;
      if (raw < -REFUEL_THR) {
        hasUnresolved = true;
        refuelEvents.push({ date: curr.date, before: prev.fuelL, after: curr.fuelL });
      } else if (Math.abs(raw) >= NOISE_THR && raw > 0) {
        fuelConsumed += raw;
        fuelCoveredKm += Math.max(0, interDayKm);
      }
    }
  }
  const fuelPoints = points.filter(p => p.hasFuel);
  let conf = 'insufficient', kml = null;
  if (fuelConsumed >= 10 && fuelCoveredKm >= 150 && !hasUnresolved) {
    kml = round_(fuelCoveredKm / fuelConsumed, 1); conf = 'reliable';
  } else if (fuelConsumed > 0 && fuelCoveredKm > 0 && !hasUnresolved && fuelConsumed >= 5 && fuelCoveredKm >= 50) {
    kml = round_(fuelCoveredKm / fuelConsumed, 1); conf = 'provisional';
  }

  // Trip reconstruction
  const tripData = await reconstructTrips(db, periodStart, periodEnd);

  return jsonResponse({
    window: periodLabel, periodStart, periodEnd,
    dataStart: first.date, calendarDays,
    mileage: { firstOdometer: first.dayStart, lastOdometer: last.dayEnd, distanceKm, observedDailyKm, unallocatedGapKm },
    driving: {
      observedDrivingDays, drivingDaysComplete: unallocatedGapKm === 0,
      avgKmPerDay: calendarDays > 0 ? round_(distanceKm / calendarDays, 1) : 0,
      avgKmPerDrivingDay: observedDrivingDays > 0 ? round_(observedDailyKm / observedDrivingDays, 1) : 0,
      longestDay: { date: longestDay.date, km: Math.round(longestDay.km) }
    },
    fuel: {
      fuelDataStart: fuelPoints.length > 0 ? fuelPoints[0].date : null,
      fuelDataEnd: fuelPoints.length > 0 ? fuelPoints[fuelPoints.length-1].date : null,
      fuelCoveredKm: Math.round(fuelCoveredKm), fuelConsumedL: round_(fuelConsumed, 1),
      fuelSampleCount: fuelPoints.length, refuelCount: refuelEvents.length,
      refuelEvents, kmPerLitre: kml, consumptionConfidence: conf
    },
    trips: tripData, dailySeries, dataPoints: points.length
  }, 200, cors);
}

// ─────────────────────────────────────────────
// Trip reconstruction from raw data
// ─────────────────────────────────────────────
async function reconstructTrips(db, startDate, endDate) {
  const rows = await db.prepare(
    `SELECT snapshot_timestamp, entity_id, state, trigger_reason
     FROM bmw_raw_daily
     WHERE snapshot_timestamp >= ? AND snapshot_timestamp <= ?
     ORDER BY snapshot_timestamp ASC`
  ).bind(startDate, endDate + 'T99:99:99').all();

  const events = [];
  const mileageBySnapshot = {};

  // First pass: collect mileage by snapshot timestamp
  for (const r of rows.results) {
    if (r.entity_id === 'sensor.x3_m40d_vehicle_mileage') {
      mileageBySnapshot[r.snapshot_timestamp] = parseFloat(r.state);
    }
  }

  // Second pass: collect trip events
  for (const r of rows.results) {
    if (r.trigger_reason !== 'trip_start' && r.trigger_reason !== 'trip_end') continue;
    events.push({
      ts: r.snapshot_timestamp,
      trigger: r.trigger_reason,
      mileage: mileageBySnapshot[r.snapshot_timestamp] ?? null
    });
  }

  if (events.length === 0) return { available: false, note: 'No trip events recorded yet.' };

  const trips = [];
  let pendingStart = null;
  for (const ev of events) {
    if (ev.trigger === 'trip_start') { pendingStart = ev; }
    else if (ev.trigger === 'trip_end' && pendingStart) {
      const dist = (ev.mileage !== null && pendingStart.mileage !== null) ? ev.mileage - pendingStart.mileage : null;
      const durMs = new Date(ev.ts).getTime() - new Date(pendingStart.ts).getTime();
      trips.push({
        startTs: pendingStart.ts, endTs: ev.ts,
        startKm: pendingStart.mileage, endKm: ev.mileage,
        distanceKm: dist !== null ? Math.round(dist) : null,
        durationMin: durMs > 0 ? Math.round(durMs / 60000) : null
      });
      pendingStart = null;
    }
  }

  return { available: true, tripCount: trips.length, trips, unmatchedStarts: pendingStart ? 1 : 0, totalTripEvents: events.length };
}

// ─────────────────────────────────────────────
// GET /api/dump
// ─────────────────────────────────────────────
async function handleDump(env, cors) {
  const db = env.DB;
  const daily = await db.prepare('SELECT * FROM bmw_daily ORDER BY snapshot_date ASC').all();
  const cardata = await db.prepare('SELECT * FROM bmw_cardata_raw ORDER BY c_timestamp ASC').all();
  return jsonResponse({ daily: daily.results, cardata_raw: cardata.results }, 200, cors);
}


// ─────────────────────────────────────────────

async function handleImport(request, env, cors) {
  const body = await request.json();
  const db = env.DB;
  const table = body.table;
  const rows = body.rows;
  if (!table || !rows || !rows.length) return jsonResponse({error: 'Missing table or rows'}, 400, cors);

  const results = [];
  const BATCH = 50;
  for (let i = 0; i < rows.length; i += BATCH) {
    const batch = rows.slice(i, i + BATCH);
    const stmts = [];
    
    for (const row of batch) {
      if (table === 'bmw_current') {
        stmts.push(db.prepare(
          `INSERT OR REPLACE INTO bmw_current (entity_id, category, friendly_name, value, unit, last_changed, last_updated, bmw_timestamp, attributes_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(row.entity_id, row.category||'', row.friendly_name||'', row.value||'', row.unit||'', row.last_changed||'', row.last_updated||'', row.bmw_timestamp||'', row.attributes_json||''));
      } else if (table === 'bmw_entities') {
        stmts.push(db.prepare(
          `INSERT OR REPLACE INTO bmw_entities (entity_id, friendly_name, device, integration, category, unit, first_seen, last_seen, included_in_daily) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(row.entity_id, row.friendly_name||'', row.device||'', row.integration||'', row.category||'', row.unit||'', row.first_seen||'', row.last_seen||'', row.included||'Yes'));
      } else if (table === 'bmw_cardata_metadata') {
        stmts.push(db.prepare(
          `INSERT INTO bmw_cardata_metadata (technical_name, description, value_type, value_range, unit) VALUES (?, ?, ?, ?, ?)`
        ).bind(row.technical_name, row.description||'', row.value_type||'', row.value_range||'', row.unit||''));
      } else if (table === 'bmw_daily') {
        stmts.push(db.prepare(
          `INSERT OR REPLACE INTO bmw_daily (snapshot_timestamp, snapshot_date, data_json, mileage_km, mileage_start_km, daily_distance_km, fuel_percent, fuel_litres, range_km, lock_state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(row.snapshot_timestamp, row.snapshot_date, row.data_json||'{}', row.mileage_km, row.mileage_start_km, row.daily_distance_km, row.fuel_percent, row.fuel_litres, row.range_km, row.lock_state));
      } else if (table === 'bmw_raw_daily') {
        stmts.push(db.prepare(
          `INSERT INTO bmw_raw_daily (snapshot_timestamp, entity_id, friendly_name, state, unit, device_class, last_changed, last_updated, attributes_json, bmw_timestamp, trigger_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(row.snapshot_timestamp, row.entity_id, row.friendly_name||'', row.state||'', row.unit||'', row.device_class||'', row.last_changed||'', row.last_updated||'', row.attributes_json||'', row.bmw_timestamp||'', row.trigger_reason||'scheduled'));
      } else if (table === 'bmw_cardata_raw') {
        stmts.push(db.prepare(
          `INSERT INTO bmw_cardata_raw (c_timestamp, door_row2_driver, door_row1_passenger, door_row1_driver, sunroof_status, trunk_door, altitude, longitude, latitude, sunroof_position, sunroof_tiltstatus, door_row2_passenger, travelled_distance, sunroof_overallstatus, hood, trunk, heading) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(row.c_timestamp, row.d_r2_driver||'', row.d_r1_passenger||'', row.d_r1_driver||'', row.sunroof_status||'', row.trunk_door||'', row.altitude, row.longitude, row.latitude, row.sunroof_pos, row.sunroof_tilt||'', row.d_r2_passenger||'', row.travelled, row.sunroof_overall||'', row.hood||'', row.trunk||'', row.heading));
      }
    }
    
    if (stmts.length > 0) {
      await db.batch(stmts);
      results.push({batch: Math.floor(i/BATCH)+1, rows: stmts.length});
    }
  }

  return jsonResponse({status: 'OK', table, totalRows: rows.length, batches: results}, 200, cors);
}

// ─────────────────────────────────────────────
// Dashboard HTML
// ─────────────────────────────────────────────

// Car image endpoint
const CAR_IMAGE_B64 = "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";
let _carImageBuf = null;
function serveCarImage() {
  if (!_carImageBuf) {
    const raw = atob(CAR_IMAGE_B64);
    const buf = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
    _carImageBuf = buf;
  }
  return new Response(_carImageBuf, {
    headers: {
      'Content-Type': 'image/jpeg',
      'Cache-Control': 'public, max-age=86400',
      'Access-Control-Allow-Origin': '*',
    }
  });
}


function serveVehicleInfo() {
  const html = `<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>BMW X3 M40d \u00b7 Scheda Veicolo</title>
  <style>
    :root{--bg:#0a1726;--card:#111d2e;--text:#e4ecf5;--muted:#7b93a8;--accent:#438eff;--line:rgba(39,71,102,.4);--green:#2ea55c}
    *{margin:0;padding:0;box-sizing:border-box}
    html{scroll-behavior:smooth}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
    .topbar{position:sticky;top:0;z-index:100;backdrop-filter:blur(18px);background:rgba(10,23,38,.85);padding:16px 24px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}
    .topbar a{color:var(--accent);text-decoration:none;font-size:14px;display:flex;align-items:center;gap:6px}
    .topbar h1{font-size:18px;font-weight:700}
    .shell{max-width:900px;margin:0 auto;padding:24px 20px}
    .hero{display:flex;gap:24px;align-items:center;margin-bottom:32px;padding:24px;background:var(--card);border-radius:16px;border:1px solid var(--line)}
    .hero img{width:280px;border-radius:12px;flex-shrink:0}
    .hero-data h2{font-size:26px;font-weight:800;margin-bottom:4px}
    .hero-data p{color:var(--muted);font-size:14px;margin-bottom:12px}
    .hero-spec{display:grid;grid-template-columns:1fr 1fr;gap:6px 16px;font-size:13px}
    .hero-spec span{color:var(--muted)}
    .hero-spec strong{color:var(--text)}
    .section{margin-bottom:28px}
    .section-title{font-size:15px;font-weight:700;color:var(--accent);margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:8px}
    .opts{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px}
    .opt{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;display:flex;align-items:flex-start;gap:10px;transition:border-color .2s}
    .opt:hover{border-color:var(--accent)}
    .opt-code{font-family:monospace;font-size:12px;color:var(--accent);background:rgba(67,142,255,.12);padding:2px 6px;border-radius:4px;flex-shrink:0;margin-top:2px}
    .opt-name{font-size:13px;line-height:1.4}
    @media(max-width:700px){.hero{flex-direction:column;text-align:center}.hero img{width:100%;max-width:320px}.hero-spec{grid-template-columns:1fr}.opts{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <header class="topbar">
    <a href="/">\u2190 Dashboard</a>
    <h1>Scheda Veicolo</h1>
    <span style="width:80px"></span>
  </header>
  <main class="shell">
    <div class="hero">
      <img src="/car.jpg" alt="BMW X3 M40d">
      <div class="hero-data">
        <h2>BMW X3 M40d</h2>
        <p>G01 \u00b7 Sports Activity Vehicle \u00b7 2019</p>
        <div class="hero-spec">
          <div><span>VIN</span><br><strong>WBATX9••••••62133</strong></div>
          <div><span>Produzione</span><br><strong>13 settembre 2019</strong></div>
          <div><span>Motore</span><br><strong>B57T \u2014 6 cil. diesel biturbo</strong></div>
          <div><span>Cambio</span><br><strong>Sport Automatic</strong></div>
          <div><span>Colore</span><br><strong>Alpinweiss 3</strong></div>
          <div><span>Interni</span><br><strong>Leather Merino Tartufo</strong></div>
          <div><span>Trazione</span><br><strong>xDrive (integrale)</strong></div>
          <div><span>Sterzo</span><br><strong>Guida sinistra</strong></div>
        </div>
      </div>
    </div>

    <nav style="background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 22px;margin-bottom:28px">
      <div style="font-size:13px;font-weight:700;color:var(--muted);margin-bottom:10px;text-transform:uppercase;letter-spacing:.5px">Indice</div>
      <div style="display:flex;flex-wrap:wrap;gap:8px">
        <a href="#performance" style="background:rgba(67,142,255,.1);color:var(--accent);padding:8px 14px;border-radius:8px;text-decoration:none;font-size:13px;font-weight:600;border:1px solid rgba(67,142,255,.2);transition:all .2s">\ud83c\udfc1 M Performance</a>
        <a href="#comfort" style="background:rgba(67,142,255,.1);color:var(--accent);padding:8px 14px;border-radius:8px;text-decoration:none;font-size:13px;font-weight:600;border:1px solid rgba(67,142,255,.2);transition:all .2s">\ud83d\udecb\ufe0f Comfort</a>
        <a href="#multimedia" style="background:rgba(67,142,255,.1);color:var(--accent);padding:8px 14px;border-radius:8px;text-decoration:none;font-size:13px;font-weight:600;border:1px solid rgba(67,142,255,.2);transition:all .2s">\ud83d\udcf1 Multimedia</a>
        <a href="#guida" style="background:rgba(67,142,255,.1);color:var(--accent);padding:8px 14px;border-radius:8px;text-decoration:none;font-size:13px;font-weight:600;border:1px solid rgba(67,142,255,.2);transition:all .2s">\ud83d\ude97 Guida</a>
        <a href="#ruote" style="background:rgba(67,142,255,.1);color:var(--accent);padding:8px 14px;border-radius:8px;text-decoration:none;font-size:13px;font-weight:600;border:1px solid rgba(67,142,255,.2);transition:all .2s">\ud83d\udede Ruote</a>
        <a href="#sicurezza" style="background:rgba(67,142,255,.1);color:var(--accent);padding:8px 14px;border-radius:8px;text-decoration:none;font-size:13px;font-weight:600;border:1px solid rgba(67,142,255,.2);transition:all .2s">\ud83d\udd12 Sicurezza</a>
      </div>
    </nav>

    <div class="section">
      <div class="section-title" id="performance">\ud83c\udfc1 M Performance</div>
      <div class="opts">
        <div class="opt"><span class="opt-code">S710</span><span class="opt-name">Volante M in pelle</span></div>
        <div class="opt"><span class="opt-code">S715</span><span class="opt-name">Pacchetto aerodinamico M</span></div>
        <div class="opt"><span class="opt-code">S2NH</span><span class="opt-name">Freni M Sport</span></div>
        <div class="opt"><span class="opt-code">S2T4</span><span class="opt-name">Differenziale M Sport</span></div>
        <div class="opt"><span class="opt-code">S2TB</span><span class="opt-name">Cambio automatico sportivo</span></div>
        <div class="opt"><span class="opt-code">S2VF</span><span class="opt-name">Assetto M adattivo</span></div>
        <div class="opt"><span class="opt-code">S2VG</span><span class="opt-name">Performance Control</span></div>
        <div class="opt"><span class="opt-code">S2VL</span><span class="opt-name">Sterzo sportivo variabile</span></div>
      </div>
    </div>

    <div class="section">
      <div class="section-title" id="comfort">\ud83d\udecb\ufe0f Comfort e interni</div>
      <div class="opts">
        <div class="opt"><span class="opt-code">S402</span><span class="opt-name">Tetto panoramico in vetro</span></div>
        <div class="opt"><span class="opt-code">S413</span><span class="opt-name">Rete vano bagagli</span></div>
        <div class="opt"><span class="opt-code">S423</span><span class="opt-name">Tappetini in velour</span></div>
        <div class="opt"><span class="opt-code">S430</span><span class="opt-name">Specchietti auto-oscuranti</span></div>
        <div class="opt"><span class="opt-code">S441</span><span class="opt-name">Pacchetto fumatori</span></div>
        <div class="opt"><span class="opt-code">S459</span><span class="opt-name">Sedili elettrici con memoria</span></div>
        <div class="opt"><span class="opt-code">S461</span><span class="opt-name">Schienale elettrico posteriore</span></div>
        <div class="opt"><span class="opt-code">S481</span><span class="opt-name">Sedili sportivi</span></div>
        <div class="opt"><span class="opt-code">S488</span><span class="opt-name">Supporto lombare guidatore/passeggero</span></div>
        <div class="opt"><span class="opt-code">S493</span><span class="opt-name">Pacchetto vani portaoggetti</span></div>
        <div class="opt"><span class="opt-code">S494</span><span class="opt-name">Sedili riscaldati ant.</span></div>
        <div class="opt"><span class="opt-code">S4AW</span><span class="opt-name">Plancia Sensatec</span></div>
        <div class="opt"><span class="opt-code">S4K7</span><span class="opt-name">Finiture alluminio romboidale</span></div>
        <div class="opt"><span class="opt-code">S4U0</span><span class="opt-name">Cover cromate elementi di comando</span></div>
        <div class="opt"><span class="opt-code">S4UR</span><span class="opt-name">Illuminazione ambient</span></div>
        <div class="opt"><span class="opt-code">S248</span><span class="opt-name">Volante riscaldato</span></div>
        <div class="opt"><span class="opt-code">S322</span><span class="opt-name">Comfort Access</span></div>
        <div class="opt"><span class="opt-code">S534</span><span class="opt-name">Climatizzatore automatico</span></div>
        <div class="opt"><span class="opt-code">S3KA</span><span class="opt-name">Vetri acustici comfort</span></div>
      </div>
    </div>

    <div class="section">
      <div class="section-title" id="multimedia">\ud83d\udcf1 Multimedia e connettivit\u00e0</div>
      <div class="opts">
        <div class="opt"><span class="opt-code">S6C4</span><span class="opt-name">Connected Package Professional</span></div>
        <div class="opt"><span class="opt-code">S6U3</span><span class="opt-name">BMW Live Cockpit Professional</span></div>
        <div class="opt"><span class="opt-code">S654</span><span class="opt-name">Sintonizzatore DAB</span></div>
        <div class="opt"><span class="opt-code">S676</span><span class="opt-name">Sistema audio HiFi</span></div>
        <div class="opt"><span class="opt-code">S6AC</span><span class="opt-name">Chiamata emergenza intelligente</span></div>
        <div class="opt"><span class="opt-code">S6AE</span><span class="opt-name">Teleservices</span></div>
        <div class="opt"><span class="opt-code">S6AK</span><span class="opt-name">Connected Drive Services</span></div>
        <div class="opt"><span class="opt-code">S6NW</span><span class="opt-name">Telefonia con ricarica wireless</span></div>
        <div class="opt"><span class="opt-code">S6UH</span><span class="opt-name">Informazioni traffico in tempo reale</span></div>
        <div class="opt"><span class="opt-code">S6WD</span><span class="opt-name">Hotspot WLAN</span></div>
      </div>
    </div>

    <div class="section">
      <div class="section-title" id="guida">\ud83d\ude97 Assistenza alla guida e illuminazione</div>
      <div class="opts">
        <div class="opt"><span class="opt-code">S552</span><span class="opt-name">Fari LED adattivi</span></div>
        <div class="opt"><span class="opt-code">S5A1</span><span class="opt-name">Fendinebbia LED</span></div>
        <div class="opt"><span class="opt-code">S5AC</span><span class="opt-name">Assistente abbaglianti</span></div>
        <div class="opt"><span class="opt-code">S5AS</span><span class="opt-name">Driving Assistant</span></div>
        <div class="opt"><span class="opt-code">S5DM</span><span class="opt-name">Assistente al parcheggio</span></div>
        <div class="opt"><span class="opt-code">S5DA</span><span class="opt-name">Disattivazione airbag passeggero</span></div>
        <div class="opt"><span class="opt-code">S8TF</span><span class="opt-name">Protezione attiva pedoni</span></div>
      </div>
    </div>

    <div class="section">
      <div class="section-title" id="ruote">\ud83d\udede Ruote e pneumatici</div>
      <div class="opts">
        <div class="opt"><span class="opt-code">S22Z</span><span class="opt-name">Cerchi 21\" doppia razze 718M (mix)</span></div>
        <div class="opt"><span class="opt-code">S258</span><span class="opt-name">Pneumatici runflat</span></div>
        <div class="opt"><span class="opt-code">S2PA</span><span class="opt-name">Bulloni antifurto</span></div>
        <div class="opt"><span class="opt-code">S2VB</span><span class="opt-name">Display pressione pneumatici</span></div>
      </div>
    </div>

    <div class="section">
      <div class="section-title" id="sicurezza">\ud83d\udd12 Sicurezza e aspetto</div>
      <div class="opts">
        <div class="opt"><span class="opt-code">S302</span><span class="opt-name">Sistema di allarme</span></div>
        <div class="opt"><span class="opt-code">S760</span><span class="opt-name">Shadow Line lucida</span></div>
        <div class="opt"><span class="opt-code">S775</span><span class="opt-name">Rivestimento tetto antracite</span></div>
        <div class="opt"><span class="opt-code">S3MC</span><span class="opt-name">Barre tetto M Shadow Line</span></div>
        <div class="opt"><span class="opt-code">S9AA</span><span class="opt-name">Protezione carrozzeria esterna</span></div>
        <div class="opt"><span class="opt-code">S1AG</span><span class="opt-name">Serbatoio maggiorato</span></div>
        <div class="opt"><span class="opt-code">S548</span><span class="opt-name">Tachimetro in km</span></div>
        <div class="opt"><span class="opt-code">S855</span><span class="opt-name">Lingua italiana</span></div>
      </div>
    </div>

    <div style="text-align:center;padding:32px 0;color:var(--muted);font-size:12px">
      Dati estratti da mdecoder.com \u00b7 VIN WBATX9••••••62133
    </div>
  </main>
</body>
</html>`;
  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'public, max-age=3600' }
  });
}


async function serveTripsData(env, cors) {
  const db = env.DB;
  const rows = await db.prepare(
    `SELECT snapshot_date, mileage_km, mileage_start_km, daily_distance_km, fuel_percent, fuel_litres, range_km 
     FROM bmw_daily WHERE mileage_km IS NOT NULL ORDER BY snapshot_date DESC LIMIT 90`
  ).all();
  
  // Also get GPS data from bmw_cardata_raw if available
  const gpsRows = await db.prepare(
    `SELECT c_timestamp, latitude, longitude FROM bmw_cardata_raw 
     WHERE latitude IS NOT NULL ORDER BY c_timestamp DESC LIMIT 200`
  ).all();
  
  return new Response(JSON.stringify({
    trips: rows.results,
    gps: gpsRows.results
  }), { headers: { ...cors, 'Content-Type': 'application/json' } });
}


function serveTrips() {
  const html = `<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>BMW X3 M40d \u00b7 Viaggi</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><\/script>
  <style>
    :root{--bg:#0a1726;--card:#111d2e;--text:#e4ecf5;--muted:#7b93a8;--accent:#438eff;--line:rgba(39,71,102,.4);--green:#2ea55c;--amber:#f5a623;--red:#e05252}
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
    .topbar{position:sticky;top:0;z-index:100;backdrop-filter:blur(18px);background:rgba(10,23,38,.85);padding:16px 24px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}
    .topbar a{color:var(--accent);text-decoration:none;font-size:14px;display:flex;align-items:center;gap:6px}
    .topbar h1{font-size:18px;font-weight:700}
    .shell{max-width:1200px;margin:0 auto;padding:24px 20px}
    #mapTrips{height:300px;border-radius:14px;margin-bottom:24px;border:1px solid var(--line)}
    .stats-row{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
    .stat-card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 18px;flex:1;min-width:120px}
    .stat-card small{color:var(--muted);font-size:11px;display:block;margin-bottom:4px}
    .stat-card strong{font-size:20px;font-weight:800}
    .stat-card .sub{font-size:11px;color:var(--muted);margin-top:2px}
    table{width:100%;border-collapse:collapse;font-size:13px}
    thead{position:sticky;top:56px;background:var(--bg);z-index:10}
    th{text-align:left;padding:8px 10px;color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid var(--line)}
    td{padding:8px 10px;border-bottom:1px solid var(--line)}
    tr:hover{background:rgba(67,142,255,.06)}
    tr.refuel-row{background:rgba(46,165,92,.08)}
    tr.refuel-row:hover{background:rgba(46,165,92,.14)}
    .km-bar{display:inline-block;height:6px;border-radius:3px;background:var(--accent);vertical-align:middle;min-width:2px}
    .fuel-badge{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:700}
    .fuel-green{background:rgba(46,165,92,.15);color:#69e1b2}
    .fuel-amber{background:rgba(245,166,35,.15);color:#f5c56a}
    .fuel-red{background:rgba(224,82,82,.15);color:#f08080}
    .refuel-badge{display:inline-flex;align-items:center;gap:4px;background:rgba(46,165,92,.18);color:#69e1b2;padding:3px 10px;border-radius:8px;font-size:12px;font-weight:700}
    .no-trip{color:var(--muted);font-style:italic}
    .loading{text-align:center;padding:40px;color:var(--muted)}
    .refuel-section{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 22px;margin-bottom:24px}
    .refuel-section h3{font-size:14px;font-weight:700;margin-bottom:12px;color:var(--green)}
    .refuel-list{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px}
    .refuel-item{background:rgba(46,165,92,.08);border:1px solid rgba(46,165,92,.2);border-radius:10px;padding:10px 14px}
    .refuel-item .date{font-weight:700;font-size:13px}
    .refuel-item .detail{font-size:12px;color:var(--muted);margin-top:4px}
    @media(max-width:700px){.stats-row{flex-direction:column}th,td{padding:6px 4px;font-size:11px}.refuel-list{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <header class="topbar">
    <a href="/">\u2190 Dashboard</a>
    <h1>\ud83d\uddfa\ufe0f Viaggi e Rifornimenti</h1>
    <span style="width:80px"></span>
  </header>
  <main class="shell">
    <div id="mapTrips"></div>
    <div class="stats-row">
      <div class="stat-card"><small>Periodo</small><strong id="statPeriod">\u2014</strong></div>
      <div class="stat-card"><small>Km totali</small><strong id="statKm">\u2014</strong></div>
      <div class="stat-card"><small>Giorni guida</small><strong id="statDays">\u2014</strong></div>
      <div class="stat-card"><small>Media km/giorno</small><strong id="statAvg">\u2014</strong></div>
      <div class="stat-card"><small>Consumo medio</small><strong id="statConsumption">\u2014</strong><div class="sub" id="statConsumptionSub"></div></div>
      <div class="stat-card"><small>Rifornimenti</small><strong id="statRefuels">\u2014</strong><div class="sub" id="statRefuelSub"></div></div>
    </div>
    <div id="refuelSection" class="refuel-section" style="display:none">
      <h3>\u26fd Storico rifornimenti</h3>
      <div class="refuel-list" id="refuelList"></div>
    </div>
    <div class="loading" id="loading">Caricamento viaggi...</div>
    <table style="display:none" id="tripsTable">
      <thead>
        <tr><th>Data</th><th>Km</th><th></th><th>Carburante</th><th>L consumati</th><th>Consumo</th><th>Km da riforn.</th><th>Note</th></tr>
      </thead>
      <tbody id="tripsBody"></tbody>
    </table>
  </main>
  <script>
    var map = L.map('mapTrips',{zoomControl:true,attributionControl:false}).setView([39.36,9.01],10);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{maxZoom:19}).addTo(map);

    fetch('/api/trips').then(function(r){return r.json()}).then(function(data){
      var trips = data.trips || [];
      if (!trips.length) { document.getElementById('loading').textContent='Nessun dato'; return; }
      
      trips.reverse(); // oldest first
      
      // === FUEL & REFUEL CALCULATIONS ===
      var totalKm=0, activeDays=0, maxKm=0;
      var totalLitresUsed=0, totalKmWithFuel=0;
      var refuels=[];
      var lastRefuelKm = trips[0].mileage_km || 0;
      var lastRefuelDate = trips[0].snapshot_date;
      
      trips.forEach(function(t, i){
        var km = t.daily_distance_km || 0;
        totalKm += km;
        if(km > 0) activeDays++;
        if(km > maxKm) maxKm = km;
        
        t._litresUsed = null;
        t._consumption = null;
        t._refuel = false;
        t._refuelAmount = 0;
        t._kmSinceRefuel = (t.mileage_km || 0) - lastRefuelKm;
        
        if (i === 0) return;
        var prev = trips[i-1];
        
        // Fuel delta (both must have fuel data)
        if (t.fuel_litres !== null && t.fuel_litres !== undefined && 
            prev.fuel_litres !== null && prev.fuel_litres !== undefined) {
          var delta = prev.fuel_litres - t.fuel_litres; // positive = consumed
          
          if (delta < -3) { // fuel went up by >3L = refuel detected
            t._refuel = true;
            t._refuelAmount = Math.round(Math.abs(delta));
            var kmSinceLastRefuel = (t.mileage_km || 0) - lastRefuelKm;
            refuels.push({
              date: t.snapshot_date,
              litres: t._refuelAmount,
              fuelAfter: t.fuel_litres,
              fuelPct: t.fuel_percent,
              kmSince: kmSinceLastRefuel,
              kmAt: t.mileage_km
            });
            lastRefuelKm = t.mileage_start_km || t.mileage_km;
            lastRefuelDate = t.snapshot_date;
            t._kmSinceRefuel = 0;
          } else if (delta > 0) {
            t._litresUsed = Math.round(delta * 10) / 10;
            totalLitresUsed += delta;
            totalKmWithFuel += km;
          }
        }
        
        // Consumption L/100km
        if (km > 0 && t._litresUsed > 0) {
          t._consumption = (t._litresUsed / km * 100).toFixed(1);
        }
      });
      
      // === STATS ===
      var months=['gen','feb','mar','apr','mag','giu','lug','ago','set','ott','nov','dic'];
      
      document.getElementById('statPeriod').textContent = trips[0].snapshot_date.substring(5) + ' \u2192 ' + trips[trips.length-1].snapshot_date.substring(5);
      document.getElementById('statKm').textContent = totalKm.toLocaleString('it') + ' km';
      document.getElementById('statDays').textContent = activeDays + '/' + trips.length;
      document.getElementById('statAvg').textContent = activeDays > 0 ? Math.round(totalKm/activeDays) + ' km' : '\u2014';
      
      var avgConsumption = totalLitresUsed > 0 ? (totalKmWithFuel / totalLitresUsed).toFixed(1) : null;
      document.getElementById('statConsumption').textContent = avgConsumption ? avgConsumption + ' km/L' : '\u2014';
      document.getElementById('statConsumptionSub').textContent = totalLitresUsed > 0 ? Math.round(totalLitresUsed) + 'L su ' + Math.round(totalKmWithFuel) + ' km' : '';
      
      document.getElementById('statRefuels').textContent = refuels.length;
      if (refuels.length > 0) {
        var avgKmBetween = Math.round(refuels.reduce(function(s,r){return s+r.kmSince},0) / refuels.length);
        document.getElementById('statRefuelSub').textContent = 'ogni ~' + avgKmBetween + ' km';
      }
      
      // === REFUEL CARDS ===
      if (refuels.length > 0) {
        document.getElementById('refuelSection').style.display = 'block';
        var rl = document.getElementById('refuelList');
        refuels.forEach(function(r){
          var d = new Date(r.date + 'T12:00:00');
          var dateStr = d.getDate() + ' ' + months[d.getMonth()] + ' ' + d.getFullYear();
          var div = document.createElement('div');
          div.className = 'refuel-item';
          div.innerHTML = '<div class="date">\u26fd ' + dateStr + '</div>' +
            '<div class="detail">+' + r.litres + 'L \u2192 ' + r.fuelAfter + 'L (' + (r.fuelPct||'?') + '%)</div>' +
            '<div class="detail">' + r.kmSince.toLocaleString('it') + ' km dal precedente \u00b7 a ' + (r.kmAt||0).toLocaleString('it') + ' km</div>';
          rl.appendChild(div);
        });
      }
      
      // === TABLE ===
      var tbody = document.getElementById('tripsBody');
      trips.forEach(function(t){
        var km = t.daily_distance_km || 0;
        var d = new Date(t.snapshot_date + 'T12:00:00');
        var dateStr = d.getDate() + ' ' + months[d.getMonth()] + ' ' + d.getFullYear();
        var dayName = d.toLocaleDateString('it-IT',{weekday:'short'});
        var barW = maxKm > 0 ? Math.round((km/maxKm)*100) : 0;
        
        // Fuel display
        var fuelStr = '\u2014';
        if (t.fuel_percent !== null && t.fuel_percent !== undefined) {
          fuelStr = t.fuel_percent + '% (' + (t.fuel_litres||'?') + 'L)';
        }
        
        // Litres used
        var litresStr = '\u2014';
        if (t._litresUsed !== null) litresStr = t._litresUsed.toFixed(1) + ' L';
        
        // Consumption with color
        var consStr = '\u2014';
        if (t._consumption !== null) {
          var c = parseFloat(t._consumption);
          var cls = c > 12 ? 'fuel-red' : c > 9 ? 'fuel-amber' : 'fuel-green';
          var kmL = Number(t._consumption)>0 ? (100/Number(t._consumption)).toFixed(1) : null;
          consStr = kmL ? '<span class="fuel-badge ' + cls + '">' + kmL + ' km/L</span>' : '—';
        }
        
        // Km since refuel
        var kmRefuelStr = t._kmSinceRefuel > 0 ? t._kmSinceRefuel.toLocaleString('it') + ' km' : '\u2014';
        
        // Note
        var noteStr = '';
        if (t._refuel) {
          noteStr = '<span class="refuel-badge">\u26fd +' + t._refuelAmount + 'L</span>';
        } else if (km === 0) {
          noteStr = '<span style="color:var(--muted);font-size:11px">Fermo</span>';
        }
        
        var tr = document.createElement('tr');
        if (t._refuel) tr.className = 'refuel-row';
        tr.innerHTML = '<td><strong>' + dateStr + '</strong><br><span style="color:var(--muted);font-size:11px">' + dayName + '</span></td>'
          + '<td>' + (km > 0 ? '<strong>' + km + '</strong>' : '<span class="no-trip">0</span>') + '</td>'
          + '<td><span class="km-bar" style="width:' + barW + 'px"></span></td>'
          + '<td>' + fuelStr + '</td>'
          + '<td>' + litresStr + '</td>'
          + '<td>' + consStr + '</td>'
          + '<td>' + kmRefuelStr + '</td>'
          + '<td>' + noteStr + '</td>';
        tbody.appendChild(tr);
      });
      
      document.getElementById('loading').style.display='none';
      document.getElementById('tripsTable').style.display='table';
      
      // === MAP ===
      if (data.gps && data.gps.length) {
        var points = [];
        data.gps.forEach(function(g){
          if(g.latitude && g.longitude) points.push([g.latitude, g.longitude]);
        });
        if (points.length) {
          L.polyline(points, {color:'#438eff',weight:3,opacity:0.7}).addTo(map);
          points.forEach(function(p,i){
            if(i===0 || i===points.length-1) L.circleMarker(p,{radius:6,color:'#438eff',fillColor:'#69e1b2',fillOpacity:1}).addTo(map);
          });
          map.fitBounds(L.latLngBounds(points).pad(0.1));
        }
      }
      setTimeout(function(){map.invalidateSize()},200);
    }).catch(function(e){
      document.getElementById('loading').textContent='Errore: '+e.message;
    });
  <\/script>
</body>
</html>`;
  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'public, max-age=300' }
  });
}



async function serveFuelData(env, cors) {
  const db = env.DB;
  const daily = await db.prepare(
    'SELECT snapshot_date, mileage_km, mileage_start_km, daily_distance_km, fuel_percent, fuel_litres, range_km, refuel_litres, refuel_cost_eur, diesel_price_eur FROM bmw_daily ORDER BY snapshot_date ASC'
  ).all();
  const prices = await db.prepare('SELECT date, price_eur, source FROM diesel_prices ORDER BY date DESC LIMIT 90').all();
  const latestPrice = prices.results.length > 0 ? prices.results[0] : { date: DIESEL_PRICE_DATE, price_eur: DIESEL_PRICE_EUR };
  return new Response(JSON.stringify({ 
    daily: daily.results, 
    prices: prices.results, 
    dieselPrice: latestPrice.price_eur, 
    dieselPriceDate: latestPrice.date,
    dieselPriceSource: latestPrice.source || 'default'
  }), {
    headers: { ...cors, 'Content-Type': 'application/json' }
  });
}


function serveFuel() {
  const html = `<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>BMW X3 M40d \u00b7 Carburante</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"><\/script>
  <style>
    :root{--bg:#0a1726;--card:#111d2e;--text:#e4ecf5;--muted:#7b93a8;--accent:#438eff;--line:rgba(39,71,102,.4);--green:#2ea55c;--amber:#e5a50a;--red:#e54545}
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
    .topbar{position:sticky;top:0;z-index:100;backdrop-filter:blur(18px);background:rgba(10,23,38,.85);padding:16px 24px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}
    .topbar a{color:var(--accent);text-decoration:none;font-size:14px}
    .topbar h1{font-size:18px;font-weight:700}
    .shell{max-width:1100px;margin:0 auto;padding:24px 20px}
    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:24px}
    .stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
    .stat small{color:var(--muted);font-size:12px;display:block;margin-bottom:4px}
    .stat strong{font-size:24px;font-weight:800}
    .stat .sub{color:var(--muted);font-size:11px;margin-top:4px}
    .chart-card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px;margin-bottom:20px}
    .chart-card h3{font-size:14px;font-weight:700;color:var(--muted);margin-bottom:14px;text-transform:uppercase;letter-spacing:.5px}
    .chart-holder{position:relative;height:220px}
    .notice{background:rgba(67,142,255,.08);border:1px solid rgba(67,142,255,.2);border-radius:12px;padding:16px 20px;margin-bottom:24px;color:var(--muted);font-size:13px;line-height:1.6}
    table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}
    th{text-align:left;padding:8px 10px;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid var(--line)}
    td{padding:8px 10px;border-bottom:1px solid var(--line)}
    tr:hover{background:rgba(67,142,255,.05)}
    .refuel-row{background:rgba(46,165,92,.08)}
    .badge-green{color:var(--green);font-weight:700}
    .badge-yellow{color:var(--amber);font-weight:700}
    .badge-red{color:var(--red);font-weight:700}
    .empty{text-align:center;padding:30px;color:var(--muted);font-style:italic}
    @media(max-width:600px){.stats{grid-template-columns:1fr 1fr}.chart-holder{height:180px}}
  </style>
</head>
<body>
  <header class="topbar">
    <a href="/">\u2190 Dashboard</a>
    <h1>\u26fd Carburante</h1>
    <span style="width:80px"></span>
  </header>
  <main class="shell">
    <div id="notice" class="notice" style="display:none"></div>
    <div class="stats">
      <div class="stat"><small>Consumo medio</small><strong id="sAvg">\u2014</strong><div class="sub">km/L</div></div>
      <div class="stat"><small>Litri consumati</small><strong id="sLitres">\u2014</strong><div class="sub">totale periodo</div></div>
      <div class="stat"><small>Km per litro</small><strong id="sKmL">\u2014</strong><div class="sub">efficienza</div></div>
      <div class="stat"><small>Rifornimenti</small><strong id="sRefuels">\u2014</strong><div class="sub" id="sRefuelCost"></div></div>
    </div>
    <div class="chart-card">
      <h3>Consumo giornaliero (km/L)</h3>
      <div class="chart-holder"><canvas id="chartConsumption"></canvas></div>
    </div>
    <div class="chart-card">
      <h3>Livello serbatoio (%)</h3>
      <div class="chart-holder"><canvas id="chartFuelLevel"></canvas></div>
    </div>
    <div class="chart-card">
      <h3>\u26fd Rifornimenti</h3>
      <div id="refuelTable"></div>
    </div>
    <div class="chart-card" style="border:1px solid rgba(67,142,255,.2);background:linear-gradient(135deg,rgba(17,29,46,.95),rgba(10,23,38,.98))">
      <h3 style="display:flex;align-items:center;gap:8px">
        <span style="font-size:1.3rem">\u26fd</span> Prezzi Gasolio nella tua zona
      </h3>
      <p style="color:var(--muted);margin:.5rem 0 1rem;line-height:1.6;font-size:.9rem">Confronta i prezzi dei distributori vicino a casa tua con i dati MIMIT aggiornati quotidianamente.</p>
      <a href="https://carburanti.samuelecorona.it?lat=39.3627&lng=9.0098&fuel=Gasolio&from=bmw" target="_blank" rel="noopener" style="display:inline-block;background:linear-gradient(135deg,#1d4ed8,#2563eb);color:#fff;padding:.75rem 1.5rem;border-radius:10px;text-decoration:none;font-weight:600;font-size:.9rem;transition:transform .2s,box-shadow .2s;box-shadow:0 4px 15px rgba(37,99,235,.3)">Confronta prezzi zona \u2192</a>
    </div>
    <div class="chart-card">
      <h3>Dettaglio giornaliero</h3>
      <div id="dailyTable"></div>
    </div>
  </main>
  <script>
  var DIESEL_PRICE = 1.75;
  fetch('/api/fuel').then(function(r){return r.json()}).then(function(data){
    var daily = data.daily || [];
    if (!daily.length) { document.getElementById('notice').textContent='Nessun dato disponibile'; document.getElementById('notice').style.display='block'; return; }

    var prevFuel=null, totalL=0, totalKmF=0, refuels=[], cPoints=[], fuelLevels=[], details=[];
    var months=['gen','feb','mar','apr','mag','giu','lug','ago','set','ott','nov','dic'];

    daily.forEach(function(d,i){
      var km=d.daily_distance_km||0, fuel=d.fuel_litres, pct=d.fuel_percent;
      var detail={date:d.snapshot_date, km:km, fuelStart:prevFuel, fuelEnd:fuel, pct:pct, consumption:null, refuel:false, refuelAmt:0};

      if(pct!==null) fuelLevels.push({date:d.snapshot_date, value:pct});

      if(fuel!==null && prevFuel!==null){
        var delta=prevFuel-fuel;
        if(delta<-3){
          detail.refuel=true; detail.refuelAmt=Math.abs(delta);
          refuels.push({date:d.snapshot_date, added:Math.abs(delta), after:fuel, pctAfter:pct, km:d.mileage_km});
        } else if(delta>0 && km>0){
          var l100=(delta/km)*100;
          if(l100>0 && l100<30){
            cPoints.push({date:d.snapshot_date, value:Math.round(l100*10)/10, km:km, litres:Math.round(delta*10)/10});
            detail.consumption=Math.round(l100*10)/10;
            totalL+=delta; totalKmF+=km;
          }
        }
      }
      details.push(detail);
      prevFuel=fuel;
    });

    var fuelDays=cPoints.length;
    if(fuelDays<3){
      var n=document.getElementById('notice');
      n.innerHTML='\ud83d\udcca <strong>In raccolta dati</strong> \u2014 '+fuelDays+' intervall'+(fuelDays===1?'o':'i')+' con dati carburante. Il consumo diventer\u00e0 pi\u00f9 preciso con pi\u00f9 giorni di monitoraggio.';
      n.style.display='block';
    }

    // Stats
    var avgKmL=totalL>0?Math.round(totalKmF/totalL*10)/10:null;
    document.getElementById('sAvg').textContent=avgKmL!==null?avgKmL.toFixed(1):'\u2014';
    document.getElementById('sLitres').textContent=totalL>0?Math.round(totalL)+' L':'\u2014';
    document.getElementById('sKmL').textContent=totalL>0?(totalKmF/totalL).toFixed(1):'\u2014';
    document.getElementById('sRefuels').textContent=refuels.length;
    var totalRefuelL=0; refuels.forEach(function(r){totalRefuelL+=r.added});
    document.getElementById('sRefuelCost').textContent=totalRefuelL>0?'\u20ac '+(totalRefuelL*DIESEL_PRICE).toFixed(0)+' stimati':'';

    // Chart 1: Consumption bars
    if(cPoints.length>0){
      var ctx1=document.getElementById('chartConsumption').getContext('2d');
      new Chart(ctx1,{type:'bar',data:{
        labels:cPoints.map(function(p){var d=new Date(p.date+'T12:00:00');return d.getDate()+' '+months[d.getMonth()]}),
        datasets:[{label:'km/L',data:cPoints.map(function(p){return p.value>0?Math.round((100/p.value)*10)/10:null}),
          backgroundColor:cPoints.map(function(p){return p.value<9?'rgba(46,165,92,.8)':p.value<12?'rgba(229,165,10,.8)':'rgba(229,69,69,.8)'}),
          borderRadius:5}]
      },options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{
        x:{ticks:{color:'#7b93a8',font:{size:11}},grid:{display:false}},
        y:{ticks:{color:'#7b93a8'},grid:{color:'rgba(39,71,102,.3)'},beginAtZero:true}
      }}});
    }

    // Chart 2: Fuel level area
    if(fuelLevels.length>0){
      var ctx2=document.getElementById('chartFuelLevel').getContext('2d');
      var gradient=ctx2.createLinearGradient(0,0,0,220);
      gradient.addColorStop(0,'rgba(67,142,255,.4)');gradient.addColorStop(1,'rgba(67,142,255,.02)');
      new Chart(ctx2,{type:'line',data:{
        labels:fuelLevels.map(function(p){var d=new Date(p.date+'T12:00:00');return d.getDate()+' '+months[d.getMonth()]}),
        datasets:[{label:'%',data:fuelLevels.map(function(p){return p.value}),
          borderColor:'#438eff',backgroundColor:gradient,fill:true,tension:.3,pointRadius:3,pointBackgroundColor:'#438eff'}]
      },options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{
        x:{ticks:{color:'#7b93a8',font:{size:11}},grid:{display:false}},
        y:{ticks:{color:'#7b93a8',callback:function(v){return v+'%'}},grid:{color:'rgba(39,71,102,.3)'},min:0,max:100}
      }}});
    }

    // Refuel table
    var rt=document.getElementById('refuelTable');
    if(refuels.length>0){
      var h='<table><thead><tr><th>Data</th><th>Litri aggiunti</th><th>Livello dopo</th><th>Costo stimato</th></tr></thead><tbody>';
      refuels.forEach(function(r){
        var d=new Date(r.date+'T12:00:00');
        var ds=d.getDate()+' '+months[d.getMonth()]+' '+d.getFullYear();
        h+='<tr class="refuel-row"><td><strong>'+ds+'</strong></td><td class="badge-green">+'+Math.round(r.added)+' L</td><td>'+Math.round(r.after)+' L ('+r.pctAfter+'%)</td><td>\u20ac '+(r.added*DIESEL_PRICE).toFixed(2)+'</td></tr>';
      });
      h+='</tbody></table>';
      rt.innerHTML=h;
    } else { rt.innerHTML='<div class="empty">Nessun rifornimento rilevato</div>'; }

    // Daily detail table
    var dt=document.getElementById('dailyTable');
    var daysWithFuel=details.filter(function(d){return d.fuelEnd!==null});
    if(daysWithFuel.length>0){
      var h2='<table><thead><tr><th>Data</th><th>Km</th><th>Litri inizio</th><th>Litri fine</th><th>Consumo</th><th>Note</th></tr></thead><tbody>';
      daysWithFuel.reverse().forEach(function(d){
        var dt2=new Date(d.date+'T12:00:00');
        var ds=dt2.getDate()+' '+months[dt2.getMonth()];
        var cons=d.consumption?('<span class="badge-'+(d.consumption<9?'green':d.consumption<12?'yellow':'red')+'">'+d.consumption+'</span>'):'\u2014';
        var note=d.refuel?'\u26fd +'+Math.round(d.refuelAmt)+'L':'';
        h2+='<tr'+(d.refuel?' class="refuel-row"':'')+'><td>'+ds+'</td><td>'+(d.km||0)+' km</td><td>'+(d.fuelStart!==null?Math.round(d.fuelStart)+'L':'\u2014')+'</td><td>'+(d.fuelEnd!==null?Math.round(d.fuelEnd)+'L':'\u2014')+'</td><td>'+cons+'</td><td>'+note+'</td></tr>';
      });
      h2+='</tbody></table>';
      dt.innerHTML=h2;
    } else { dt.innerHTML='<div class="empty">In attesa di dati carburante giornalieri</div>'; }

  }).catch(function(e){
    document.getElementById('notice').textContent='Errore: '+e.message;
    document.getElementById('notice').style.display='block';
  });
  <\/script>
</body>
</html>`;
  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=utf-8', 'Cache-Control': 'public, max-age=300' }
  });
}


// === Price management ===
async function servePrices(env, cors) {
  const rows = await env.DB.prepare('SELECT date, price_eur, source FROM diesel_prices ORDER BY date DESC LIMIT 90').all();
  return new Response(JSON.stringify({ prices: rows.results }), {
    headers: { ...cors, 'Content-Type': 'application/json' }
  });
}

async function updatePrice(request, env, cors) {
  const body = await request.json();
  const price = parseFloat(body.price);
  const date = body.date || new Date().toISOString().substring(0, 10);
  if (!price || isNaN(price) || price < 0.5 || price > 5) {
    return new Response(JSON.stringify({ error: 'Invalid price (0.5-5.0)' }), { status: 400, headers: { ...cors, 'Content-Type': 'application/json' } });
  }
  await env.DB.prepare('INSERT OR REPLACE INTO diesel_prices (date, price_eur, source) VALUES (?, ?, ?)').bind(date, price, body.source || 'manual').run();
  return new Response(JSON.stringify({ status: 'ok', date, price_eur: price }), {
    headers: { ...cors, 'Content-Type': 'application/json' }
  });
}

// === History (Cronologia) ===
async function serveHistoryData(env, cors, request) {
    const reqUrl = new URL(request.url);
    const limit = parseInt(reqUrl.searchParams.get('limit') || '50');
    const category = reqUrl.searchParams.get('category') || 'all';
    const db = env.DB;
    
    const categoryFilters = {
        'doors': "entity_id LIKE '%door%' OR entity_id LIKE '%lock%' OR entity_id LIKE '%secur%'",
        'windows': "entity_id LIKE '%window%' OR entity_id LIKE '%sunroof%'",
        'trunk': "entity_id LIKE '%trunk%' OR entity_id LIKE '%hood%' OR entity_id LIKE '%tailgate%'",
        'fuel': "entity_id LIKE '%fuel%' OR entity_id LIKE '%tank%' OR entity_id LIKE '%range%' OR entity_id LIKE '%remaining%'",
        'gps': "entity_id LIKE '%latitude%' OR entity_id LIKE '%longitude%' OR entity_id LIKE '%heading%' OR entity_id LIKE '%altitude%' OR entity_id LIKE '%navigation%'",
        'km': "entity_id LIKE '%mileage%' OR entity_id LIKE '%distance%' OR entity_id LIKE '%travelled%' OR entity_id LIKE '%odometer%'",
        'tyres': "entity_id LIKE '%tire%' OR entity_id LIKE '%tyre%' OR entity_id LIKE '%pressure%'",
        'climate': "entity_id LIKE '%preconditioning%' OR entity_id LIKE '%precond%'"
    };
    
    let sql = 'SELECT snapshot_timestamp, entity_id, state, bmw_timestamp, trigger_reason FROM bmw_raw_daily';
    if (category !== 'all' && categoryFilters[category]) {
        sql += ' WHERE (' + categoryFilters[category] + ')';
    }
    sql += ' ORDER BY snapshot_timestamp DESC LIMIT ' + Math.min(limit * 3, 1500);
    
    const rows = await db.prepare(sql).all();
    
    // Smart dedup: skip consecutive identical states per entity
    const deduped = [];
    const lastState = {};
    for (const row of rows.results) {
        const key = row.entity_id;
        let stateVal = row.state;
        // GPS: round to 4 decimals before comparing
        if (key.includes('latitude') || key.includes('longitude')) {
            stateVal = parseFloat(stateVal).toFixed(4);
        }
        if (lastState[key] === stateVal) continue;
        lastState[key] = stateVal;
        deduped.push(row);
        if (deduped.length >= limit) break;
    }
    
    return new Response(JSON.stringify({ events: deduped, count: deduped.length, total_raw: rows.results.length }), {
        headers: { ...cors, 'Content-Type': 'application/json' }
    });
}

function serveHistory() {
  const html = `<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>BMW X3 M40d \u00b7 Cronologia</title>
  <style>
    :root{--bg:#0a1726;--card:#111d2e;--text:#e4ecf5;--muted:#7b93a8;--accent:#438eff;--line:rgba(39,71,102,.4);--green:#2ea55c}
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
    .topbar{position:sticky;top:0;z-index:100;backdrop-filter:blur(18px);background:rgba(10,23,38,.85);padding:16px 24px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}
    .topbar a{color:var(--accent);text-decoration:none;font-size:14px}
    .topbar h1{font-size:18px;font-weight:700}
    .shell{max-width:900px;margin:0 auto;padding:24px 20px}
    .filter-section{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
    .filter-label{color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;width:100%;margin-bottom:2px}
    .pill{padding:6px 14px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--text);cursor:pointer;font-size:12px;transition:all .2s}
    .pill:hover{border-color:var(--accent)}
    .pill.active{background:var(--accent);color:#fff;border-color:var(--accent)}
    .cat-pill{padding:5px 11px;border-radius:7px;border:1px solid var(--line);background:var(--card);color:var(--text);cursor:pointer;font-size:11px;transition:all .2s}
    .cat-pill:hover{border-color:var(--accent)}
    .cat-pill.active{background:rgba(67,142,255,.2);color:var(--accent);border-color:var(--accent)}
    .stats-bar{display:flex;gap:16px;margin-bottom:16px;font-size:12px;color:var(--muted)}
    .event-list{border:1px solid var(--line);border-radius:12px;overflow:hidden}
    .date-sep{padding:10px 16px;background:rgba(67,142,255,.06);font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--line)}
    .ev{display:grid;grid-template-columns:90px 1fr auto;gap:8px;padding:10px 16px;border-bottom:1px solid rgba(39,71,102,.25);align-items:center;font-size:13px;transition:background .15s}
    .ev:hover{background:rgba(67,142,255,.04)}
    .ev.alert{background:rgba(255,87,87,.04)}
    .ev-time{font-family:'SF Mono',monospace;font-size:11px;color:var(--muted)}
    .ev-entity{font-weight:600;font-size:12px}
    .badge-open{display:inline-block;background:rgba(255,87,87,.15);color:#ff5757;padding:2px 8px;border-radius:5px;font-size:11px;font-weight:600}
    .badge-closed{display:inline-block;background:rgba(46,165,92,.15);color:#5cf29c;padding:2px 8px;border-radius:5px;font-size:11px;font-weight:600}
    .badge-val{display:inline-block;background:rgba(67,142,255,.12);color:var(--accent);padding:2px 8px;border-radius:5px;font-size:11px;font-weight:500}
    .loading{text-align:center;padding:40px;color:var(--muted)}
    @media(max-width:600px){.ev{grid-template-columns:70px 1fr auto;padding:8px 10px}.ev-entity{font-size:11px}}
  </style>
</head>
<body>
  <header class="topbar">
    <a href="/">\u2190 Dashboard</a>
    <h1>\ud83d\udcdc Cronologia</h1>
    <span style="width:80px"></span>
  </header>
  <main class="shell">
    <div class="filter-section">
      <div class="filter-label">Quantit\u00e0</div>
      <button class="pill active" data-limit="50" onclick="setLimit(50)">50</button>
      <button class="pill" data-limit="100" onclick="setLimit(100)">100</button>
      <button class="pill" data-limit="150" onclick="setLimit(150)">150</button>
      <button class="pill" data-limit="300" onclick="setLimit(300)">300</button>
    </div>
    <div class="filter-section">
      <div class="filter-label">Categoria</div>
      <button class="cat-pill active" data-cat="all" onclick="setCat('all')">Tutti</button>
      <button class="cat-pill" data-cat="doors" onclick="setCat('doors')">\ud83d\udd12 Serrature</button>
      <button class="cat-pill" data-cat="windows" onclick="setCat('windows')">\ud83e\ude9f Finestrini</button>
      <button class="cat-pill" data-cat="trunk" onclick="setCat('trunk')">\ud83d\ude97 Cofano/Port.</button>
      <button class="cat-pill" data-cat="fuel" onclick="setCat('fuel')">\u26fd Carburante</button>
      <button class="cat-pill" data-cat="gps" onclick="setCat('gps')">\ud83d\udccd GPS</button>
      <button class="cat-pill" data-cat="km" onclick="setCat('km')">\ud83d\udee3\ufe0f Km</button>
      <button class="cat-pill" data-cat="tyres" onclick="setCat('tyres')">\ud83d\udd27 Pneumatici</button>
      <button class="cat-pill" data-cat="climate" onclick="setCat('climate')">\u2744\ufe0f Clima</button>
    </div>
    <div class="stats-bar">
      <span id="statsCount">Caricamento...</span>
      <span id="statsDedup"></span>
    </div>
    <div id="eventList" class="event-list">
      <div class="loading">Caricamento eventi...</div>
    </div>
  </main>
  <script>
    var currentLimit = 50;
    var currentCat = 'all';
    
    function setLimit(n) {
      currentLimit = n;
      document.querySelectorAll('.pill').forEach(function(b){b.classList.toggle('active', parseInt(b.dataset.limit)===n)});
      load();
    }
    function setCat(c) {
      currentCat = c;
      document.querySelectorAll('.cat-pill').forEach(function(b){b.classList.toggle('active', b.dataset.cat===c)});
      load();
    }
    
    var entityNames = {
      'vehicle.cabin.door.status': '\ud83d\udd12 Serratura',
      'vehicle.cabin.door.row1.driver.isOpen': '\ud83d\udeb9 Porta guidatore',
      'vehicle.cabin.door.row1.passenger.isOpen': '\ud83d\udeb9 Porta passeggero',
      'vehicle.cabin.door.row2.driver.isOpen': '\ud83d\udeb9 Porta post. SX',
      'vehicle.cabin.door.row2.passenger.isOpen': '\ud83d\udeb9 Porta post. DX',
      'binary_sensor.x3_m40d_tailgate_door_state': '\ud83d\udeb9 Portellone',
      'binary_sensor.x3_m40d_tailgate_state': '\ud83d\udeb9 Portellone',
      'binary_sensor.x3_m40d_hood_state': '\ud83d\ude97 Cofano',
      'vehicle.body.hood.isOpen': '\ud83d\ude97 Cofano',
      'vehicle.body.trunk.isOpen': '\ud83d\udeb9 Portellone',
      'vehicle.body.trunk.door.isOpen': '\ud83d\udeb9 Sportello bagagliaio',
      'vehicle.cabin.window.row1.driver.status': '\ud83e\ude9f Finestrino ant. SX',
      'vehicle.cabin.window.row1.passenger.status': '\ud83e\ude9f Finestrino ant. DX',
      'vehicle.cabin.window.row2.driver.status': '\ud83e\ude9f Finestrino post. SX',
      'vehicle.cabin.window.row2.passenger.status': '\ud83e\ude9f Finestrino post. DX',
      'vehicle.cabin.sunroof.status': '\u2600\ufe0f Tetto apribile',
      'vehicle.cabin.sunroof.overallStatus': '\u2600\ufe0f Tetto apribile',
      'vehicle.cabin.sunroof.tiltStatus': '\u2600\ufe0f Tetto (tilt)',
      'sensor.x3_m40d_vehicle_mileage': '\ud83d\udee3\ufe0f Chilometraggio',
      'vehicle.vehicle.travelledDistance': '\ud83d\udee3\ufe0f Chilometraggio',
      'sensor.x3_m40d_range_tank_level': '\u26fd Carburante %',
      'sensor.x3_m40d_range_tank_level_2': '\u26fd Carburante L',
      'vehicle.drivetrain.fuelSystem.level': '\u26fd Carburante %',
      'vehicle.drivetrain.fuelSystem.remainingFuel': '\u26fd Carburante L',
      'vehicle.drivetrain.lastRemainingRange': '\ud83d\udee3\ufe0f Autonomia km',
      'sensor.x3_m40d_range_total_range_last_sent': '\ud83d\udee3\ufe0f Autonomia km',
      'vehicle.cabin.infotainment.navigation.currentLocation.latitude': '\ud83d\udccd GPS Lat',
      'vehicle.cabin.infotainment.navigation.currentLocation.longitude': '\ud83d\udccd GPS Lng',
      'vehicle.cabin.infotainment.navigation.currentLocation.heading': '\ud83e\udded GPS Direzione',
      'vehicle.cabin.infotainment.navigation.currentLocation.altitude': '\ud83c\udfd4\ufe0f GPS Altitudine',
      'sensor.x3_m40d_tire_pressure_front_left': '\ud83d\udd27 Pressione ant. SX',
      'sensor.x3_m40d_tire_pressure_front_right': '\ud83d\udd27 Pressione ant. DX',
      'sensor.x3_m40d_tire_pressure_rear_left': '\ud83d\udd27 Pressione post. SX',
      'sensor.x3_m40d_tire_pressure_rear_right': '\ud83d\udd27 Pressione post. DX',
      'vehicle.chassis.axle.row1.wheel.left.tire.pressure': '\ud83d\udd27 Pressione ant. SX',
      'vehicle.chassis.axle.row1.wheel.right.tire.pressure': '\ud83d\udd27 Pressione ant. DX',
      'vehicle.chassis.axle.row2.wheel.left.tire.pressure': '\ud83d\udd27 Pressione post. SX',
      'vehicle.chassis.axle.row2.wheel.right.tire.pressure': '\ud83d\udd27 Pressione post. DX',
      'sensor.x3_m40d_preconditioning_state': '\u2744\ufe0f Clima pre-avvio',
      'vehicle.vehicle.preConditioning.activity': '\u2744\ufe0f Clima pre-avvio',
      'vehicle.vehicle.preConditioning.error': '\u2744\ufe0f Clima errore',
      'vehicle.vehicle.preConditioning.remainingTime': '\u2744\ufe0f Clima tempo',
      'sensor.x3_m40d_driving_distance_this_month': '\ud83d\udcc5 Km questo mese'
    };
    
    var stateLabels = {
      'UNLOCKED': 'Sbloccata', 'LOCKED': 'Bloccata', 'SECURED': 'Protetta',
      'CLOSED': 'Chiuso', 'OPEN': 'Aperto',
      'true': 'Aperto', 'false': 'Chiuso',
      'on': 'Aperto', 'off': 'Chiuso',
      'INACTIVE': 'Inattivo', 'ACTIVE': 'Attivo',
      'OK': 'OK', 'ok': 'OK'
    };
    
    function isAlert(state) {
      var s = String(state).toUpperCase();
      return s === 'UNLOCKED' || s === 'OPEN' || s === 'TRUE' || s === 'ON';
    }
    function badgeClass(state) {
      var s = String(state).toUpperCase();
      if (s === 'UNLOCKED' || s === 'OPEN' || s === 'TRUE' || s === 'ON') return 'badge-open';
      if (s === 'LOCKED' || s === 'SECURED' || s === 'CLOSED' || s === 'FALSE' || s === 'OFF') return 'badge-closed';
      return 'badge-val';
    }
    function formatState(state, entityId) {
      var label = stateLabels[state] || state;
      if (!isNaN(parseFloat(state)) && entityId) {
        if (entityId.includes('pressure')) label = state + ' kPa';
        else if (entityId.includes('latitude') || entityId.includes('longitude')) label = parseFloat(state).toFixed(4) + '\u00b0';
        else if (entityId.includes('heading')) label = state + '\u00b0';
        else if (entityId.includes('altitude')) label = state + ' m';
        else if (entityId.includes('mileage') || entityId.includes('distance') || entityId.includes('travelled') || entityId.includes('range') || entityId.includes('Range')) label = parseInt(state).toLocaleString('it') + ' km';
        else if (entityId.includes('fuel') && entityId.includes('level')) label = state + '%';
        else if (entityId.includes('remainingFuel') || entityId.includes('tank_level_2')) label = state + ' L';
      }
      return label;
    }
    function entityName(id) {
      if (entityNames[id]) return entityNames[id];
      var parts = id.split('.');
      return parts.slice(-2).join('.');
    }
    
    function load() {
      document.getElementById('eventList').innerHTML = '<div class="loading">Caricamento...</div>';
      fetch('/api/history?limit=' + currentLimit + '&category=' + currentCat)
        .then(function(r){return r.json()})
        .then(render)
        .catch(function(e){document.getElementById('eventList').innerHTML='<div class="loading">Errore: '+e.message+'</div>'});
    }
    
    function render(data) {
      var events = data.events || [];
      document.getElementById('statsCount').textContent = events.length + ' cambi di stato';
      document.getElementById('statsDedup').textContent = data.total_raw ? '(filtrati da ' + data.total_raw + ' eventi)' : '';
      
      if (!events.length) {
        document.getElementById('eventList').innerHTML = '<div class="loading">Nessun evento per questa categoria</div>';
        return;
      }
      
      // Group events by bmw_timestamp (same message = same timestamp)
      var grouped = [];
      var curGroup = null;
      events.forEach(function(ev) {
        var ts = ev.bmw_timestamp || ev.snapshot_timestamp;
        if (curGroup && curGroup.ts === ts) {
          curGroup.items.push(ev);
        } else {
          curGroup = { ts: ts, snapshot: ev.snapshot_timestamp, items: [ev] };
          grouped.push(curGroup);
        }
      });
      
      var months = ['gen','feb','mar','apr','mag','giu','lug','ago','set','ott','nov','dic'];
      var days = ['dom','lun','mar','mer','gio','ven','sab'];
      var html = '';
      var lastDate = '';
      var targetF = 240, targetR = 250; // kPa targets
      
      function pressureBar(val, target) {
        var v = parseInt(val);
        if (isNaN(v)) return '';
        var w = Math.round((v / 300) * 80);
        var diff = Math.abs(v - target);
        var col = diff <= 20 ? '#5cf29c' : diff <= 40 ? '#ffb55c' : '#ff5757';
        return '<span style="display:inline-block;height:8px;width:' + w + 'px;background:' + col + ';border-radius:4px;vertical-align:middle;margin:0 4px"></span>';
      }
      
      function fuelBar(val) {
        var v = parseFloat(val);
        if (isNaN(v)) return '';
        var pct = v;
        if (v > 100) return ''; // not a percentage
        var w = Math.round(pct * 0.8);
        var col = pct > 30 ? '#5cf29c' : pct > 15 ? '#ffb55c' : '#ff5757';
        return '<span style="display:inline-block;height:8px;width:' + w + 'px;background:' + col + ';border-radius:4px;vertical-align:middle;margin:0 4px"></span>';
      }
      
      function tyrePos(id) {
        if (id.includes('front_left') || id.includes('row1') && id.includes('left')) return 'FL';
        if (id.includes('front_right') || id.includes('row1') && id.includes('right')) return 'FR';
        if (id.includes('rear_left') || id.includes('row2') && id.includes('left')) return 'RL';
        if (id.includes('rear_right') || id.includes('row2') && id.includes('right')) return 'RR';
        return '?';
      }
      
      grouped.forEach(function(group) {
        var ts = new Date(group.snapshot || group.ts);
        var dateStr = ts.toISOString().substring(0,10);
        if (dateStr !== lastDate) {
          lastDate = dateStr;
          var dayName = days[ts.getDay()];
          html += '<div class="date-sep">\u2500\u2500 ' + dayName + ' ' + ts.getDate() + ' ' + months[ts.getMonth()] + ' ' + ts.getFullYear() + ' \u2500\u2500</div>';
        }
        var time = String(ts.getHours()).padStart(2,'0') + ':' + String(ts.getMinutes()).padStart(2,'0') + ':' + String(ts.getSeconds()).padStart(2,'0');
        
        // Check for tyre group (multiple pressure readings at same time)
        var tyreItems = group.items.filter(function(e) {
          return e.entity_id.includes('tire_pressure') || e.entity_id.includes('axle');
        });
        var nonTyreItems = group.items.filter(function(e) {
          return !(e.entity_id.includes('tire_pressure') || e.entity_id.includes('axle'));
        });
        
        // Render grouped tyres as one row
        if (tyreItems.length >= 2) {
          var parts = tyreItems.map(function(t) {
            var pos = tyrePos(t.entity_id);
            var val = parseInt(t.state);
            var target = (pos === 'FL' || pos === 'FR') ? targetF : targetR;
            return '<span style="margin-right:12px">' + pos + ' <strong>' + t.state + '</strong>' + pressureBar(t.state, target) + '</span>';
          });
          html += '<div class="ev"><span class="ev-time">' + time + '</span><span class="ev-entity">\ud83d\udd27 Pressione</span><span>' + parts.join('') + '<small style="color:var(--muted)">kPa</small></span></div>';
        } else if (tyreItems.length === 1) {
          var t = tyreItems[0];
          var pos = tyrePos(t.entity_id);
          var target = (pos === 'FL' || pos === 'FR') ? targetF : targetR;
          html += '<div class="ev"><span class="ev-time">' + time + '</span><span class="ev-entity">\ud83d\udd27 Pressione ' + pos + '</span><span><strong>' + t.state + '</strong>' + pressureBar(t.state, target) + ' <small style="color:var(--muted)">kPa</small></span></div>';
        }
        
        // Render non-tyre items
        nonTyreItems.forEach(function(ev) {
          var name = entityName(ev.entity_id);
          var stateText = formatState(ev.state, ev.entity_id);
          var cls = badgeClass(ev.state);
          var rowCls = isAlert(ev.state) ? 'ev alert' : 'ev';
          var bar = '';
          
          // Add fuel bar for percentage values
          if (ev.entity_id.includes('fuel') && ev.entity_id.includes('level') && !ev.entity_id.includes('remaining')) {
            bar = fuelBar(ev.state);
          }
          
          html += '<div class="' + rowCls + '">';
          html += '<span class="ev-time">' + time + '</span>';
          html += '<span class="ev-entity">' + name + '</span>';
          html += '<span class="' + cls + '">' + stateText + bar + '</span>';
          html += '</div>';
        });
      });
      
      document.getElementById('eventList').innerHTML = html;
    }
    
    load();
  <\/script>
</body>
</html>`;
  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=utf-8' }
  });
}

// === Locations (Posizioni) ===
async function serveLocationsData(env, cors) {
  const db = env.DB;
  const current = await db.prepare("SELECT entity_id, value, bmw_timestamp FROM bmw_current WHERE entity_id IN ('vehicle.cabin.infotainment.navigation.currentLocation.latitude','vehicle.cabin.infotainment.navigation.currentLocation.longitude','vehicle.cabin.infotainment.navigation.currentLocation.heading')").all();
  const history = await db.prepare("SELECT snapshot_timestamp, entity_id, state FROM bmw_raw_daily WHERE entity_id IN ('vehicle.cabin.infotainment.navigation.currentLocation.latitude','vehicle.cabin.infotainment.navigation.currentLocation.longitude') ORDER BY snapshot_timestamp ASC LIMIT 500").all();
  const daily = await db.prepare("SELECT snapshot_date, mileage_km FROM bmw_daily WHERE mileage_km IS NOT NULL ORDER BY snapshot_date ASC").all();
  return new Response(JSON.stringify({ current: current.results, history: history.results, daily: daily.results }), {
    headers: { ...cors, 'Content-Type': 'application/json' }
  });
}

function serveLocations() {
  const html = `<!DOCTYPE html>
<html lang="it"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BMW X3 M40d \u00b7 Posizioni</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><\/script>
<style>
:root{--bg:#0a1726;--card:#111d2e;--text:#e4ecf5;--muted:#7b93a8;--accent:#438eff;--line:rgba(39,71,102,.4)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.topbar{position:sticky;top:0;z-index:100;backdrop-filter:blur(18px);background:rgba(10,23,38,.85);padding:16px 24px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}
.topbar a{color:var(--accent);text-decoration:none;font-size:14px}
.topbar h1{font-size:18px;font-weight:700}
.shell{max-width:1100px;margin:0 auto;padding:24px 20px}
#mapLoc{height:400px;border-radius:14px;margin-bottom:24px;border:1px solid var(--line)}
.stats-row{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap}
.stat-card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 20px;flex:1;min-width:140px}
.stat-card small{color:var(--muted);font-size:12px;display:block;margin-bottom:4px}
.stat-card strong{font-size:20px;font-weight:800}
.loading{text-align:center;padding:40px;color:var(--muted)}
</style></head><body>
<header class="topbar"><a href="/">\u2190 Dashboard</a><h1>\ud83d\udccd Posizioni</h1><span style="width:80px"></span></header>
<main class="shell">
<div id="mapLoc"></div>
<div class="stats-row">
<div class="stat-card"><small>Posizione attuale</small><strong id="sLat">\u2014</strong></div>
<div class="stat-card"><small>Punti GPS</small><strong id="sCount">\u2014</strong></div>
<div class="stat-card"><small>Ultimo agg.</small><strong id="sTime">\u2014</strong></div>
</div>
<div id="locList" class="loading">Caricamento posizioni...</div>
</main>
<script>
var map=L.map('mapLoc',{zoomControl:true,attributionControl:false}).setView([39.36,9.01],12);
L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{maxZoom:19}).addTo(map);
fetch('/api/locations').then(function(r){return r.json()}).then(function(data){
var cur={};
(data.current||[]).forEach(function(c){
if(c.entity_id.indexOf('latitude')>=0)cur.lat=parseFloat(c.value);
if(c.entity_id.indexOf('longitude')>=0)cur.lng=parseFloat(c.value);
if(c.entity_id.indexOf('heading')>=0)cur.heading=parseFloat(c.value);
});
if(cur.lat&&cur.lng){
document.getElementById('sLat').textContent=cur.lat.toFixed(4)+'\u00b0N, '+cur.lng.toFixed(4)+'\u00b0E';
var icon=L.divIcon({className:'',html:'<div style="font-size:28px;filter:drop-shadow(0 2px 4px rgba(0,0,0,.5))">\ud83d\ude97</div>',iconSize:[28,28],iconAnchor:[14,14]});
L.marker([cur.lat,cur.lng],{icon:icon}).addTo(map).bindPopup('Posizione attuale');
map.setView([cur.lat,cur.lng],14);
}
var pts=[],hist=data.history||[];
for(var i=0;i<hist.length;i+=2){
if(hist[i]&&hist[i+1]){
var lat=parseFloat(hist[i].state),lng=parseFloat(hist[i+1].state);
if(!isNaN(lat)&&!isNaN(lng))pts.push({lat:lat,lng:lng,ts:hist[i].snapshot_timestamp});
}}
document.getElementById('sCount').textContent=pts.length+' punti';
if(pts.length>1){
var line=pts.map(function(p){return[p.lat,p.lng]});
L.polyline(line,{color:'#438eff',weight:2,opacity:0.6}).addTo(map);
pts.forEach(function(p){L.circleMarker([p.lat,p.lng],{radius:4,color:'#438eff',fillColor:'#69e1b2',fillOpacity:0.8}).addTo(map)});
map.fitBounds(L.latLngBounds(line).pad(0.1));
}
document.getElementById('locList').innerHTML='<div style="color:var(--muted);font-size:13px">'+pts.length+' posizioni GPS registrate</div>';
setTimeout(function(){map.invalidateSize()},200);
}).catch(function(e){document.getElementById('locList').textContent='Errore: '+e.message;});
<\/script></body></html>`;
  return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}

function serveDashboard() {
  return new Response(DASHBOARD_HTML, {
    headers: { 'Content-Type': 'text/html;charset=utf-8' }
  });
}

// The dashboard HTML is embedded as a constant string.
// It replaces google.script.run calls with fetch() to the Worker API.
const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <title>BMW X3 M40d · Dashboard personale</title>
  <style>
:root{--bg:#07111d;--bg2:#091827;--card:rgba(12,27,45,.88);--line:#274766;--text:#f4f7fb;--muted:#9fb2c7;--blue:#3f8cff;--green:#64e78b;--amber:#ffc65b;--red:#ff6b6b}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:radial-gradient(circle at 15% 10%,#163152 0,transparent 32%),radial-gradient(circle at 90% 4%,#0e3154 0,transparent 30%),linear-gradient(180deg,var(--bg2),var(--bg));color:var(--text);font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif}body{overflow-x:hidden}
.ambient{position:fixed;filter:blur(90px);opacity:.18;pointer-events:none;border-radius:50%}.ambient-a{width:360px;height:360px;background:#277eff;top:120px;left:-150px}.ambient-b{width:420px;height:420px;background:#0ad0a0;right:-220px;top:500px}.shell{width:min(1240px,calc(100% - 28px));margin:0 auto;padding:22px 0 36px;position:relative;z-index:2}
.topbar{display:flex;justify-content:space-between;align-items:center;padding:6px 8px 22px}.brand{display:flex;align-items:center;gap:14px}.brand-title{font-size:27px;font-weight:800}.brand-sub{color:var(--muted);font-size:14px}.roundel{width:54px;height:54px;border:3px solid #fff;border-radius:50%;background:conic-gradient(#fff 0 25%,#2494ff 0 50%,#fff 0 75%,#2494ff 0);box-shadow:0 0 0 3px #17202c inset}.top-status{display:flex;align-items:center;gap:14px}.eyebrow{font-size:12px;color:#9fb2c7;text-transform:uppercase;letter-spacing:.12em}.time{font-weight:700;margin-top:3px}.freshness{font-size:12px;color:var(--green);margin-top:5px}.freshness i{display:inline-block;width:8px;height:8px;background:var(--green);border-radius:50%;margin-right:6px}.refresh{width:42px;height:42px;border-radius:14px;border:1px solid var(--line);background:#10233a;color:#d9e8f8;font-size:23px;cursor:pointer}.refresh:hover{background:#153151}
.card{background:linear-gradient(180deg,rgba(17,37,60,.94),rgba(8,22,38,.94));border:1px solid rgba(74,112,148,.42);border-radius:20px;box-shadow:0 20px 60px rgba(0,0,0,.18);overflow:hidden}.hero-grid{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(310px,.7fr);gap:16px}.hero-card{min-height:330px;position:relative;padding:36px;display:flex;align-items:center;overflow:hidden;background:radial-gradient(circle at 78% 22%,rgba(52,126,214,.22),transparent 38%),linear-gradient(135deg,#07121f 0%,#0a1b2e 58%,#0d2238 100%)}.hero-card:after{content:"";position:absolute;inset:0;z-index:2;pointer-events:none;background:linear-gradient(90deg,rgba(5,13,22,.97) 0%,rgba(5,13,22,.92) 34%,rgba(5,13,22,.70) 56%,rgba(5,13,22,.32) 76%,rgba(5,13,22,.18) 100%),linear-gradient(180deg,rgba(6,14,24,.12) 0%,rgba(6,14,24,.08) 58%,rgba(6,14,24,.58) 100%)}.hero-copy{position:relative;z-index:4;max-width:450px}.hero-copy h1{font-size:56px;line-height:.96;margin:12px 0 18px;font-weight:300;letter-spacing:-.04em;text-shadow:0 2px 18px rgba(0,0,0,.35)}.hero-copy h1 span{color:#dce8f6}.hero-copy p{color:#c3d0de;max-width:380px;line-height:1.5;text-shadow:0 1px 10px rgba(0,0,0,.3)}.hero-pills{display:flex;gap:8px;flex-wrap:wrap;margin-top:22px}.pill{padding:8px 11px;border-radius:999px;border:1px solid rgba(108,146,184,.48);background:rgba(10,29,48,.86);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);font-size:12px;color:#d4e0ec;box-shadow:0 5px 18px rgba(0,0,0,.10)}.car-side{position:absolute;z-index:1;right:-3%;bottom:-2%;width:58%;opacity:.34;overflow:hidden;border-radius:0 0 20px 0;filter:saturate(.72) contrast(.86) brightness(.76) blur(.6px);transform:scale(1.02);transform-origin:bottom right;pointer-events:none}.car-side img{width:100%;display:block;border-radius:14px!important;filter:none!important}.car-side svg{width:100%;display:block}.hero-logout{position:absolute!important;top:18px;right:18px;z-index:5!important;background:rgba(7,20,33,.88)!important;color:#dce7f2!important;border-color:rgba(124,155,185,.42)!important}.mileage-card{padding:24px}.card-kicker{font-weight:750;font-size:15px;margin-bottom:14px}.big-number{font-size:44px;font-weight:800;letter-spacing:-.04em}.big-number small,.medium-number small,.analytics-value small{font-size:.45em;color:#d9e5f2}.mini-note{color:var(--muted);font-size:12px;line-height:1.45}.fresh-chip{display:inline-flex;align-items:center;gap:6px;padding:3px 8px;border-radius:999px;font-size:11px;font-weight:700}.fresh-chip.fresh{background:rgba(92,242,156,.12);color:var(--green)}.fresh-chip.stale{background:rgba(242,184,75,.12);color:var(--amber)}.fresh-chip.old,.fresh-chip.unknown{background:rgba(255,87,87,.10);color:#ff8f8f}.mileage-card canvas{margin-top:16px;max-height:150px}
.quick-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:16px}.quick-card{min-height:104px;border:1px solid rgba(74,112,148,.38);border-radius:17px;background:linear-gradient(180deg,rgba(16,37,60,.88),rgba(9,24,40,.9));padding:16px;display:flex;align-items:center;gap:13px}.insight-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:16px}.insight-card{padding:18px 20px}.insight-card strong{display:block;font-size:24px;letter-spacing:-.03em;margin:4px 0 6px}.quick-icon{font-size:25px;filter:saturate(.85)}.quick-card small,.quick-card strong,.quick-card em{display:block}.quick-card small{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.quick-card strong{font-size:24px;margin:3px 0 1px}.quick-card em{font-size:10px;color:#7890a7;font-style:normal}
.summary-grid{display:grid;grid-template-columns:.78fr 1.05fr .65fr;gap:16px;margin-top:16px}.summary-grid .card{padding:24px}.metric-row{display:flex;align-items:baseline;gap:30px}.medium-number{font-size:40px;font-weight:800}.side-value{font-size:22px;font-weight:700;color:#d5e1ee}.progress{height:13px;border-radius:99px;background:#213951;margin:18px 0;overflow:hidden}.progress span{display:block;height:100%;width:0;background:linear-gradient(90deg,#53d79d,#4bd2bd);border-radius:99px;transition:width .6s}.submetric{display:flex;justify-content:space-between;align-items:end;color:var(--muted);font-size:13px}.submetric strong{display:block;color:white;font-size:24px}.status-main{font-size:27px;color:var(--green);font-weight:800;margin:-2px 0 12px}.check-list{display:grid;grid-template-columns:1fr 1fr;gap:10px 14px}.check-list div{display:flex;align-items:center;gap:8px;color:#d4dfeb;font-size:13px}.check-list b{width:24px;height:24px;display:grid;place-items:center;background:#1b6744;color:#8bf2a9;border-radius:50%;font-size:12px}.battery-card{text-align:center}.ok-disc{width:68px;height:68px;margin:4px auto 14px;border-radius:50%;display:grid;place-items:center;background:var(--green);color:#042416;font-size:34px;font-weight:900}.battery-msg{font-size:18px;font-weight:750;margin-bottom:14px}
.advanced-grid{display:grid;grid-template-columns:1fr 1fr .82fr;gap:16px;margin-top:16px}.analytics-card,.trip-card{padding:22px;min-height:310px}.analytics-head{display:flex;align-items:flex-start;justify-content:space-between;gap:15px}.analytics-value{font-size:34px;font-weight:800;letter-spacing:-.03em}.analytics-average{font-size:11px;color:var(--muted);text-align:right}.analytics-average strong{display:block;color:#dce7f3;font-size:18px;margin-top:3px}.chart-holder{position:relative;height:185px;margin-top:16px}.chart-holder canvas{height:185px!important}.empty-state{position:absolute;inset:0;display:grid;place-items:center;text-align:center;color:var(--muted);border:1px dashed rgba(96,129,160,.35);border-radius:14px;background:rgba(7,18,30,.34);font-size:13px;padding:18px}.hidden{display:none!important}
.trip-layout{display:grid;grid-template-columns:155px 1fr;align-items:center;gap:12px;height:230px}.donut-wrap{position:relative;width:150px;height:150px;margin:auto}.donut-wrap canvas{width:150px!important;height:150px!important}.donut-center{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column;pointer-events:none}.donut-center strong{font-size:14px}.donut-center span{font-size:10px;color:var(--muted)}.trip-legend{display:grid;gap:11px}.trip-legend div{display:grid;grid-template-columns:9px 1fr auto;gap:8px;align-items:center;font-size:12px;color:#cdd9e5}.trip-legend i{width:9px;height:9px;border-radius:50%}.trip-legend strong{font-size:12px}.trip-legend .eco{background:#59d989}.trip-legend .eco-plus{background:#83e0c3}.trip-legend .electric{background:#4e9cff}.trip-legend .normal{background:#8497ac}
.lower-grid{display:grid;grid-template-columns:1.55fr .75fr;gap:16px;margin-top:16px}.tyres-card{padding:24px}.section-head{display:flex;justify-content:space-between;align-items:start}.tiny-time{font-size:11px;color:#8fa5ba}.tyre-alert-summary{margin:10px 0 0;padding:9px 11px;border:1px solid rgba(255,198,91,.45);background:rgba(255,198,91,.10);color:var(--amber);border-radius:10px;font-size:12px}.tyres-layout{height:390px;display:grid;grid-template-columns:1fr 220px 1fr;grid-template-rows:1fr 1fr;grid-template-areas:"fl car fr" "rl car rr";align-items:center;gap:4px 22px;margin-top:8px}.fl{grid-area:fl}.fr{grid-area:fr}.rl{grid-area:rl}.rr{grid-area:rr}.top-car{grid-area:car;width:150px;height:330px;justify-self:center;position:relative;border-radius:70px;background:linear-gradient(90deg,#303b49,#9cabb9 48%,#26313d);border:2px solid #53697d;box-shadow:0 10px 35px rgba(0,0,0,.35) inset,0 20px 45px rgba(0,0,0,.28)}.car-roof{position:absolute;left:25px;right:25px;top:58px;height:160px;border-radius:50px 50px 35px 35px;background:linear-gradient(#0f1b27,#243746);border:1px solid #7990a5}.wheel{position:absolute;width:18px;height:62px;background:#05080c;border-radius:8px;border:2px solid #697787}.w1{left:-12px;top:65px}.w2{right:-12px;top:65px}.w3{left:-12px;bottom:65px}.w4{right:-12px;bottom:65px}.tyre-metric{position:relative;padding:10px;border:1px solid transparent;border-radius:14px}.tyre-metric span{display:block;color:#aebed0;font-size:13px}.tyre-metric strong{display:block;font-size:30px;margin:4px 0}.tyre-metric small{color:#879bb0}.tyre-metric.pressure-alert{border-color:rgba(255,198,91,.45);background:rgba(255,198,91,.07)}.pressure-badge{display:inline-block;margin-top:9px;padding:4px 8px;border-radius:999px;background:rgba(100,231,139,.14);color:var(--green);font-size:10px}.pressure-badge.alert{background:rgba(255,198,91,.14);color:var(--amber)}.fr,.rr{text-align:right}.side-stack{display:grid;gap:16px}.compact-card{padding:22px;min-height:112px}.compact-main{font-size:23px;font-weight:800;margin:2px 0 6px}
.charts-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-top:16px}.chart-card{padding:20px;min-height:245px}.chart-card canvas{max-height:165px}.chart-note{margin-top:8px}.footer{display:grid;grid-template-columns:repeat(3,1fr);gap:0;margin-top:18px;border-top:1px solid #20394f;padding:22px 8px 0}.footer div{padding:0 22px;border-right:1px solid #20394f}.footer div:last-child{border-right:0}.footer strong,.footer span{display:block}.footer strong{font-size:13px}.footer span{font-size:11px;color:#91a8bd;margin-top:4px}.loading{position:fixed;inset:0;background:rgba(4,12,20,.82);backdrop-filter:blur(10px);z-index:99;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;font-weight:700}.loading.hidden{display:none}.spinner{width:42px;height:42px;border-radius:50%;border:3px solid #244866;border-top-color:#5ba3ff;animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}.error{color:var(--red)!important}.warn{color:var(--amber)!important}
@media(max-width:1050px){.advanced-grid{grid-template-columns:1fr 1fr}.trip-card{grid-column:1/-1}.trip-layout{grid-template-columns:170px 1fr;max-width:520px;margin:auto}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
@media(max-width:900px){.shell{width:min(100% - 18px,760px);padding-top:12px}.topbar{align-items:flex-start}.brand-title{font-size:22px}.roundel{width:45px;height:45px}.hero-grid,.lower-grid,.charts-grid{grid-template-columns:1fr}.hero-card{min-height:420px;padding:26px}.hero-copy h1{font-size:45px}.car-side{width:92%;right:-16%;opacity:.65}.quick-stats{grid-template-columns:1fr 1fr}.summary-grid{grid-template-columns:1fr 1fr}.security-card{grid-column:1/-1}.advanced-grid{grid-template-columns:1fr}.trip-card{grid-column:auto}.tyres-layout{grid-template-columns:1fr 150px 1fr;height:340px}.top-car{width:115px;height:285px}.check-list{grid-template-columns:1fr}.charts-grid{grid-template-columns:1fr}.footer{grid-template-columns:1fr;gap:15px}.footer div{border-right:0;border-bottom:1px solid #20394f;padding:0 8px 15px}.footer div:last-child{border-bottom:0}.top-status .eyebrow,.top-status .time{display:none}}
@media(max-width:560px){.summary-grid{grid-template-columns:1fr}.quick-stats{grid-template-columns:repeat(2,minmax(0,1fr))}.quick-card:last-child{grid-column:1/-1}.insight-grid{grid-template-columns:1fr}.insight-card{padding:14px}.insight-card strong{font-size:20px}.security-card{grid-column:auto}.period-bar{position:static;padding:.65rem .4rem}.period-pill{padding:.4rem .75rem}.period-label{order:3;width:100%;margin-left:0}.period-bar>div{order:4;width:100%;margin-left:0!important}.hero-card{min-height:318px;padding:22px 18px 22px}.hero-card:after{background:linear-gradient(90deg,rgba(5,13,22,.985) 0%,rgba(5,13,22,.96) 48%,rgba(5,13,22,.72) 72%,rgba(5,13,22,.40) 100%),linear-gradient(180deg,rgba(5,13,22,.08),rgba(5,13,22,.58))}.hero-copy{max-width:92%}.hero-copy h1{font-size:34px;margin:8px 0 12px}.hero-copy p{font-size:13px;max-width:285px}.hero-pills{margin-top:13px;padding-right:42px}.pill{padding:7px 10px;font-size:11px}.hero-logout{top:14px;right:14px;padding:7px 10px!important}.car-side{bottom:-4px;right:-24%;width:92%;opacity:.22;filter:saturate(.6) contrast(.82) brightness(.66) blur(.8px)}.quick-card{min-height:82px}.tyres-layout{grid-template-columns:1fr 105px 1fr;gap:6px;height:310px}.top-car{width:82px;height:240px}.car-roof{left:14px;right:14px}.tyre-metric{padding:6px}.tyre-metric strong{font-size:24px}.tyre-metric span{font-size:11px}.trip-layout{grid-template-columns:1fr;height:auto}.donut-wrap{margin:4px auto 16px}.footer{padding-top:18px}}


/* Period selector */
.period-bar{display:flex;align-items:center;gap:.5rem;padding:.75rem 1rem;position:sticky;top:0;z-index:10;background:var(--bg);border-bottom:1px solid var(--line);flex-wrap:wrap}
.period-pill{background:var(--card);color:var(--muted);border:1px solid var(--line);border-radius:2rem;padding:.4rem 1rem;font-size:.82rem;font-weight:600;cursor:pointer;transition:all .2s}
.period-pill.active{background:var(--blue);color:#fff;border-color:var(--blue)}
.period-pill:hover:not(.active){border-color:var(--blue);color:var(--text)}
.period-label{color:var(--muted);font-size:.72rem;margin-left:auto}
.analytics-spinner{text-align:center;padding:1rem}
.spinner.small{width:20px;height:20px;border-width:2px}

/* Analytics grid */
.analytics-grid{display:grid;grid-template-columns:1fr;gap:.75rem;padding:0 .75rem}
@media(min-width:640px){.analytics-grid{grid-template-columns:repeat(2,1fr)}}
@media(min-width:960px){.analytics-grid{grid-template-columns:repeat(3,1fr)}}

/* Compact cards */
.compact-card{padding:1rem}
.big-metric{font-size:2rem;font-weight:700;line-height:1.1;margin:.25rem 0 .5rem}
.big-metric small{font-size:.9rem;font-weight:400;color:var(--muted)}
.metric-row-compact{display:flex;gap:1.5rem;margin:.3rem 0}
.metric-row-compact div{display:flex;flex-direction:column}
.metric-label{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.metric-row-compact strong{font-size:1.05rem}

.chart-card{grid-column:1/-1}
.chart-card .chart-holder{height:180px}

/* Badges */
.badge{display:inline-block;font-size:.65rem;font-weight:600;padding:.15rem .5rem;border-radius:1rem;vertical-align:middle;margin-left:.4rem}
.badge.insufficient{background:rgba(255,170,50,.15);color:var(--amber)}
.badge.provisional{background:rgba(67,142,255,.15);color:var(--blue)}
.partial-badge{font-size:.7rem;color:var(--amber);margin-top:.25rem}

/* Coverage card */
.coverage-line{font-size:1.1rem;font-weight:600;font-variant-numeric:tabular-nums}
.coverage-dist{font-size:.85rem;color:var(--muted);margin-top:.15rem}

/* Trip stats */
.trip-collecting{display:flex;align-items:center;gap:.5rem;color:var(--muted);font-size:.85rem}
.pulse-dot{width:8px;height:8px;border-radius:50%;background:var(--amber);animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:.4}50%{opacity:1}}
.trip-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:.75rem}
.trip-stat{display:flex;flex-direction:column;align-items:center}
.trip-num{font-size:1.4rem;font-weight:700}
.trip-label{font-size:.7rem;color:var(--muted);text-transform:uppercase}

</style>

  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><\/script>
</head>
<body>
  <div class="ambient ambient-a"></div>
  <div class="ambient ambient-b"></div>

  <main class="shell">
    <header class="topbar">
      <div class="brand">
        <div class="roundel" aria-hidden="true"></div>
        <div>
          <div class="brand-title">BMW X3 M40d</div>
          <div class="brand-sub">Dashboard personale · BMW CarData</div>
        </div>
      </div>
      <div class="top-status">
        <div>
          <div class="eyebrow">Ultimo dato BMW</div>
          <div class="time" id="lastBmw">—</div>
          <div class="freshness" id="freshness"><i></i> Caricamento…</div>
        </div>
        <button class="refresh" id="refreshBtn" onclick="loadDashboard(true)" title="Aggiorna">↻</button>
      </div>
    </header>

    <section class="hero-grid">
      <article class="card hero-card">
        <div class="hero-copy">
          <div class="eyebrow">BMW X3 M40d · G01</div>
          <h1>Più lontano,<br><span>insieme.</span></h1>
          <p>Stato, percorrenza, consumi e manutenzione in un’unica vista.</p>
          <div class="hero-pills">
            <span class="pill" id="homePill">● Stato vettura</span>
            <span class="pill" id="dataHealth" style="font-size:11px;padding:7px 10px">◌ Stato dati</span>
            <span class="pill" id="tripBadge" style="display:none;background:var(--amber);color:#000;animation:pulse 1.5s infinite">🏎️ In viaggio</span>
            <span class="pill">Aggiornamento giornaliero</span>
             <a href="/vehicle-info" class="pill" style="text-decoration:none;background:rgba(67,142,255,.2);color:var(--accent)">📋 Scheda veicolo</a>
             <a href="/trips" class="pill" style="text-decoration:none;background:rgba(92,221,142,.2);color:var(--green)">🗺️ Viaggi</a>
             <a href="/fuel" class="pill" style="text-decoration:none;background:rgba(255,181,92,.2);color:#ffb55c">⛽ Carburante</a>
             <a href="/locations" class="pill" style="text-decoration:none;background:rgba(147,112,219,.2);color:#9370db">📍 Posizioni</a>
             <a href="/history" class="pill" style="text-decoration:none;background:rgba(255,152,0,.2);color:#ff9800">📜 Cronologia</a>
             <a href="/logout" class="pill hero-logout" style="text-decoration:none">Esci</a>
          </div>
          <div id="heroStats" style="margin-top:12px;font-size:13px;color:var(--muted);display:flex;flex-wrap:wrap;gap:8px 16px">
            <span id="heroLock" style="padding:2px 10px;border-radius:12px;font-weight:700">🔒 —</span>
            <span>🛣️ <strong id="heroKm">—</strong> km</span>
            <span>⛽ <strong id="heroFuel">—</strong></span>
            <span>📅 <strong id="heroMonthKm">—</strong> km questo mese <small id="heroMonthFreshness" style="color:var(--muted)"></small></span>
            <span>💰 <strong id="heroCostMonth">—</strong></span>
            <span>⏰ <strong id="heroLastUpdate">—</strong></span>
          </div>
        </div>
        <div class="car-side" aria-hidden="true">
           <img src="/car.jpg" alt="BMW X3 M40d" style="width:100%;display:block;border-radius:12px;filter:drop-shadow(0 8px 32px rgba(0,0,0,.5))"/>
         </div>
      </article>
      <article class="card mileage-card">
        <div class="card-kicker">Chilometraggio totale</div>
        <div class="big-number"><span id="mileage">—</span><small> km</small></div>
        <div class="mini-note">Baseline pneumatici: ~79.000 km</div>
        <canvas id="mileageChart" height="120"></canvas>
      </article>
    </section>

    <section style="margin-top:16px">
      <article class="card" style="padding:16px 20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
        <div style="display:flex;align-items:center;gap:12px">
          <span id="statusBannerIcon" style="font-size:28px">\ud83d\udd12</span>
          <div>
            <strong id="statusBannerLock" style="font-size:18px">\u2014</strong>
            <div style="font-size:11px;color:var(--muted)" id="statusBannerTime">\u2014</div>
          </div>
        </div>
        <div style="display:flex;gap:14px;font-size:13px;flex-wrap:wrap">
          <span id="sBDoors">\u2713 Porte</span>
          <span id="sBWindows">\u2713 Finestrini</span>
          <span id="sBHood">\u2713 Cofano</span>
          <span id="sBTrunk">\u2713 Portellone</span>
          <span id="sBSunroof">\u2713 Tetto</span>
        </div>
      </article>
    </section>

    <section class="quick-stats" aria-label="Riepilogo rapido">
      <article class="quick-card"><span class="quick-icon">🛣️</span><div><small>Km oggi</small><strong id="quickKm">—</strong><em id="quickKmNote">ultimo intervallo giornaliero</em></div></article>
      <article class="quick-card"><span class="quick-icon">⛽</span><div><small>Consumo stimato</small><strong id="quickConsumption">—</strong><em id="quickConsumptionNote">km/L stimati</em></div></article>
      <article class="quick-card"><span class="quick-icon">🌿</span><div><small>ECO Pro</small><strong id="quickEco">—</strong><em>ultimo trip BMW</em></div></article>
      <article class="quick-card"><span class="quick-icon">💰</span><div><small>Costo/km</small><strong id="quickCostKm">—</strong><em id="quickCostNote">€ al km stimato</em></div></article>
      <article class="quick-card"><span class="quick-icon">🅿️</span><div><small>Stato</small><strong id="quickStatus">—</strong><em id="quickStatusNote">stato corrente</em></div></article>
    </section>

    <section class="insight-grid">
      <article class="card insight-card"><div class="card-kicker">Ultimo incremento odometro</div><strong id="lastMoveDistance">—</strong><div class="mini-note" id="lastMoveNote">In attesa di dati odometro</div></article>
      <article class="card insight-card"><div class="card-kicker">Checkpoint 81.000 km</div><strong id="milestoneRemaining">—</strong><div class="mini-note" id="milestoneNote">Stima in preparazione</div></article>
      <article class="card insight-card"><div class="card-kicker">Anomalie recenti</div><div id="anomalyList" class="mini-note">Analisi in corso…</div></article>
      <article class="card insight-card"><div class="card-kicker">Ultimo rifornimento rilevato</div><strong id="lastRefuel">—</strong><div class="mini-note" id="lastRefuelNote">Rilevamento stimato dal livello carburante</div></article>
    </section>

    <section class="summary-grid">
      <article class="card" style="padding:24px">
        <div class="card-kicker">Carburante</div>
        <div class="metric-row"><div class="medium-number"><span id="fuelPercent">—</span><small>%</small></div><div class="side-value"><span id="fuelLitres">—</span> L</div></div>
        <div class="progress"><span id="fuelBar"></span></div>
        <div class="submetric"><span>Autonomia stimata</span><strong><span id="rangeKm">—</span> km</strong></div>
        <div class="mini-note" id="fuelLastUpdate" style="margin-top:8px;font-size:0.78rem;color:var(--muted)">—</div>
      </article>
      <article class="card security-card" style="padding:24px">
        <div class="card-kicker">Stato vettura</div>
        <div class="status-main" id="lockState">—</div>
        <div class="check-list">
          <div><b id="doorsIcon">✓</b><span id="doorsLabel">Porte chiuse</span><small id="doorsTs" style="display:block;color:var(--muted);font-size:0.7rem;margin-top:1px"></small></div>
          <div><b id="windowsIcon">✓</b><span id="windowsLabel">Finestrini chiusi</span><small id="windowsTs" style="display:block;color:var(--muted);font-size:0.7rem;margin-top:1px"></small></div>
          <div><b id="hoodIcon">✓</b><span>Cofano chiuso</span><small id="hoodTs" style="display:block;color:var(--muted);font-size:0.7rem;margin-top:1px"></small></div>
          <div><b id="tailgateIcon">✓</b><span>Portellone chiuso</span><small id="tailgateTs" style="display:block;color:var(--muted);font-size:0.7rem;margin-top:1px"></small></div>
          <div><b id="sunroofIcon">✓</b><span>Tetto apribile chiuso</span><small id="sunroofTs" style="display:block;color:var(--muted);font-size:0.7rem;margin-top:1px"></small></div>
        </div>
        <div class="mini-note" id="securityLastUpdate" style="margin-top:8px;font-size:0.78rem;color:var(--muted)"></div>
      </article>
      <article class="card battery-card" style="padding:24px">
        <div class="card-kicker">Batteria 12V</div>
        <div class="ok-disc" id="batteryDisc">✓</div>
        <div class="battery-msg" id="batteryMsg">—</div>
        <div class="mini-note" id="batteryNote">Stato batteria 12V dal sistema BMW</div>
      </article>
    </section>

    <div class="period-bar" id="periodBar">
      <button class="period-pill" data-days="1" onclick="selectPeriod(1)">1D</button>
      <button class="period-pill" data-days="7" onclick="selectPeriod(7)">7D</button>
      <button class="period-pill" data-days="30" onclick="selectPeriod(30)">30D</button>
      <button class="period-pill" data-days="90" onclick="selectPeriod(90)">90D</button>
      <button class="period-pill active" data-days="0" onclick="selectPeriod(0)">ALL</button>
      <span class="period-label" id="periodLabel"></span>
       <div style="display:flex;gap:6px;align-items:center;margin-left:auto;flex-wrap:wrap">
         <select id="periodMonth" style="background:var(--card);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:5px 8px;font-size:0.8rem;cursor:pointer" onchange="selectMonthYear()">
           <option value="">Mese</option>
         </select>
         <select id="periodYear" style="background:var(--card);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:5px 8px;font-size:0.8rem;cursor:pointer" onchange="selectMonthYear()">
           <option value="">Anno</option>
         </select>
       </div>
    </div>
    <div class="analytics-spinner hidden" id="analyticsLoading"><div class="spinner small"></div></div>

    <section class="analytics-grid" id="drivingSection">
      <article class="card compact-card"><div class="card-kicker">Distanza</div><div class="big-metric"><span id="distanceKm">—</span><small> km</small></div><div class="metric-row-compact"><div><span class="metric-label">km/giorno</span><strong id="avgKmDay">—</strong></div><div><span class="metric-label" id="activeLabel">km/giorno attivo</span><strong id="avgKmActive">—</strong></div></div><div class="metric-row-compact"><div><span class="metric-label">Giorni guidati</span><strong id="drivingDaysVal">—</strong></div><div><span class="metric-label">Più lungo</span><strong id="longestDayVal">—</strong></div></div><div class="partial-badge hidden" id="drivingDaysCov">Copertura parziale</div></article>
      <article class="card compact-card"><div class="card-kicker">Consumo carburante</div><div class="big-metric"><span id="fuelKmL">—</span><small> km/l</small> <span class="badge hidden" id="fuelBadge"></span></div><div class="mini-note hidden" id="fuelCoverage"></div></article>
      <article class="card chart-card"><div class="card-kicker">Distanza giornaliera</div><div class="chart-holder"><canvas id="dailyKmChart2"></canvas><div class="empty-state hidden" id="dailyKmEmpty2">In attesa di dati</div></div></article>
      <article class="card compact-card"><div class="card-kicker">Viaggi</div><div id="tripStatsContent"><div class="trip-collecting"><span class="pulse-dot"></span> Raccolta dati viaggi in corso</div></div></article>
      <article class="card compact-card coverage-card"><div class="card-kicker">Copertura chilometraggio</div><div class="coverage-line"><span id="covFirst">—</span> → <span id="covLast">—</span> km</div><div class="coverage-dist"><span id="covDist">—</span> km monitorati</div><div class="mini-note hidden" id="covGap"></div></article>
    </section>

    <section class="lower-grid">
      <article class="card tyres-card" style="padding:24px">
        <div class="section-head"><div><div class="card-kicker">Pneumatici</div><div class="mini-note">Trend rispetto alla precedente rilevazione valida</div></div><div class="tiny-time" id="tyreTimestamp">—</div></div>
        <div class="tyre-alert-summary hidden" id="tyreAlertSummary">⚠ Pressione fuori target di oltre 0,5 bar</div>
        <div class="tyres-layout">
          <div class="tyre-metric fl" id="tyreFL"><span>Ant. sinistra</span><strong><span id="fl">—</span> bar</strong><small>Target <span id="tfl">—</span> · Δ <span id="flTrend">—</span></small><b class="pressure-badge" id="flAlert">OK</b></div>
          <div class="tyre-metric fr" id="tyreFR"><span>Ant. destra</span><strong><span id="fr">—</span> bar</strong><small>Target <span id="tfr">—</span> · Δ <span id="frTrend">—</span></small><b class="pressure-badge" id="frAlert">OK</b></div>
          <div class="top-car" aria-hidden="true"><div class="car-roof"></div><div class="wheel w1"></div><div class="wheel w2"></div><div class="wheel w3"></div><div class="wheel w4"></div></div>
          <div class="tyre-metric rl" id="tyreRL"><span>Post. sinistra</span><strong><span id="rl">—</span> bar</strong><small>Target <span id="trl">—</span> · Δ <span id="rlTrend">—</span></small><b class="pressure-badge" id="rlAlert">OK</b></div>
          <div class="tyre-metric rr" id="tyreRR"><span>Post. destra</span><strong><span id="rr">—</span> bar</strong><small>Target <span id="trr">—</span> · Δ <span id="rrTrend">—</span></small><b class="pressure-badge" id="rrAlert">OK</b></div>
        </div>
      </article>
      <div class="side-stack">
        <article class="card compact-card" style="padding:22px"><div class="card-kicker">Preclimatizzazione</div><div class="compact-main" id="precondition">—</div><div class="mini-note" id="preconditionDetail">—</div></article>
        <article class="card compact-card" style="padding:22px"><div class="card-kicker">Posizione</div><div class="compact-main" id="locationState">—</div><div class="mini-note" id="locationCoords" style="font-size:0.78rem"></div></article>
        <article class="card" style="padding:22px"><div class="card-kicker">🔧 Service / CBS</div><div id="serviceState" style="margin:4px 0 8px;color:var(--muted)">Caricamento...</div><div id="serviceTable"></div></article>
      </div>
    </section>

    <!-- Map + Vehicle Info -->
    <section class="summary-grid" style="grid-template-columns:1fr 1fr">
      <article class="card" style="padding:20px">
        <div class="card-kicker">📍 Posizione veicolo</div>
        <div id="mapContainer" style="height:280px;border-radius:12px;overflow:hidden;margin-top:8px;background:var(--bg2)">
          <div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--muted)">Caricamento mappa...</div>
        </div>
      </article>
      <article class="card" style="padding:20px">
        <div class="card-kicker">⚙️ Info veicolo</div>
        <div style="margin-top:12px;display:grid;gap:8px;font-size:14px">
          <div style="display:flex;justify-content:space-between"><span style="color:var(--muted)">Modello</span><span>BMW X3 M40d (G01)</span></div>
          <div style="display:flex;justify-content:space-between"><span style="color:var(--muted)">VIN</span><span style="font-family:monospace;font-size:12px">WBATX9••••••62133</span></div>
          <div style="display:flex;justify-content:space-between"><span style="color:var(--muted)">Motore</span><span>B57T (Diesel)</span></div>
          <div style="display:flex;justify-content:space-between"><span style="color:var(--muted)">Colore</span><span>Alpinweiss III</span></div>
          <div style="display:flex;justify-content:space-between"><span style="color:var(--muted)">Costruzione</span><span>13/09/2019</span></div>
          <div style="display:flex;justify-content:space-between"><span style="color:var(--muted)">Trazione</span><span>Convenzionale</span></div>
          <div style="display:flex;justify-content:space-between"><span style="color:var(--muted)">SIM</span><span style="color:var(--green)">● Attiva</span></div>
          <div style="display:flex;justify-content:space-between"><span style="color:var(--muted)">Tetto apribile</span><span>Si</span></div>
          <div style="display:flex;justify-content:space-between"><span style="color:var(--muted)">Navigatore</span><span>Si</span></div>
        </div>
        <a href="/vehicle-info" style="display:block;text-align:center;margin-top:14px;padding:10px;background:rgba(67,142,255,.12);border-radius:10px;color:var(--accent);text-decoration:none;font-size:13px;font-weight:600">📋 Vedi allestimento completo →</a>
      </article>
    </section>

    <section class="extra-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-top:24px">
      <article class="card" style="padding:20px">
        <div class="card-kicker">🏎️ Stile di guida</div>
        <div id="tripModeContent" style="margin-top:12px">
          <div style="display:flex;gap:6px;align-items:center;margin-bottom:8px"><span style="width:12px;height:12px;border-radius:50%;background:#2ea55c;display:inline-block"></span><span style="font-size:13px">ECO Pro</span><strong id="tripEco" style="margin-left:auto">—</strong></div>
          <div style="display:flex;gap:6px;align-items:center;margin-bottom:8px"><span style="width:12px;height:12px;border-radius:50%;background:#438eff;display:inline-block"></span><span style="font-size:13px">ECO Pro+</span><strong id="tripEcoPlus" style="margin-left:auto">—</strong></div>
          <div style="display:flex;gap:6px;align-items:center;margin-bottom:8px"><span style="width:12px;height:12px;border-radius:50%;background:#7b93a8;display:inline-block"></span><span style="font-size:13px">Normal</span><strong id="tripNormal" style="margin-left:auto">—</strong></div>
          <div style="height:8px;border-radius:4px;overflow:hidden;display:flex;margin-top:10px;background:rgba(39,71,102,.3)" id="tripBar">
            <div id="tripBarEco" style="background:#2ea55c;transition:width .5s"></div>
            <div id="tripBarEcoPlus" style="background:#438eff;transition:width .5s"></div>
            <div id="tripBarNormal" style="background:#7b93a8;transition:width .5s"></div>
          </div>
        </div>
      </article>
      <article class="card" style="padding:20px">
        <div class="card-kicker">❄️ Climatizzatore</div>
        <div style="margin-top:12px;text-align:center">
          <div id="precondIcon" style="font-size:36px;margin-bottom:8px">❄️</div>
          <div id="precondState" style="font-size:18px;font-weight:700;margin-bottom:4px">—</div>
          <div id="precondDetail" style="font-size:13px;color:var(--muted)">—</div>
          <div id="precondTime" style="font-size:13px;color:var(--muted);margin-top:4px"></div>
        </div>
      </article>
      <article class="card" style="padding:20px">
        <div class="card-kicker">🔒 Allarme</div>
        <div style="margin-top:12px;text-align:center">
          <div id="alarmIcon" style="font-size:36px;margin-bottom:8px">🔒</div>
          <div id="alarmState" style="font-size:18px;font-weight:700;margin-bottom:4px">—</div>
          <div id="alarmDetail" style="font-size:13px;color:var(--muted)">—</div>
        </div>
      </article>
      <article class="card" style="padding:20px">
        <div class="card-kicker">📱 Telefono</div>
        <div style="margin-top:12px;text-align:center">
          <div style="font-size:36px;margin-bottom:8px">📱</div>
          <div id="phoneState" style="font-size:16px;font-weight:600;margin-bottom:4px">—</div>
          <div style="font-size:12px;color:var(--muted)">Connessione Bluetooth</div>
        </div>
      </article>
      <article class="card" style="padding:20px">
        <div class="card-kicker">💡 Luci</div>
        <div style="margin-top:12px;text-align:center">
          <div id="lightsIcon" style="font-size:36px;margin-bottom:8px">💡</div>
          <div id="lightsState" style="font-size:16px;font-weight:600;margin-bottom:4px">—</div>
          <div style="font-size:12px;color:var(--muted)">Luci esterne</div>
        </div>
      </article>
    </section>

    <section class="charts-grid">
      <article class="card chart-card" style="padding:20px"><div class="card-kicker">Autonomia</div><canvas id="rangeChart"></canvas></article>
      <article class="card chart-card" style="padding:20px"><div class="card-kicker">Carburante</div><canvas id="fuelChart"></canvas></article>
      <article class="card chart-card" style="padding:20px"><div class="card-kicker">Pressione pneumatici</div><canvas id="tyreChart"></canvas><div class="mini-note chart-note">Linee tratteggiate = target BMW anteriori/posteriori.</div></article>
    </section>

    <footer class="footer">
      <div><strong>BMW X3 M40d</strong><span>Connected through BMW CarData</span></div>
      <div><strong>Dati giornalieri</strong><span><span id="entitiesCount">—</span> entità monitorate</span></div>
      <div><strong>Aggiornamento automatico</strong><span>Ogni giorno alle 06:00</span></div>
    </footer>
  </main>

  <div class="loading" id="loading"><div class="spinner"></div><span>Carico i dati BMW…</span></div>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"><\/script>
  <script>
let charts = {};
const $ = id => document.getElementById(id);

function initPeriodSelectors(){
  var m=$('periodMonth'), y=$('periodYear');
  if(!m||!y)return;
  var names=['Gennaio','Febbraio','Marzo','Aprile','Maggio','Giugno','Luglio','Agosto','Settembre','Ottobre','Novembre','Dicembre'];
  names.forEach((name,i)=>{var o=document.createElement('option');o.value=String(i+1).padStart(2,'0');o.textContent=name;m.appendChild(o)});
  var now=new Date(), cy=now.getFullYear();
  for(var yr=cy-2;yr<=cy+1;yr++){var o=document.createElement('option');o.value=String(yr);o.textContent=String(yr);y.appendChild(o)}
  m.value=String(now.getMonth()+1).padStart(2,'0');
  y.value=String(cy);
}

function fmtInt(v){
  if(v === null || v === undefined || v === '') return '—';
  return Number(v).toLocaleString('it-IT',{maximumFractionDigits:0});
}
function fmt1(v){
  if(v === null || v === undefined || v === '') return '—';
  return Number(v).toLocaleString('it-IT',{minimumFractionDigits:1,maximumFractionDigits:1});
}
function parseDate(v){ if(!v) return null; const d=new Date(v); return isNaN(d)?null:d; }
function dateTime(v){ const d=parseDate(v); return d?d.toLocaleString('it-IT',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}):'—'; }
function ageLabel(v){
  const d=parseDate(v); if(!d) return 'Età dato non disponibile';
  const mins=Math.max(0,Math.round((Date.now()-d.getTime())/60000));
  if(mins<2) return 'Dato BMW appena aggiornato';
  if(mins<60) return \`Dato BMW: \${mins} min fa\`;
  const h=Math.floor(mins/60),m=mins%60;
  if(h<24) return \`Dato BMW: \${h}h \${m}m fa\`;
  return \`Dato BMW: \${Math.floor(h/24)}g \${h%24}h fa\`;
}
function formatTimestamp(ts) {
  if (!ts) return '\u2014';
  try {
    var d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    var months = ['gen','feb','mar','apr','mag','giu','lug','ago','set','ott','nov','dic'];
    return d.getDate() + ' ' + months[d.getMonth()] + ', ' + String(d.getHours()).padStart(2,'0') + ':' + String(d.getMinutes()).padStart(2,'0');
  } catch(e) { return ts; }
}

function shortDate(v){ const d=parseDate(v); return d?d.toLocaleDateString('it-IT',{day:'2-digit',month:'2-digit'}):String(v||''); }
function boolIcon(id,ok){ const el=$(id); if(!el)return; if(ok===null||ok===undefined){el.textContent='?';el.parentElement.classList.remove('error');el.parentElement.classList.add('warn');return;} el.textContent=ok?'✓':'!'; el.parentElement.classList.toggle('error',!ok); el.parentElement.classList.remove('warn'); }
function lockLabel(v){ const x=String(v||'').toLowerCase(); if(['secured','locked','selectivelocked','selective-locked'].includes(x))return '🔒 Bloccata'; if(x==='unlocked')return '🔓 Sbloccata'; return v||'—'; }
function locationLabel(v){ const x=String(v||'').toLowerCase(); if(x==='home')return '🏠 Casa'; if(x==='not_home'||x==='away')return '📍 Fuori casa'; return v||'Sconosciuto'; }
function climateLabel(v){ const labels={'INACTIVE':'Inattivo','ACTIVE':'Attivo','HEATING':'Riscaldamento','COOLING':'Raffreddamento','VENTILATION':'Ventilazione','OFF':'Spento'}; return labels[String(v||'')] || v || '—'; }
function escapeHtml(s){ return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

function loadDashboard(manual=false){
  $('loading').classList.remove('hidden');
  fetch('/api/data')
    .then(r => r.json())
    .then(data => {
      renderDashboard(data);
      selectPeriod(currentPeriod);
      $('loading').classList.add('hidden');
      if(manual)$('refreshBtn').animate([{transform:'rotate(0deg)'},{transform:'rotate(360deg)'}],{duration:500});
    })
    .catch(err => {
      $('loading').innerHTML=\`<div class="error">Errore caricamento</div><div>\${escapeHtml(err.message||String(err))}</div>\`;
    });
}

function renderDashboard(d){
  $('mileage').textContent=fmtInt(d.core.mileageKm);
  $('fuelPercent').textContent=fmtInt(d.core.fuelPercent);
  $('fuelLitres').textContent=fmtInt(d.core.fuelLitres);
  $('rangeKm').textContent=fmtInt(d.core.rangeKm);
  $('fuelLastUpdate').textContent=d.core.fuelTimestamp?'Aggiornato '+formatTimestamp(d.core.fuelTimestamp)+' · '+ageLabel(d.core.fuelTimestamp):'Dato carburante non disponibile';
  $('fuelBar').style.width=\`\${Math.max(0,Math.min(100,Number(d.core.fuelPercent)||0))}%\`;
  var mileageTs=d.core.mileageUpdatedAt||d.core.lastBmwTimestamp;
  $('lastBmw').textContent=dateTime(mileageTs);
  var odFresh=(d.freshness&&d.freshness.odometer)||{status:'unknown'};
  $('freshness').className='freshness '+(odFresh.status||'unknown');
  $('freshness').style.color=odFresh.status==='fresh'?'var(--green)':(odFresh.status==='stale'?'var(--amber)':'var(--red)');
  var freshnessDot=$('freshness').querySelector('i');
  if(freshnessDot) freshnessDot.style.background=odFresh.status==='fresh'?'var(--green)':(odFresh.status==='stale'?'var(--amber)':'var(--red)');
  $('freshness').innerHTML='<i></i>'+escapeHtml('Odometro · '+ageLabel(mileageTs).replace('Dato BMW appena aggiornato','appena aggiornato').replace('Dato BMW: ',''));
  $('homePill').textContent=\`● \${locationLabel(d.core.locationState)}\`;
  if($('dataHealth')){
    var fs=d.freshness||{};
    var keys=['odometer','fuel','tyres','battery','location','security'];
    var vals=keys.map(function(k){return fs[k]}).filter(Boolean), total=keys.length;
    var recent=vals.filter(function(x){return x&&x.status==='fresh';}).length;
    var pipe=fs.pipeline||{status:'unknown',timestamp:null};
    var pipeOk=pipe.status==='fresh';
    var pipeStale=pipe.status==='stale';
    var stateColor=pipeOk?'var(--green)':(pipeStale?'var(--amber)':'var(--red)');
    var prefix=pipeOk?'Flusso attivo':(pipeStale?'Flusso in ritardo':'Flusso dati fermo');
    $('dataHealth').textContent='● '+prefix+' · '+recent+'/'+total+' dati recenti';
    $('dataHealth').style.color=stateColor;
    $('dataHealth').style.borderColor=stateColor;
    $('dataHealth').title=pipe.timestamp?('Ultimo invio: '+formatTimestamp(pipe.timestamp)):'Ultimo invio non disponibile';
  }
  // Status banner rendering
  var lkV = (d.security.lockState || '').toUpperCase();
  var lockKnown = ['LOCKED','SECURED','UNLOCKED'].includes(lkV);
  var isLk = lkV === 'LOCKED' || lkV === 'SECURED';
  if($('statusBannerIcon')) $('statusBannerIcon').textContent = !lockKnown ? '❔' : (isLk ? '🔒' : '🔓');
  if($('statusBannerLock')) { $('statusBannerLock').textContent = !lockKnown ? 'Stato serratura n.d.' : (isLk ? 'Bloccata' : 'Sbloccata'); $('statusBannerLock').style.color = !lockKnown ? '#f2b84b' : (isLk ? '#5cf29c' : '#ff5757'); }
  if($('statusBannerTime')) $('statusBannerTime').textContent = d.security.lockTimestamp ? formatTimestamp(d.security.lockTimestamp) : '';
  var oM='<b style="color:#5cf29c">✓</b> ', wM='<b style="color:#ff5757">✗</b> ', uM='<b style="color:#f2b84b">?</b> ';
  var mark=v=>v===null||v===undefined?uM:(v?oM:wM);
  if($('sBDoors')) $('sBDoors').innerHTML = mark(d.security.doorsClosed)+'Porte';
  if($('sBWindows')) $('sBWindows').innerHTML = mark(d.security.windowsClosed)+'Finestrini';
  if($('sBHood')) $('sBHood').innerHTML = mark(d.security.hoodClosed)+'Cofano';
  if($('sBTrunk')) $('sBTrunk').innerHTML = mark(d.security.tailgateClosed)+'Portellone';
  if($('sBSunroof')) $('sBSunroof').innerHTML = mark(d.security.sunroofClosed)+'Tetto';
  if($('heroLock')) { $('heroLock').style.background=!lockKnown?'rgba(242,184,75,.16)':(isLk?'rgba(46,165,92,.2)':'rgba(255,87,87,.2)'); $('heroLock').style.color=!lockKnown?'#f2b84b':(isLk?'#5cf29c':'#ff5757'); $('heroLock').innerHTML=(!lockKnown?'❔':(isLk?'🔒':'🔓'))+' <strong>'+(!lockKnown?'Serratura n.d.':(isLk?'Bloccata':'Sbloccata'))+'</strong>'; }

  // Hero stats
  if(d.core.mileageKm) $('heroKm').textContent=fmtInt(d.core.mileageKm);
  if(d.core.fuelPercent!=null) $('heroFuel').textContent=fmtInt(d.core.fuelPercent)+'% ('+( d.core.fuelLitres||'—')+'L) · '+(d.core.rangeKm||'—')+' km';
  if(d.distanceThisMonth!=null) $('heroMonthKm').textContent=(d.distanceThisMonthPartial?'≥ ':'')+fmtInt(d.distanceThisMonth);
  if($('heroMonthFreshness')) $('heroMonthFreshness').textContent=d.distanceThisMonthPartial&&d.distanceThisMonthThrough?'· fino al '+formatTimestamp(d.distanceThisMonthThrough):'';
  var lastTs = d.core.lastBmwTimestamp || d.core.lastHaUpdated;
  if(lastTs) { try { var dt=new Date(lastTs); $('heroLastUpdate').textContent=dt.toLocaleDateString('it-IT',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}); } catch(e2){} }
  // Trip badge
  var tb=$('tripBadge'); if(tb){ if(d.security.tripInProgress){tb.style.display='inline-flex'}else{tb.style.display='none'} }
  // Map
  if(d.location && d.location.lat && d.location.lng) {
    try {
      var mc=$('mapContainer');
      mc.innerHTML='';
      var mymap=L.map(mc,{zoomControl:true,attributionControl:false}).setView([d.location.lat,d.location.lng],15);
      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{maxZoom:19}).addTo(mymap);
      var icon=L.divIcon({className:'',html:'<div style="font-size:28px;filter:drop-shadow(0 2px 4px rgba(0,0,0,.5))">\ud83d\ude97</div>',iconSize:[28,28],iconAnchor:[14,14]});
      L.marker([d.location.lat,d.location.lng],{icon:icon}).addTo(mymap);
      setTimeout(function(){mymap.invalidateSize()},200);
      // Google Maps link
      var gmLink=document.createElement('a');
      gmLink.href='https://www.google.com/maps?q='+d.location.lat+','+d.location.lng;
      gmLink.target='_blank';
      gmLink.rel='noopener';
      gmLink.style.cssText='display:block;text-align:center;margin-top:8px;color:var(--blue);font-size:0.85rem;text-decoration:none;';
      gmLink.innerHTML='\ud83d\uddfa\ufe0f Apri in Google Maps';
      mc.parentNode.insertBefore(gmLink,mc.nextSibling);
    } catch(e3){ $('mapContainer').innerHTML='<div style="color:var(--muted);padding:20px">Mappa non disponibile</div>'; }
  } else {
    $('mapContainer').innerHTML='<div style="display:flex;align-items:center;justify-content:center;height:100%;color:var(--muted)">Coordinate GPS non disponibili</div>';
  }

  $('lockState').textContent=lockLabel(d.security.lockState);
  $('securityLastUpdate').textContent=d.security.lockTimestamp?'Aggiornato '+formatTimestamp(d.security.lockTimestamp)+' · '+ageLabel(d.security.lockTimestamp):'Aggiornamento non disponibile';
  if(d.security.doorsTimestamp) $('doorsTs').textContent=formatTimestamp(d.security.doorsTimestamp);
  if(d.security.windowsTimestamp) $('windowsTs').textContent=formatTimestamp(d.security.windowsTimestamp);
  if(d.security.hoodTimestamp) $('hoodTs').textContent=formatTimestamp(d.security.hoodTimestamp);
  if(d.security.tailgateTimestamp) $('tailgateTs').textContent=formatTimestamp(d.security.tailgateTimestamp);
  if(d.security.sunroofTimestamp) $('sunroofTs').textContent=formatTimestamp(d.security.sunroofTimestamp);
  boolIcon('doorsIcon',d.security.doorsClosed); boolIcon('windowsIcon',d.security.windowsClosed);
  $('doorsLabel').textContent=d.security.doorsClosed===null?'Porte: dato n.d.':(d.security.doorsClosed?'Porte chiuse':'Porte aperte');
  $('windowsLabel').textContent=d.security.windowsClosed===null?'Finestrini: dato n.d.':(d.security.windowsClosed?'Finestrini chiusi':'Finestrini aperti');
  boolIcon('hoodIcon',d.security.hoodClosed); boolIcon('tailgateIcon',d.security.tailgateClosed); boolIcon('sunroofIcon',d.security.sunroofClosed);

  const battOk=d.battery12v.rechargeRequired===0||d.battery12v.rechargeRequired===null;
  const battTs=parseDate(d.battery12v.bmwTimestamp);
  const battStale=battTs?((Date.now()-battTs.getTime())/3600000>48):true;
  $('batteryDisc').textContent=battOk?'✓':'!';
  $('batteryDisc').style.background=battStale?'var(--amber)':(battOk?'var(--green)':'var(--amber)');
  $('batteryNote').textContent='Stato BMW'+(d.battery12v.bmwTimestamp?' · '+ageLabel(d.battery12v.bmwTimestamp):'');
  (() => {
    const hMap = {'200':'Buono ✅','0':'Scarica ⚠️','100':'Ricarica necessaria ⚠️'};
    const label = hMap[String(d.battery12v.rawHealthState)] || ('Codice: ' + (d.battery12v.rawHealthState || '—'));
    $('batteryMsg').textContent = d.battery12v.rechargeRequired ? 'Ricarica necessaria ⚠️' : (battStale ? 'Ultimo stato: '+label.replace(' ✅','') : label);
  })()

  renderQuickStats(d);
  if(d.lastMovement){
    $('lastMoveDistance').textContent='+'+fmt1(d.lastMovement.distanceKm)+' km';
    $('lastMoveNote').textContent=formatTimestamp(d.lastMovement.timestamp)+' · '+(d.lastMovement.source||'odometro');
  }else{
    $('lastMoveDistance').textContent='—';
    $('lastMoveNote').textContent='Nessun incremento odometro ricostruibile';
  }
  if(d.milestone81000){
    $('milestoneRemaining').textContent=d.milestone81000.remainingKm>0?d.milestone81000.remainingKm.toLocaleString('it-IT')+' km':'Raggiunti';
    if(d.milestone81000.estimatedDate && d.milestone81000.remainingKm>0){
      var md=new Date(d.milestone81000.estimatedDate);
      $('milestoneNote').textContent='~'+md.toLocaleDateString('it-IT',{day:'2-digit',month:'short'})+(d.milestone81000.avgKmPerDay?' · '+fmt1(d.milestone81000.avgKmPerDay)+' km/giorno':'')+(d.distanceThisMonthPartial?' · odometro parziale':'');
    }else{
      $('milestoneNote').textContent=d.milestone81000.avgKmPerDay?fmt1(d.milestone81000.avgKmPerDay)+' km/giorno':'Serve più storico per stimare la data';
    }
  }
  if($('anomalyList')) $('anomalyList').innerHTML=(d.anomalies||[]).map(function(a){
    var icon=a.severity==='ok'?'✓':(a.severity==='alert'?'!':'⚠');
    var cls=a.severity==='alert'?'old':(a.severity==='warn'?'stale':(a.severity==='info'?'unknown':'fresh'));
    var when=a.timestamp?' · '+ageLabel(a.timestamp).replace('Dato BMW: ','').replace('Dato BMW appena aggiornato','adesso'):'';
    return '<div style="margin:6px 0"><span class="fresh-chip '+cls+'">'+icon+' '+escapeHtml(a.text)+escapeHtml(when)+'</span></div>';
  }).join('');
  if($('lastRefuel')){
    if(d.refuels&&d.refuels.last){
      $('lastRefuel').textContent='~'+fmt1(d.refuels.last.litresEstimated)+' L';
      $('lastRefuelNote').textContent=formatTimestamp(d.refuels.last.timestamp)+(d.refuels.last.odometerKm?' · '+fmtInt(d.refuels.last.odometerKm)+' km':'')+' · stima';
    }else{
      $('lastRefuel').textContent='—';
      $('lastRefuelNote').textContent='Nessun rifornimento ≥8 L rilevato nei dati disponibili';
    }
  }
  // renderAnalytics(d.analytics); // replaced by getAnalytics
  // renderTrip(d.trip); // trip mode chart moved to analytics section
  renderTyres(d.tyres);

  $('precondition').textContent=climateLabel(d.climate.preconditioningState);
  $('preconditionDetail').textContent=String(d.climate.errorReason||'').toLowerCase()==='ok'?'Nessun errore':(d.climate.errorReason?\`Stato: \${d.climate.errorReason}\`:'—');
  $('locationState').textContent=locationLabel(d.core.locationState);
  if(d.location && d.location.lat && d.location.lng) {
    $('locationCoords').innerHTML='Posizione disponibile'+(d.location.timestamp?' · '+escapeHtml(ageLabel(d.location.timestamp)):'')+' · <a href="/locations" style="color:var(--blue);text-decoration:none">vedi dettagli</a>';
  } else {
    $('locationCoords').textContent='Solo zona, coordinate non disponibili';
  }
  // Service CBS: visualizza solo valori realmente presenti nei dati BMW.
  if (d.service.items && d.service.items.length > 0) {
    $('serviceState').textContent = d.service.items.length + ' servizi monitorati' + (d.service.bmwTimestamp?' · '+ageLabel(d.service.bmwTimestamp):'');
    const statusIcons = { OK: '\u2705', OVERDUE: '\u26a0\ufe0f', UNKNOWN: '\u2753' };
    let tbl = '<table style="width:100%;border-collapse:collapse;font-size:0.88rem;margin-top:8px">';
    tbl += '<tr style="color:var(--muted);border-bottom:1px solid var(--line)"><th style="text-align:left;padding:6px 8px">Servizio</th><th style="text-align:center;padding:6px 4px">Stato</th><th style="text-align:center;padding:6px 4px">Scadenza</th><th style="text-align:center;padding:6px 4px">Km rimanenti</th></tr>';
    const titleIT = {'Brake fluid':'Liquido freni','Engine oil':'Olio motore','Vehicle check':'Controllo veicolo','Statutory emissions test':'Revisione emissioni'};
    const monthIT = {'01':'Gen','02':'Feb','03':'Mar','04':'Apr','05':'Mag','06':'Giu','07':'Lug','08':'Ago','09':'Set','10':'Ott','11':'Nov','12':'Dic'};
    const currentKm = d.core.mileageKm || null;
    d.service.items.forEach(s => {
      const icon = statusIcons[s.status] || statusIcons.UNKNOWN;
      let kmDisplay = '-';
      if (s.kmRemaining && s.kmRemaining !== '-') {
        const remaining = parseInt(s.kmRemaining);
        if (!isNaN(remaining)) {
          const target = currentKm===null?null:(currentKm + remaining);
          kmDisplay = '<span style="color:var(--accent)">' + remaining.toLocaleString('it') + ' km</span>'+(target===null?'':'<br><small style="color:var(--muted)">a ' + target.toLocaleString('it') + ' km</small>');
        }
      }
      const title = titleIT[s.title] || s.title;
      const parts = (s.date || '').split('-');
      const dateIT = parts.length === 2 ? (monthIT[parts[1]] || parts[1]) + ' ' + parts[0] : s.date;
      tbl += '<tr style="border-bottom:1px solid rgba(39,71,102,0.3)"><td style="padding:8px">' + title + '</td><td style="text-align:center;padding:8px">' + icon + '</td><td style="text-align:center;padding:8px;color:var(--muted)">' + dateIT + '</td><td style="text-align:center;padding:8px">' + kmDisplay + '</td></tr>';
    });
    tbl += '</table>';
    $('serviceTable').innerHTML = tbl;
  } else {
    $('serviceState').textContent = 'Dettaglio CBS non disponibile nei dati correnti'+(d.service.bmwTimestamp?' · '+ageLabel(d.service.bmwTimestamp):'');
  }
  $('entitiesCount').textContent=d.meta.monitoredEntities??'—';

  buildBaseCharts(d.history||[],d.tyres);

  // Extra data rendering
  if (d.extra) {
    var eco = d.extra.tripEcoPro || 0;
    var ecoPlus = d.extra.tripEcoProPlus || 0;
    var elec = d.extra.tripElectric || 0;
    var normal = Math.max(0, 100 - eco - ecoPlus - elec);
    $('tripEco').textContent = eco + '%';
    $('tripEcoPlus').textContent = ecoPlus + '%';
    $('tripNormal').textContent = normal + '%';
    $('tripBarEco').style.width = eco + '%';
    $('tripBarEcoPlus').style.width = ecoPlus + '%';
    $('tripBarNormal').style.width = normal + '%';

    var ps = (d.extra.precondState || 'INACTIVE').toUpperCase();
    $('precondState').textContent = ps === 'INACTIVE' ? 'Inattivo' : ps === 'ACTIVE' ? 'Attivo' : ps;
    $('precondState').style.color = ps === 'ACTIVE' ? 'var(--accent)' : 'var(--muted)';
    $('precondIcon').textContent = ps === 'ACTIVE' ? '🔥' : '❄️';
    var pe = d.extra.precondError || '';
    $('precondDetail').textContent = pe.toLowerCase() === 'ok' ? 'Nessun errore' : pe || '—';
    if (d.extra.precondTime > 0) $('precondTime').textContent = d.extra.precondTime + ' min rimanenti';

    var ds = (d.extra.doorStatus || '').toUpperCase();
    $('alarmState').textContent = ds === 'SECURED' ? 'Protetta' : ds === 'SELECTIVELOCKED' ? 'Parz. chiusa' : ds || '—';
    $('alarmState').style.color = ds === 'SECURED' ? 'var(--green)' : '#e85d5d';
    $('alarmIcon').textContent = ds === 'SECURED' ? '🔒' : '🔓';
    $('alarmDetail').textContent = ds === 'SECURED' ? 'Veicolo chiuso e protetto' : 'Verificare chiusura';

    var ph = d.extra.phoneConnected;
    $('phoneState').textContent = ph === true || ph === 'true' ? 'Connesso' : ph === false || ph === 'false' ? 'Non connesso' : 'In attesa dati';
    
    var li = d.extra.lightsOn;
    $('lightsState').textContent = li === true || li === 'true' ? 'Accese' : li === false || li === 'false' ? 'Spente' : 'In attesa dati';
    $('lightsIcon').textContent = li === true || li === 'true' ? '💡' : '🌙';
  }
}

function renderQuickStats(d){
  $('quickKm').textContent=d.quick.dailyKm===null?'—':\`\${fmt1(d.quick.dailyKm)} km\`;
  if(d.quick.dailyKm===null){
    $('quickKmNote').textContent=d.core.mileageUpdatedAt?'odometro invariato da '+formatTimestamp(d.core.mileageUpdatedAt):'dato odometro non disponibile';
  }else if(d.quick.dailyKmStale){
    $('quickKmNote').textContent=(d.quick.dailyKm>0?'almeno ':'')+fmt1(d.quick.dailyKm)+' km · odometro da aggiornare';
  }else if(d.quick.dailyKm===0){
    $('quickKmNote').textContent='nessun incremento odometro rilevato oggi';
  }else{
    var src=d.quick.dailyKmSource?(' · '+d.quick.dailyKmSource):'';
    $('quickKmNote').textContent='distanza odierna'+src;
  }
  $('quickConsumption').textContent=(d.quick.consumptionL100===null||!(d.quick.consumptionL100>0))?'—':fmt1(100/d.quick.consumptionL100)+' km/L';
  if (d.analytics && d.analytics.consumption && d.analytics.consumption.points && d.analytics.consumption.points.length > 0) {
    const avgC = d.analytics.consumption.average, q=d.consumptionQuality||{};
    $('quickConsumptionNote').textContent = avgC ? 'stima · affidabilità '+(q.confidence||'bassa')+' · '+(q.coveredKm||0)+' km coperti' : 'stima ultimo intervallo';
  }
  $('quickEco').textContent=\`\${fmtInt(d.quick.ecoProPercent)}%\`;
  $('quickStatus').textContent=d.quick.vehicleState||'—';
  if(d.costs && d.costs.costPerKm) {
    $('quickCostKm').textContent=d.costs.costPerKm.toFixed(3)+' \u20ac';
    $('quickCostNote').textContent='diesel '+d.costs.dieselPriceEur.toFixed(3)+' \u20ac/L · '+(d.costs.dieselPriceSource||'fonte n.d.');
  }
  if(d.costs && d.costs.costThisMonth) {
    $('heroCostMonth').textContent=(d.distanceThisMonthPartial?'≥ ':'~')+d.costs.costThisMonth+' \u20ac questo mese';
  } else {
    $('heroCostMonth').textContent='';
  }
  $('quickStatusNote').textContent=d.trip.inProgress?'trip BMW in corso':(d.location&&d.location.label?'posizione BMW CarData':'ultima posizione disponibile');
}

function renderAnalytics(a){
  const kmOk=a&&a.dailyKm&&a.dailyKm.points&&a.dailyKm.points.length;
  $('dailyKmValue').textContent=kmOk?fmt1(a.dailyKm.latest):'—';
  $('dailyKmAvg').textContent=kmOk?\`\${fmt1(a.dailyKm.average)} km\`:'—';
  toggleEmpty('dailyKmChart','dailyKmEmpty',!kmOk);
  if(kmOk){
    makeChart('dailyKmChart','bar',a.dailyKm.points.map(p=>shortDate(p.timestamp)),[{label:'km/giorno',data:a.dailyKm.points.map(p=>p.value),backgroundColor:'rgba(67,142,255,.78)',borderRadius:6}],baseChartOptions(false));
  }else destroyChart('dailyKmChart');

  const cOk=a&&a.consumption&&a.consumption.points&&a.consumption.points.length;
  $('consumptionValue').textContent=cOk?fmt1(a.consumption.latest):'—';
  $('consumptionAvg').textContent=cOk?\`\${fmt1(a.consumption.average)} L/100km\`:'—';
  toggleEmpty('consumptionChart','consumptionEmpty',!cOk);
  if(cOk){
    makeChart('consumptionChart','line',a.consumption.points.map(p=>shortDate(p.timestamp)),[{label:'km/L',data:a.consumption.points.map(p=>p.value>0?Math.round((100/p.value)*10)/10:null),borderColor:'#64e78b',backgroundColor:'rgba(100,231,139,.12)',fill:true,tension:.32,pointRadius:3}],baseChartOptions(false));
  }else destroyChart('consumptionChart');
}

function renderTrip(t){
  $('tripState').textContent=t.inProgress===null?'Dato n.d.':(t.inProgress?'In corso':'Fermo');
  $('ecoProValue').textContent=\`\${fmtInt(t.ecoPro)}%\`; $('ecoProPlusValue').textContent=\`\${fmtInt(t.ecoProPlus)}%\`;
  $('electricValue').textContent=\`\${fmtInt(t.electric)}%\`; $('normalValue').textContent=\`\${fmt1(t.normal)}%\`;
  makeChart('tripModeChart','doughnut',[],[{
    data:[t.ecoPro,t.ecoProPlus,t.electric,t.normal],
    backgroundColor:['#59d989','#83e0c3','#4e9cff','#8497ac'],borderWidth:0,hoverOffset:3
  }],{responsive:true,maintainAspectRatio:false,cutout:'72%',plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>\`\${['ECO Pro','ECO Pro Plus','Electric','Normal'][ctx.dataIndex]}: \${fmt1(ctx.raw)}%\`}}}});
}

function renderTyres(t){
  const map={fl:'frontLeft',fr:'frontRight',rl:'rearLeft',rr:'rearRight',tfl:'targetFrontLeft',tfr:'targetFrontRight',trl:'targetRearLeft',trr:'targetRearRight'};
  Object.keys(map).forEach(id=>$(id).textContent=fmt1(t[map[id]]));
  $('tyreTimestamp').textContent=\`BMW: \${dateTime(t.bmwTimestamp)} · \${ageLabel(t.bmwTimestamp)}\`;
  const defs=[['FL','frontLeft','fl'],['FR','frontRight','fr'],['RL','rearLeft','rl'],['RR','rearRight','rr']];
  defs.forEach(([suffix,key,short])=>{
    const targetAlert=Boolean(t.alerts&&t.alerts[key]); const trendAlert=Boolean(t.trendAlerts&&t.trendAlerts[key]); const alert=targetAlert||trendAlert;
    const drift=t.trend&&t.trend[key]; if($(short+'Trend')) $(short+'Trend').textContent=drift===null||drift===undefined?'—':((drift>0?'+':'')+fmt1(drift)+' bar');
    const box=$(\`tyre\${suffix}\`),badge=$(short+'Alert'); box.classList.toggle('pressure-alert',alert); badge.classList.toggle('alert',alert); badge.textContent=targetAlert?'TARGET':trendAlert?'Δ 0,2+':'OK';
  });
  const targetAny=Boolean(t.alerts&&t.alerts.any),trendAny=Boolean(t.trendAlerts&&t.trendAlerts.any);
  $('tyreAlertSummary').classList.toggle('hidden',!(targetAny||trendAny));
  $('tyreAlertSummary').textContent=targetAny?'⚠ Pressione fuori target di oltre 0,5 bar':trendAny?'⚠ Variazione di almeno 0,2 bar rispetto alla precedente rilevazione':'';
}

function buildBaseCharts(history,tyres){
  const labels=history.map(x=>shortDate(x.timestamp));
  const common=baseChartOptions(true);
  const dailyKmData = history.map((x,i) => {
    if (i === 0 || !x.mileageKm || !history[i-1].mileageKm) return 0;
    const d = x.mileageKm - history[i-1].mileageKm;
    return d >= 0 && d < 500 ? Math.round(d) : 0;
  });
  makeChart('mileageChart','bar',labels,[{label:'km/giorno',data:dailyKmData,backgroundColor:'rgba(67,142,255,.75)',borderRadius:5}],common);
  makeChart('rangeChart','bar',labels,[{label:'km',data:history.map(x=>x.rangeKm),backgroundColor:'rgba(67,142,255,.75)',borderRadius:5}],common);
  makeChart('fuelChart','bar',labels,[{label:'%',data:history.map(x=>x.fuelPercent),backgroundColor:'rgba(92,221,142,.75)',borderRadius:5}],common);

  const frontTarget=tyres.targetFrontLeft??tyres.targetFrontRight??2.4;
  const rearTarget=tyres.targetRearLeft??tyres.targetRearRight??2.5;
  makeChart('tyreChart','line',labels,[
    {label:'Ant. SX',data:history.map(x=>x.flBar),borderColor:'#4e9cff',tension:.3,pointRadius:2},
    {label:'Ant. DX',data:history.map(x=>x.frBar),borderColor:'#cb8cff',tension:.3,pointRadius:2},
    {label:'Post. SX',data:history.map(x=>x.rlBar),borderColor:'#69e1b2',tension:.3,pointRadius:2},
    {label:'Post. DX',data:history.map(x=>x.rrBar),borderColor:'#ffb55c',tension:.3,pointRadius:2},
    {label:'Target ant.',data:labels.map(()=>frontTarget),borderColor:'rgba(78,156,255,.55)',borderDash:[7,6],borderWidth:1.5,pointRadius:0,tension:0},
    {label:'Target post.',data:labels.map(()=>rearTarget),borderColor:'rgba(105,225,178,.55)',borderDash:[7,6],borderWidth:1.5,pointRadius:0,tension:0}
  ],common);
}

function baseChartOptions(showLegend){
  return {responsive:true,maintainAspectRatio:false,interaction:{mode:'index',intersect:false},plugins:{legend:{display:showLegend,labels:{color:'#b7c8d9',boxWidth:9,boxHeight:9,usePointStyle:true}}},scales:{x:{ticks:{color:'#8399ad',maxRotation:0},grid:{color:'rgba(87,118,148,.11)'}},y:{ticks:{color:'#8399ad'},grid:{color:'rgba(87,118,148,.13)'}}}};
}
function toggleEmpty(canvasId,emptyId,isEmpty){ $(canvasId).classList.toggle('hidden',isEmpty); $(emptyId).classList.toggle('hidden',!isEmpty); }
function destroyChart(id){ if(charts[id]){charts[id].destroy();delete charts[id];} }
function makeChart(id,type,labels,datasets,opts){ destroyChart(id); const ctx=$(id); if(!ctx)return; charts[id]=new Chart(ctx,{type,data:{labels,datasets},options:opts}); }

let dashboardRefreshTimer=null;
window.addEventListener('load',()=>{
  initPeriodSelectors();
  loadDashboard(false);
  dashboardRefreshTimer=setInterval(()=>{ if(!document.hidden) loadDashboard(false); },5*60*1000);
});
document.addEventListener('visibilitychange',()=>{
  if(!document.hidden) loadDashboard(false);
});


/* ===== Analytics Period Selector ===== */
let currentPeriod = 0;
let analyticsCache = {};

function selectPeriod(days) {
  currentPeriod = days;
  document.querySelectorAll('.period-pill').forEach(p => p.classList.toggle('active', parseInt(p.dataset.days) === days));
  if (analyticsCache[days]) {
    renderDrivingAnalytics(analyticsCache[days]);
  } else {
    document.getElementById('analyticsLoading').classList.remove('hidden');
    fetch('/api/analytics?days=' + days)
      .then(r => r.json())
      .then(data => {
        analyticsCache[days] = data;
        renderDrivingAnalytics(data);
        document.getElementById('analyticsLoading').classList.add('hidden');
      })
      .catch(err => {
        document.getElementById('analyticsLoading').innerHTML = '<div class="mini-note">Errore: ' + escapeHtml(err.message || String(err)) + '</div>';
      });
  }
}
function selectMonthYear(){
  var m=$('periodMonth').value;
  var y=$('periodYear').value;
  if(!m||!y)return;
  document.querySelectorAll('.period-pill').forEach(function(b){b.classList.remove('active')});
  var daysInMonth=new Date(parseInt(y),parseInt(m),0).getDate();
  var from=y+'-'+m+'-01';
  var to=y+'-'+m+'-'+String(daysInMonth).padStart(2,'0');
  var months=['','Gen','Feb','Mar','Apr','Mag','Giu','Lug','Ago','Set','Ott','Nov','Dic'];
  $('periodLabel').textContent=months[parseInt(m)]+' '+y;
  loadAnalytics('/api/analytics?days=0&from='+from+'&to='+to);
}


function renderDrivingAnalytics(a) {
  if (!a || a.error) {
    document.getElementById('drivingSection').innerHTML = '<div class="mini-note">' + (a ? a.error : 'Nessun dato') + '</div>';
    return;
  }
  const m = a.mileage, d = a.driving, f = a.fuel, t = a.trips;

  // Period label

  // Period label — show data availability
  var periodInfo = a.periodStart + ' → ' + a.periodEnd + ' (' + a.calendarDays + 'd)';
  if (a.dataStart && a.dataStart > a.periodStart) {
    periodInfo += '  ·  dati da ' + shortDate(a.dataStart);
  }
  $('periodLabel').textContent = periodInfo;


  // Distance card
  $('distanceKm').textContent = fmtInt(m.distanceKm);
  $('avgKmDay').textContent = fmt1(d.avgKmPerDay);
  $('avgKmActive').textContent = fmt1(d.avgKmPerDrivingDay);
  $('activeLabel').textContent = d.drivingDaysComplete ? 'km/giorno attivo' : 'km/giorno attivo osservato';
  $('drivingDaysVal').textContent = d.observedDrivingDays;
  $('drivingDaysCov').textContent = d.drivingDaysComplete ? '' : 'Copertura parziale';
  $('drivingDaysCov').classList.toggle('hidden', d.drivingDaysComplete);
  $('longestDayVal').textContent = d.longestDay.km > 0 ? fmtInt(d.longestDay.km) + ' km (' + shortDate(d.longestDay.date) + ')' : '—';

  // Fuel card
  renderFuelCard(f);

  // Coverage card
  $('covFirst').textContent = fmtInt(m.firstOdometer);
  $('covLast').textContent = fmtInt(m.lastOdometer);
  $('covDist').textContent = fmtInt(m.distanceKm);
  const gapEl = $('covGap');
  if (m.unallocatedGapKm > 0) {
    gapEl.textContent = fmtInt(m.unallocatedGapKm) + ' km non attribuiti a giorni specifici';
    gapEl.classList.remove('hidden');
  } else {
    gapEl.classList.add('hidden');
  }

  // Trip stats
  renderTripStats(t);

  // Daily km chart — use existing history data from the main load if available,
  // or show observed daily from analytics
  renderDailyKmChart(a);
}

function renderFuelCard(f) {
  const fuelVal = $('fuelKmL');
  const fuelBadge = $('fuelBadge');
  const fuelCov = $('fuelCoverage');

  if (f.consumptionConfidence === 'insufficient') {
    fuelVal.textContent = '—';
    fuelBadge.textContent = 'Dati insufficienti';
    fuelBadge.className = 'badge insufficient';
    fuelCov.textContent = fmtInt(f.fuelCoveredKm) + ' km / ' + fmt1(f.fuelConsumedL) + ' L osservati';
    fuelCov.classList.remove('hidden');
  } else if (f.consumptionConfidence === 'provisional') {
    fuelVal.textContent = fmt1(f.kmPerLitre);
    fuelBadge.textContent = 'Provvisorio';
    fuelBadge.className = 'badge provisional';
    fuelCov.textContent = fmtInt(f.fuelCoveredKm) + ' km / ' + fmt1(f.fuelConsumedL) + ' L';
    fuelCov.classList.remove('hidden');
  } else {
    fuelVal.textContent = fmt1(f.kmPerLitre);
    fuelBadge.textContent = '';
    fuelBadge.className = 'badge hidden';
    fuelCov.classList.add('hidden');
  }
}

function renderTripStats(t) {
  const el = $('tripStatsContent');
  if (!t || !t.available) {
    el.innerHTML = '<div class="trip-collecting"><span class="pulse-dot"></span> Raccolta dati viaggi in corso</div>';
    return;
  }
  if (t.tripCount === 0) {
    el.innerHTML = '<div class="mini-note">No completed trips in this period</div>';
    return;
  }
  const avgDist = t.trips.reduce((s, tr) => s + (tr.distanceKm || 0), 0) / t.tripCount;
  const avgDur = t.trips.reduce((s, tr) => s + (tr.durationMin || 0), 0) / t.tripCount;
  const longest = t.trips.reduce((mx, tr) => (tr.distanceKm || 0) > (mx.distanceKm || 0) ? tr : mx, t.trips[0]);
  el.innerHTML = '<div class="trip-grid">' +
    '<div class="trip-stat"><span class="trip-num">' + t.tripCount + '</span><span class="trip-label">trips</span></div>' +
    '<div class="trip-stat"><span class="trip-num">' + fmtInt(avgDist) + '</span><span class="trip-label">avg km</span></div>' +
    '<div class="trip-stat"><span class="trip-num">' + fmtInt(avgDur) + '</span><span class="trip-label">avg min</span></div>' +
    '<div class="trip-stat"><span class="trip-num">' + fmtInt(longest.distanceKm) + '</span><span class="trip-label">longest km</span></div>' +
    '</div>';
}


function renderDailyKmChart(a) {
  var canvasId = 'dailyKmChart2';
  var emptyId = 'dailyKmEmpty2';
  if (!a || !a.dailySeries || a.dailySeries.length < 1 || !a.periodStart || !a.periodEnd) {
    toggleEmpty(canvasId, emptyId, true);
    destroyChart(canvasId);
    return;
  }
  toggleEmpty(canvasId, emptyId, false);

  // Build lookup from dailySeries
  var dataMap = {};
  for (var i = 0; i < a.dailySeries.length; i++) {
    dataMap[a.dailySeries[i].date] = a.dailySeries[i].km;
  }

  // Generate every calendar date in the period
  var labels = [], data = [];
  var d = new Date(a.periodStart + 'T00:00:00');
  var end = new Date(a.periodEnd + 'T00:00:00');
  while (d <= end) {
    var iso = d.toISOString().substring(0, 10);
    labels.push(shortDate(iso));
    var val = dataMap[iso];
    data.push(val !== undefined && val > 0 ? val : null);
    d.setDate(d.getDate() + 1);
  }

  makeChart(canvasId, 'bar', labels, [{
    label: 'km',
    data: data,
    backgroundColor: 'rgba(67,142,255,.78)',
    borderRadius: 6,
    maxBarThickness: 24
  }], {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: { callbacks: { label: function(ctx) { return ctx.raw !== null ? ctx.raw + ' km' : 'Nessun dato'; } } } },
    scales: {
      x: { grid: { display: false }, ticks: { color: '#9fb2c7', font: { size: 10 }, maxRotation: 45, autoSkip: true, maxTicksLimit: 15 } },
      y: { beginAtZero: true, grid: { color: 'rgba(39,71,102,.3)' }, ticks: { color: '#9fb2c7', font: { size: 10 } } }
    }
  });
}
</script>

</body>
</html>`;
