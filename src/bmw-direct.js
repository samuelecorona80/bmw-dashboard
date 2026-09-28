const BMW_DEVICE_CODE_URL = 'https://customer.bmwgroup.com/gcdm/oauth/device/code';
const BMW_TOKEN_URL = 'https://customer.bmwgroup.com/gcdm/oauth/token';
const BMW_API_BASE = 'https://api-cardata.bmwgroup.com';
const BMW_SCOPE = 'authenticate_user openid cardata:api:read cardata:streaming:read';

function j(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}
  });
}

function b64url(bytes) {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function b64(bytes) {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s);
}
function unb64(value) {
  const raw = atob(value);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
async function sha256Bytes(value) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
}
async function tokenKey(env) {
  if (!env.BMW_TOKEN_ENCRYPTION_KEY) throw new Error('BMW_TOKEN_ENCRYPTION_KEY_missing');
  const material = await sha256Bytes('bmw-direct-v1|' + env.BMW_TOKEN_ENCRYPTION_KEY);
  return crypto.subtle.importKey('raw', material, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
}
async function seal(env, value) {
  const key = await tokenKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(value));
  const enc = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv}, key, data));
  return b64(iv) + '.' + b64(enc);
}
async function openSeal(env, value) {
  if (!value) return null;
  const [iv64, enc64] = String(value).split('.', 2);
  const key = await tokenKey(env);
  const plain = await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(iv64)}, key, unb64(enc64));
  return JSON.parse(new TextDecoder().decode(plain));
}
async function ensureSchema(env) {
  await env.DB.exec(
    'CREATE TABLE IF NOT EXISTS bmw_direct_state (' +
    'id INTEGER PRIMARY KEY CHECK (id = 1), token_blob TEXT, oauth_blob TEXT, ' +
    'client_id_hint TEXT, vin_hint TEXT, scope TEXT, gcid_hint TEXT, expires_at TEXT, ' +
    'updated_at TEXT, last_fetch_at TEXT, last_fetch_status TEXT, last_error TEXT);' +
    'CREATE TABLE IF NOT EXISTS bmw_direct_raw (' +
    'id INTEGER PRIMARY KEY AUTOINCREMENT, fetched_at TEXT NOT NULL, kind TEXT NOT NULL, ' +
    'vin TEXT, payload_json TEXT NOT NULL);' +
    'CREATE INDEX IF NOT EXISTS idx_bmw_direct_raw_time ON bmw_direct_raw(fetched_at DESC);' +
    'CREATE TABLE IF NOT EXISTS bmw_direct_meta (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT);' +
    'CREATE TABLE IF NOT EXISTS bmw_api_requests (' +
    'id INTEGER PRIMARY KEY AUTOINCREMENT, requested_at TEXT NOT NULL, path TEXT NOT NULL, status INTEGER NOT NULL);' +
    'CREATE INDEX IF NOT EXISTS idx_bmw_api_requests_time ON bmw_api_requests(requested_at DESC);'
  );
}
function configured(env) {
  return Boolean(env.BMW_CLIENT_ID && env.BMW_VIN && env.BMW_TOKEN_ENCRYPTION_KEY);
}

async function getMeta(env, key) {
  await ensureSchema(env);
  return env.DB.prepare('SELECT value, updated_at FROM bmw_direct_meta WHERE key=?').bind(key).first();
}
async function setMeta(env, key, value) {
  await ensureSchema(env);
  const now = new Date().toISOString();
  await env.DB.prepare(
    'INSERT INTO bmw_direct_meta (key,value,updated_at) VALUES (?,?,?) ' +
    'ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at'
  ).bind(key, String(value), now).run();
  return now;
}
async function recordApiRequest(env, path, status) {
  try {
    await ensureSchema(env);
    await env.DB.prepare(
      'INSERT INTO bmw_api_requests (requested_at,path,status) VALUES (?,?,?)'
    ).bind(new Date().toISOString(), path, Number(status)||0).run();
  } catch (_) {}
}
async function quotaStatus(env) {
  await ensureSchema(env);
  const since = new Date(Date.now()-24*60*60*1000).toISOString();
  const rows = await env.DB.prepare(
    'SELECT requested_at,path,status FROM bmw_api_requests WHERE requested_at>=? ORDER BY requested_at ASC'
  ).bind(since).all();
  const list = rows.results || [];
  const used = list.length;
  const limit = 50;
  const oldest = list[0]?.requested_at || null;
  const nextReset = oldest ? new Date(Date.parse(oldest)+24*60*60*1000).toISOString() : null;
  const started = await getMeta(env,'quota_tracking_started');
  if(!started) await setMeta(env,'quota_tracking_started',new Date().toISOString());
  const started2 = started || await getMeta(env,'quota_tracking_started');
  const remoteLimited = await getMeta(env,'remote_rate_limited_at');
  const remoteRetry = await getMeta(env,'remote_retry_after');
  let remoteEstimatedReset = null;
  if (remoteLimited?.value) {
    const t = Date.parse(remoteLimited.value);
    if (Number.isFinite(t)) remoteEstimatedReset = new Date(t + 24*60*60*1000).toISOString();
  }
  return {
    used,
    remaining:Math.max(0,limit-used),
    limit,
    nextReset,
    trackingStartedAt:started2?.value || null,
    scope:'Cloudflare Worker only',
    remoteRateLimitedAt:remoteLimited?.value || null,
    remoteRetryAfter:remoteRetry?.value || null,
    remoteEstimatedReset,
    note:'Contatore locale rolling 24h; non include chiamate BMW fatte prima dell’attivazione o da altri client.'
  };
}
async function latestRawAgeMs(env, kind) {
  const row = await env.DB.prepare(
    'SELECT fetched_at FROM bmw_direct_raw WHERE kind=? ORDER BY fetched_at DESC LIMIT 1'
  ).bind(kind).first();
  if(!row?.fetched_at) return Infinity;
  const t=Date.parse(row.fetched_at);
  return Number.isFinite(t)?Date.now()-t:Infinity;
}
async function getState(env) {
  await ensureSchema(env);
  return env.DB.prepare('SELECT * FROM bmw_direct_state WHERE id=1').first();
}
async function saveState(env, patch) {
  await ensureSchema(env);
  const old = await getState(env) || {};
  const next = {...old, ...patch, id:1};
  await env.DB.prepare(
    'INSERT INTO bmw_direct_state ' +
    '(id, token_blob, oauth_blob, client_id_hint, vin_hint, scope, gcid_hint, expires_at, updated_at, last_fetch_at, last_fetch_status, last_error) ' +
    'VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET token_blob=excluded.token_blob, oauth_blob=excluded.oauth_blob, ' +
    'client_id_hint=excluded.client_id_hint, vin_hint=excluded.vin_hint, scope=excluded.scope, ' +
    'gcid_hint=excluded.gcid_hint, expires_at=excluded.expires_at, updated_at=excluded.updated_at, ' +
    'last_fetch_at=excluded.last_fetch_at, last_fetch_status=excluded.last_fetch_status, last_error=excluded.last_error'
  ).bind(
    next.token_blob || null, next.oauth_blob || null, next.client_id_hint || null,
    next.vin_hint || null, next.scope || null, next.gcid_hint || null,
    next.expires_at || null, next.updated_at || null, next.last_fetch_at || null,
    next.last_fetch_status || null, next.last_error || null
  ).run();
}
function hint(value) {
  const v = String(value || '');
  if (!v) return null;
  if (v.length <= 8) return v.slice(0,2) + '…';
  return v.slice(0,4) + '…' + v.slice(-4);
}
async function postForm(url, body) {
  const response = await fetch(url, {
    method:'POST',
    headers:{'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'},
    body:new URLSearchParams(body)
  });
  let data = {};
  try { data = await response.json(); } catch (_) {}
  return {response, data};
}
async function storeTokens(env, tokenData, previousRefreshToken = null) {
  const now = Date.now();
  const expiresIn = Number(tokenData.expires_in || 3600);
  const tokenSet = {
    access_token: tokenData.access_token || null,
    id_token: tokenData.id_token || null,
    refresh_token: tokenData.refresh_token || previousRefreshToken || null,
    token_type: tokenData.token_type || 'Bearer',
    scope: tokenData.scope || BMW_SCOPE,
    gcid: tokenData.gcid || null,
    obtained_at: new Date(now).toISOString()
  };
  if (!tokenSet.access_token || !tokenSet.refresh_token) throw new Error('BMW_token_response_incomplete');
  await saveState(env, {
    token_blob: await seal(env, tokenSet),
    oauth_blob: null,
    client_id_hint: hint(env.BMW_CLIENT_ID),
    vin_hint: hint(env.BMW_VIN),
    scope: tokenSet.scope,
    gcid_hint: hint(tokenSet.gcid),
    expires_at: new Date(now + expiresIn * 1000).toISOString(),
    updated_at: new Date(now).toISOString(),
    last_error: null
  });
  return tokenSet;
}
async function refreshTokens(env, state, tokens) {
  const {response, data} = await postForm(BMW_TOKEN_URL, {
    client_id: env.BMW_CLIENT_ID,
    grant_type: 'refresh_token',
    refresh_token: tokens.refresh_token
  });
  if (!response.ok) {
    const message = data?.error_description || data?.error || ('HTTP_' + response.status);
    await saveState(env, {last_error:'refresh:' + message, updated_at:new Date().toISOString()});
    throw new Error('BMW_refresh_failed:' + message);
  }
  return storeTokens(env, data, tokens.refresh_token);
}
async function validAccessToken(env) {
  const state = await getState(env);
  if (!state?.token_blob) throw new Error('BMW_not_authorized');
  let tokens = await openSeal(env, state.token_blob);
  const expires = Date.parse(state.expires_at || '');
  if (!Number.isFinite(expires) || expires - Date.now() < 5 * 60 * 1000) {
    tokens = await refreshTokens(env, state, tokens);
  }
  return tokens.access_token;
}
async function apiGet(env, path, accessToken) {
  const response = await fetch(BMW_API_BASE + path, {
    headers:{'Authorization':'Bearer ' + accessToken,'x-version':'v1','Accept':'application/json'}
  });
  await recordApiRequest(env, path.split('?')[0], response.status);
  const text = await response.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch (_) { data = {raw:text}; }
  if (!response.ok) {
    const detail =
      data?.exveErrorId && data?.exveErrorMsg ? (data.exveErrorId + ': ' + data.exveErrorMsg) :
      data?.errorId ||
      data?.error ||
      data?.message ||
      data?.description ||
      data?.error_description ||
      (typeof data?.raw === 'string' ? data.raw.slice(0,180) : null) ||
      'request_failed';
    const detailText = String(detail);
    if (detailText.includes('CU-429') || /rate limit reached/i.test(detailText)) {
      const now = new Date().toISOString();
      await setMeta(env,'remote_rate_limited_at',now);
      const retryAfter = response.headers.get('Retry-After');
      if (retryAfter) await setMeta(env,'remote_retry_after',retryAfter);
    }
    const safePath = path.replace(/([?&](?:access_token|token|refresh_token)=)[^&]+/gi,'$1REDACTED');
    throw new Error('BMW_API_' + response.status + ':' + safePath + ':' + detailText.slice(0,220));
  }
  return data;
}

async function discoverContainerId(env, accessToken, {refresh=false} = {}) {
  if (env.BMW_CONTAINER_ID) return {id:env.BMW_CONTAINER_ID, source:'env'};
  const cached = await getMeta(env,'container_id');
  const cachedAge = cached?.updated_at ? Date.now()-Date.parse(cached.updated_at) : Infinity;
  if (!refresh && cached?.value && Number.isFinite(cachedAge) && cachedAge < 7*24*60*60*1000) {
    return {id:cached.value, source:'cached', count:null};
  }
  const payload = await apiGet(env, '/customers/containers', accessToken);
  const containers = Array.isArray(payload) ? payload : (Array.isArray(payload?.containers) ? payload.containers : []);
  const candidates = containers.filter(x => x && typeof x.containerId === 'string');
  if (!candidates.length) return {id:null, source:'none', count:0};

  const preferred = candidates.find(x =>
    x.purpose === 'High voltage battery telemetry' ||
    x.name === 'BMW CarData HV Battery'
  );
  const chosen = preferred || candidates[candidates.length - 1];
  await setMeta(env,'container_id',chosen.containerId);
  return {id:chosen.containerId, source:preferred ? 'bavariandata_named' : 'existing_latest', count:candidates.length};
}
const DIRECT_ALIAS_MAP = {
  'vehicle.vehicle.travelledDistance': {id:'sensor.x3_m40d_vehicle_mileage', name:'X3 M40d Vehicle mileage'},
  'vehicle.drivetrain.fuelSystem.level': {id:'sensor.x3_m40d_range_tank_level', name:'X3 M40d Range Tank level (%)'},
  'vehicle.drivetrain.fuelSystem.remainingFuel': {id:'sensor.x3_m40d_range_tank_level_2', name:'X3 M40d Range Tank level'},
  'vehicle.drivetrain.lastRemainingRange': {id:'sensor.x3_m40d_range_total_range_last_sent', name:'X3 M40d Range Total range (last sent)'},
  'vehicle.chassis.axle.row1.wheel.left.tire.pressure': {id:'sensor.x3_m40d_tire_pressure_front_left', name:'X3 M40d Tire pressure (front left)'},
  'vehicle.chassis.axle.row1.wheel.right.tire.pressure': {id:'sensor.x3_m40d_tire_pressure_front_right', name:'X3 M40d Tire pressure (front right)'},
  'vehicle.chassis.axle.row2.wheel.left.tire.pressure': {id:'sensor.x3_m40d_tire_pressure_rear_left', name:'X3 M40d Tire pressure (rear left)'},
  'vehicle.chassis.axle.row2.wheel.right.tire.pressure': {id:'sensor.x3_m40d_tire_pressure_rear_right', name:'X3 M40d Tire pressure (rear right)'},
  'vehicle.chassis.axle.row1.wheel.left.tire.pressureTarget': {id:'sensor.x3_m40d_tire_pressure_target_front_left', name:'X3 M40d Tire pressure target (front left)'},
  'vehicle.chassis.axle.row1.wheel.right.tire.pressureTarget': {id:'sensor.x3_m40d_tire_pressure_target_front_right', name:'X3 M40d Tire pressure target (front right)'},
  'vehicle.chassis.axle.row2.wheel.left.tire.pressureTarget': {id:'sensor.x3_m40d_tire_pressure_target_rear_left', name:'X3 M40d Tire pressure target (rear left)'},
  'vehicle.chassis.axle.row2.wheel.right.tire.pressureTarget': {id:'sensor.x3_m40d_tire_pressure_target_rear_right', name:'X3 M40d Tire pressure target (rear right)'}
};

function romeDateKey(value = new Date()) {
  const d = value instanceof Date ? value : new Date(value);
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone:'Europe/Rome', year:'numeric', month:'2-digit', day:'2-digit'
  }).formatToParts(d);
  const g = t => (parts.find(p => p.type === t) || {}).value || '';
  return g('year') + '-' + g('month') + '-' + g('day');
}

function telematicMap(payload) {
  if (!payload || typeof payload !== 'object') return {};
  const x = payload.telematicData || payload.data || {};
  return x && typeof x === 'object' && !Array.isArray(x) ? x : {};
}

async function ingestDirectTelematic(env, vin, payload, fetchedAt) {
  const data = telematicMap(payload);
  const batch = [];
  const rawBatch = [];
  const entityBatch = [];
  const daily = {};
  let newestTs = fetchedAt;

  const pushEntity = (entityId, friendlyName, descriptor, p) => {
    const ts = p?.timestamp || fetchedAt;
    if (Date.parse(ts) > Date.parse(newestTs)) newestTs = ts;
    const value = p?.value;
    const unit = p?.unit || '';
    if (value === undefined || value === null) return;
    const strValue = typeof value === 'object' ? JSON.stringify(value) : String(value);

    batch.push(env.DB.prepare(
      'INSERT INTO bmw_current (entity_id, category, friendly_name, value, unit, last_changed, last_updated, bmw_timestamp, attributes_json) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(entity_id) DO UPDATE SET category=excluded.category, friendly_name=excluded.friendly_name, ' +
      'value=excluded.value, unit=excluded.unit, last_changed=excluded.last_changed, last_updated=excluded.last_updated, ' +
      'bmw_timestamp=excluded.bmw_timestamp, attributes_json=excluded.attributes_json'
    ).bind(entityId, 'direct_cardata', friendlyName, strValue, unit, ts, fetchedAt, ts, JSON.stringify({descriptor,source:'cloudflare_direct'})));

    rawBatch.push(env.DB.prepare(
      'INSERT INTO bmw_raw_daily (snapshot_timestamp, entity_id, friendly_name, state, unit, device_class, last_changed, last_updated, attributes_json, bmw_timestamp, trigger_reason) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(fetchedAt, entityId, friendlyName, strValue, unit, '', ts, fetchedAt, JSON.stringify({descriptor,source:'cloudflare_direct'}), ts, 'cloudflare_direct'));

    entityBatch.push(env.DB.prepare(
      "INSERT INTO bmw_entities (entity_id, friendly_name, device, integration, category, unit, first_seen, last_seen, included_in_daily) " +
      "VALUES (?, ?, ?, 'cloudflare_direct', 'direct_cardata', ?, ?, ?, 'Yes') " +
      'ON CONFLICT(entity_id) DO UPDATE SET friendly_name=excluded.friendly_name, integration=excluded.integration, category=excluded.category, unit=excluded.unit, last_seen=excluded.last_seen'
    ).bind(entityId, friendlyName, vin, unit, fetchedAt, fetchedAt));
  };

  for (const [descriptor, p] of Object.entries(data)) {
    if (!p || typeof p !== 'object') continue;
    pushEntity(descriptor, descriptor, descriptor, p);
    const alias = DIRECT_ALIAS_MAP[descriptor];
    if (alias) {
      pushEntity(alias.id, alias.name, descriptor, p);
      daily[alias.name] = p.value;
    }
  }

  if (batch.length) await env.DB.batch(batch);
  if (rawBatch.length) await env.DB.batch(rawBatch);
  if (entityBatch.length) await env.DB.batch(entityBatch);

  const date = romeDateKey(fetchedAt);
  const mileage = Number(daily['X3 M40d Vehicle mileage']);
  const fuelPct = Number(daily['X3 M40d Range Tank level (%)']);
  const fuelL = Number(daily['X3 M40d Range Tank level']);
  const rangeKm = Number(daily['X3 M40d Range Total range (last sent)']);
  let existing = null;
  try {
    existing = await env.DB.prepare('SELECT * FROM bmw_daily WHERE snapshot_date=?').bind(date).first();
  } catch (_) {}

  if (existing) {
    let dataJson = {};
    try { dataJson = existing.data_json ? JSON.parse(existing.data_json) : {}; } catch (_) {}
    Object.assign(dataJson, daily);
    const startKm = existing.mileage_start_km ?? (Number.isFinite(mileage) ? mileage : null);
    const endKm = Number.isFinite(mileage) ? Math.max(Number(existing.mileage_km ?? mileage), mileage) : existing.mileage_km;
    const distance = Number.isFinite(Number(startKm)) && Number.isFinite(Number(endKm)) && Number(endKm) >= Number(startKm)
      ? Number(endKm) - Number(startKm) : existing.daily_distance_km;
    await env.DB.prepare(
      'UPDATE bmw_daily SET snapshot_timestamp=?, data_json=?, mileage_km=?, mileage_start_km=?, daily_distance_km=?, ' +
      'fuel_percent=?, fuel_litres=?, range_km=?, updated_at=datetime("now") WHERE id=?'
    ).bind(
      fetchedAt, JSON.stringify(dataJson),
      endKm ?? existing.mileage_km, startKm,
      distance,
      Number.isFinite(fuelPct) ? fuelPct : existing.fuel_percent,
      Number.isFinite(fuelL) ? fuelL : existing.fuel_litres,
      Number.isFinite(rangeKm) ? rangeKm : existing.range_km,
      existing.id
    ).run();
  } else if (Object.keys(daily).length) {
    const km = Number.isFinite(mileage) ? mileage : null;
    await env.DB.prepare(
      'INSERT INTO bmw_daily (snapshot_timestamp, snapshot_date, data_json, mileage_km, mileage_start_km, daily_distance_km, fuel_percent, fuel_litres, range_km, lock_state) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(
      fetchedAt, date, JSON.stringify(daily), km, km, 0,
      Number.isFinite(fuelPct) ? fuelPct : null,
      Number.isFinite(fuelL) ? fuelL : null,
      Number.isFinite(rangeKm) ? rangeKm : null,
      null
    ).run();
  }

  return {descriptorCount:Object.keys(data).length, newestTimestamp:newestTs};
}

async function recomputeObservedDailyDistance(env, fetchedAt) {
  try {
    const today = romeDateKey(fetchedAt);
    const rows = await env.DB.prepare(
      "SELECT snapshot_timestamp, state, bmw_timestamp, trigger_reason, attributes_json FROM bmw_raw_daily WHERE entity_id='sensor.x3_m40d_vehicle_mileage' ORDER BY snapshot_timestamp DESC LIMIT 500"
    ).all();
    const samples = (rows.results || []).map(r => {
      const ts = r.bmw_timestamp || r.snapshot_timestamp;
      const km = Number(String(r.state || '').replace(',','.'));
      let direct = r.trigger_reason === 'cloudflare_direct';
      try {
        const a = r.attributes_json ? JSON.parse(r.attributes_json) : {};
        if (a && a.source === 'cloudflare_direct') direct = true;
      } catch (_) {}
      return {ts, km, direct};
    }).filter(x => x.ts && Number.isFinite(x.km) && romeDateKey(x.ts) === today)
      .sort((a,b) => Date.parse(a.ts) - Date.parse(b.ts));

    const progress = [];
    let max = null;
    for (const s of samples) {
      if (max === null || s.km > max + 0.01) {
        max = s.km;
        progress.push(s);
      }
    }
    if (progress.length < 2) return {updated:false, reason:'insufficient_same_day_progress'};

    let distance = 0;
    for (let i=1;i<progress.length;i++) {
      const d = progress[i].km - progress[i-1].km;
      if (d > 0 && d < 500) distance += d;
    }
    distance = Math.round(distance * 10) / 10;
    const startKm = progress[0].km;
    const endKm = progress[progress.length-1].km;
    const latestTs = progress[progress.length-1].ts;

    await env.DB.prepare(
      'UPDATE bmw_daily SET mileage_start_km=?, mileage_km=?, daily_distance_km=?, snapshot_timestamp=?, updated_at=datetime("now") WHERE snapshot_date=?'
    ).bind(startKm,endKm,distance,fetchedAt,today).run();
    return {updated:true,distanceKm:distance,startKm,endKm,latestTs};
  } catch (err) {
    return {updated:false,reason:err?.message||String(err)};
  }
}

async function getMappingsWithAuthRecovery(env, accessToken) {
  try {
    return {data: await apiGet(env, '/customers/vehicles/mappings', accessToken), recovered:false};
  } catch (err) {
    const msg = err?.message || String(err);
    if (!/^BMW_API_(401|403):\/customers\/vehicles\/mappings:/.test(msg)) throw err;

    // A token can be revoked before its exp timestamp (for example after another
    // authorization flow for the same BMW client). Refresh once, then retry.
    const state = await getState(env);
    if (!state?.token_blob) throw err;
    const tokens = await openSeal(env, state.token_blob);
    const refreshed = await refreshTokens(env, state, tokens);
    const data = await apiGet(env, '/customers/vehicles/mappings', refreshed.access_token);
    return {data, recovered:true};
  }
}

async function saveRaw(env, kind, vin, payload) {
  await env.DB.prepare(
    'INSERT INTO bmw_direct_raw (fetched_at, kind, vin, payload_json) VALUES (?, ?, ?, ?)'
  ).bind(new Date().toISOString(), kind, vin || null, JSON.stringify(payload)).run();
}

export async function handleBmwDirect(request, env, path) {
  await ensureSchema(env);
  if (path === '/api/bmw-direct/status' && request.method === 'GET') {
    const state = await getState(env);
    const quota = await quotaStatus(env);
    return j({
      configured: configured(env),
      hasToken: Boolean(state?.token_blob),
      authInProgress: Boolean(state?.oauth_blob),
      clientId: state?.client_id_hint || hint(env.BMW_CLIENT_ID),
      vin: state?.vin_hint || hint(env.BMW_VIN),
      scope: state?.scope || null,
      gcid: state?.gcid_hint || null,
      expiresAt: state?.expires_at || null,
      lastFetchAt: state?.last_fetch_at || null,
      lastFetchStatus: state?.last_fetch_status || null,
      lastError: state?.last_error || null,
      apiQuota: quota
    });
  }
  if (!configured(env)) {
    return j({error:'bmw_direct_not_configured', required:['BMW_CLIENT_ID','BMW_VIN','BMW_TOKEN_ENCRYPTION_KEY']}, 503);
  }
  if (path === '/api/bmw-direct/device/start' && request.method === 'POST') {
    const verifier = b64url(crypto.getRandomValues(new Uint8Array(64)));
    const challenge = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
    const {response, data} = await postForm(BMW_DEVICE_CODE_URL, {
      client_id: env.BMW_CLIENT_ID,
      scope: BMW_SCOPE,
      response_type:'device_code',
      code_challenge:challenge,
      code_challenge_method:'S256'
    });
    if (!response.ok) return j({error:'device_code_failed', detail:data?.error_description || data?.error || response.status}, 502);
    const flow = {
      device_code:data.device_code,
      code_verifier:verifier,
      interval:Number(data.interval || 5),
      expires_at:new Date(Date.now() + Number(data.expires_in || 900)*1000).toISOString()
    };
    await saveState(env, {
      oauth_blob:await seal(env, flow),
      client_id_hint:hint(env.BMW_CLIENT_ID),
      vin_hint:hint(env.BMW_VIN),
      updated_at:new Date().toISOString(),
      last_error:null
    });
    return j({
      status:'authorization_required',
      userCode:data.user_code,
      verificationUri:data.verification_uri || data.verification_uri_complete,
      expiresIn:data.expires_in,
      interval:flow.interval
    });
  }
  if (path === '/api/bmw-direct/device/poll' && request.method === 'POST') {
    const state = await getState(env);
    if (!state?.oauth_blob) return j({error:'no_device_flow_in_progress'}, 409);
    const flow = await openSeal(env, state.oauth_blob);
    if (Date.parse(flow.expires_at) <= Date.now()) {
      await saveState(env, {oauth_blob:null,last_error:'device_flow_expired',updated_at:new Date().toISOString()});
      return j({error:'device_flow_expired'}, 410);
    }
    const {response, data} = await postForm(BMW_TOKEN_URL, {
      client_id:env.BMW_CLIENT_ID,
      grant_type:'urn:ietf:params:oauth:grant-type:device_code',
      device_code:flow.device_code,
      code_verifier:flow.code_verifier
    });
    if (response.ok) {
      await storeTokens(env, data);
      return j({status:'authorized'});
    }
    const code = data?.error || 'unknown_error';
    if (code === 'authorization_pending' || code === 'slow_down' || code === 'access_denied') {
      return j({status:'pending', code}, 202);
    }
    await saveState(env, {last_error:'device_poll:' + (data?.error_description || code),updated_at:new Date().toISOString()});
    return j({error:'device_poll_failed',code,detail:data?.error_description || null}, 502);
  }
  if (path === '/api/bmw-direct/refresh' && request.method === 'POST') {
    const state = await getState(env);
    if (!state?.token_blob) return j({error:'BMW_not_authorized'}, 409);
    const tokens = await openSeal(env, state.token_blob);
    await refreshTokens(env, state, tokens);
    return j({status:'refreshed'});
  }
  if (path === '/api/bmw-direct/fetch' && request.method === 'POST') {
    const result = await runBmwDirectFetch(env, {force:true});
    return j(result, result.ok ? 200 : 502);
  }
  return j({error:'not_found'}, 404);
}

export async function runBmwDirectFetch(env, {force=false} = {}) {
  await ensureSchema(env);
  if (!configured(env)) return {ok:false, skipped:true, reason:'not_configured'};
  const state = await getState(env);
  if (!state?.token_blob) return {ok:false, skipped:true, reason:'not_authorized'};

  const quotaBefore = await quotaStatus(env);
  // If BMW itself has told us the remote quota is exhausted, pause calls for 24 h
  // from the first observed CU-429. This avoids wasting requests while the local
  // counter is still incomplete because tracking started later than BMW usage.
  if (quotaBefore.remoteRateLimitedAt && quotaBefore.remoteEstimatedReset &&
      Date.parse(quotaBefore.remoteEstimatedReset) > Date.now()) {
    return {ok:false, skipped:true, reason:'bmw_remote_rate_limit', apiQuota:quotaBefore};
  }
  // Keep a 5-call safety reserve. Manual clicks must not burn through the full BMW allowance.
  if (quotaBefore.used >= 45) {
    return {ok:false, skipped:true, reason:'quota_guard', apiQuota:quotaBefore};
  }

  if (!force && state.last_fetch_at) {
    const age = Date.now() - Date.parse(state.last_fetch_at);
    if (Number.isFinite(age) && age < 55 * 60 * 1000) {
      return {ok:true, skipped:true, reason:'recent_fetch', apiQuota:quotaBefore};
    }
  }

  const now = new Date().toISOString();
  try {
    let token = await validAccessToken(env);
    const vin = env.BMW_VIN;
    const kinds = [];
    let container = null;

    // Expensive/static metadata: at most once per 24 h.
    const mappingsAge = await latestRawAgeMs(env,'mappings');
    if (mappingsAge >= 24*60*60*1000) {
      const mappingResult = await getMappingsWithAuthRecovery(env, token);
      if (mappingResult.recovered) token = await validAccessToken(env);
      await saveRaw(env,'mappings',vin,mappingResult.data);
      kinds.push('mappings');
    } else kinds.push('mappings:cached');

    const basicAge = await latestRawAgeMs(env,'basicData');
    if (basicAge >= 24*60*60*1000) {
      const basic = await apiGet(env,'/customers/vehicles/' + encodeURIComponent(vin) + '/basicData',token);
      await saveRaw(env,'basicData',vin,basic);
      kinds.push('basicData');
    } else kinds.push('basicData:cached');

    // Container list: cached for 7 days. This removes one REST call from normal refreshes.
    container = await discoverContainerId(env, token, {refresh:false});

    let dayDistance = {updated:false, reason:'telematic_not_fetched'};
    if (container.id) {
      const telematic = await apiGet(
        env,
        '/customers/vehicles/' + encodeURIComponent(vin) + '/telematicData?containerId=' + encodeURIComponent(container.id),
        token
      );
      await saveRaw(env,'telematicData',vin,telematic);
      const ingestion = await ingestDirectTelematic(env,vin,telematic,now);
      dayDistance = await recomputeObservedDailyDistance(env,now);
      kinds.push('telematicData');
      kinds.push('current:' + ingestion.descriptorCount);
      kinds.push(dayDistance.updated ? ('todayKm:' + dayDistance.distanceKm) : 'todayKm:n/a');
    }

    const quotaAfter = await quotaStatus(env);
    await saveState(env,{last_fetch_at:now,last_fetch_status:kinds.join('+'),last_error:null,updated_at:now});
    return {
      ok:true,fetchedAt:now,kinds,
      telematicConfigured:Boolean(container.id),
      containerSource:container.source,
      containerCount:container.count ?? null,
      dayDistance,
      apiQuota:quotaAfter
    };
  } catch (err) {
    const message = err?.message || String(err);
    const quotaAfter = await quotaStatus(env);
    await saveState(env,{last_fetch_at:now,last_fetch_status:'error',last_error:message,updated_at:now});
    return {ok:false,error:message,apiQuota:quotaAfter};
  }
}

export function serveBmwDirectPage() {
  return new Response(`<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BMW Direct · Setup</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#07111d;color:#f4f7fb;margin:0;padding:24px}
main{max-width:760px;margin:auto}.card{background:#102239;border:1px solid #31506d;border-radius:18px;padding:20px;margin:16px 0}
button{background:#4b98ff;color:#fff;border:0;border-radius:10px;padding:12px 16px;font-weight:700;margin:6px 6px 6px 0;cursor:pointer}
pre{white-space:pre-wrap;word-break:break-word;background:#091827;padding:14px;border-radius:10px;color:#cfe1f5}
a{color:#7eb5ff}.muted{color:#9fb2c7}.ok{color:#78e39b}.bad{color:#ff9a9a}
</style></head>
<body><main>
<h1>BMW CarData diretto</h1>
<p class="muted">Configurazione Cloudflare → BMW CarData. Nessun token viene mostrato in questa pagina.</p>
<div class="card">
  <h3>1. Stato</h3>
  <button onclick="status()">Aggiorna stato</button>
  <pre id="status">Caricamento…</pre>
</div>
<div class="card">
  <h3>Quota BMW REST</h3>
  <div id="quota" class="muted">Caricamento…</div>
</div>
<div class="card">
  <h3>2. Autorizzazione BMW</h3>
  <button onclick="startAuth()">Avvia Device Code Flow</button>
  <div id="auth" class="muted">Non avviato.</div>
  <button onclick="pollAuth()">Ho autorizzato · verifica</button>
</div>
<div class="card">
  <h3>3. Test REST diretto</h3>
  <button onclick="fetchNow()">Esegui fetch BMW</button>
  <pre id="fetch">Non eseguito.</pre>
</div>
<p><a href="/">← Dashboard</a></p>
<script>
async function api(path,method='GET'){
  const r=await fetch(path,{method,headers:{'Accept':'application/json'}});
  const j=await r.json().catch(()=>({error:'invalid_json'}));
  return {ok:r.ok,status:r.status,j};
}
async function status(){
  const x=await api('/api/bmw-direct/status');
  document.getElementById('status').textContent=JSON.stringify(x.j,null,2);
  const q=x.j.apiQuota;
  if(q){
    var remote='';
    if(q.remoteRateLimitedAt){
      remote='<br><span class="bad"><b>BMW segnala quota esaurita</b> dal '+new Date(q.remoteRateLimitedAt).toLocaleString('it-IT')+'</span>';
      if(q.remoteRetryAfter) remote+=' · Retry-After: '+q.remoteRetryAfter;
      if(q.remoteEstimatedReset) remote+='<br>Riprova automatica stimata dopo '+new Date(q.remoteEstimatedReset).toLocaleString('it-IT');
    }
    document.getElementById('quota').innerHTML='<b>'+q.used+' / '+q.limit+'</b> richieste Cloudflare nelle ultime 24 h · stima residue <b>'+q.remaining+'</b>'+(q.nextReset?'<br>Prima quota locale che si libera: '+new Date(q.nextReset).toLocaleString('it-IT'):'')+remote+'<br><span class="muted">Contatore locale: non include vecchie chiamate o altri client.</span>';
  }
}
async function startAuth(){
  const x=await api('/api/bmw-direct/device/start','POST');
  const el=document.getElementById('auth');
  if(!x.ok){el.innerHTML='<span class="bad">'+JSON.stringify(x.j)+'</span>';return;}
  const u=x.j.verificationUri||'#';
  el.innerHTML='Apri <a target="_blank" rel="noopener" href="'+u+'">BMW authorization</a> e inserisci il codice <b>'+x.j.userCode+'</b>. Poi torna qui e clicca “Ho autorizzato · verifica”.';
  status();
}
async function pollAuth(){
  const x=await api('/api/bmw-direct/device/poll','POST');
  document.getElementById('auth').innerHTML=x.ok?'<span class="ok">Autorizzazione completata.</span>':'<span class="muted">'+JSON.stringify(x.j)+'</span>';
  status();
}
async function fetchNow(){
  const x=await api('/api/bmw-direct/fetch','POST');
  document.getElementById('fetch').textContent=JSON.stringify(x.j,null,2);
  status();
}
status();
</script></main></body></html>`,{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'}});
}
