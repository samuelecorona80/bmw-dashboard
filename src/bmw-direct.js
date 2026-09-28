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
    'CREATE INDEX IF NOT EXISTS idx_bmw_direct_raw_time ON bmw_direct_raw(fetched_at DESC);'
  );
}
function configured(env) {
  return Boolean(env.BMW_CLIENT_ID && env.BMW_VIN && env.BMW_TOKEN_ENCRYPTION_KEY);
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
  const text = await response.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch (_) { data = {raw:text}; }
  if (!response.ok) throw new Error('BMW_API_' + response.status + ':' + (data?.errorId || data?.error || 'request_failed'));
  return data;
}

async function discoverContainerId(env, accessToken) {
  if (env.BMW_CONTAINER_ID) return {id:env.BMW_CONTAINER_ID, source:'env'};
  const payload = await apiGet(env, '/customers/containers', accessToken);
  const containers = Array.isArray(payload) ? payload : (Array.isArray(payload?.containers) ? payload.containers : []);
  const candidates = containers.filter(x => x && typeof x.containerId === 'string');
  if (!candidates.length) return {id:null, source:'none', count:0};

  const preferred = candidates.find(x =>
    x.purpose === 'High voltage battery telemetry' ||
    x.name === 'BMW CarData HV Battery'
  );
  const chosen = preferred || candidates[candidates.length - 1];
  return {id:chosen.containerId, source:preferred ? 'bavariandata_named' : 'existing_latest', count:candidates.length};
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
      lastError: state?.last_error || null
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
  if (!force && state.last_fetch_at) {
    const age = Date.now() - Date.parse(state.last_fetch_at);
    if (Number.isFinite(age) && age < 3.5 * 60 * 60 * 1000) return {ok:true, skipped:true, reason:'recent_fetch'};
  }
  const now = new Date().toISOString();
  try {
    const token = await validAccessToken(env);
    const vin = env.BMW_VIN;
    const mappings = await apiGet(env, '/customers/vehicles/mappings', token);
    await saveRaw(env, 'mappings', vin, mappings);
    const basic = await apiGet(env, '/customers/vehicles/' + encodeURIComponent(vin) + '/basicData', token);
    await saveRaw(env, 'basicData', vin, basic);
    const kinds = ['mappings','basicData'];
    const container = await discoverContainerId(env, token);
    if (container.id) {
      const telematic = await apiGet(
        env,
        '/customers/vehicles/' + encodeURIComponent(vin) + '/telematicData?containerId=' + encodeURIComponent(container.id),
        token
      );
      await saveRaw(env, 'telematicData', vin, telematic);
      kinds.push('telematicData');
    }
    await saveState(env, {last_fetch_at:now,last_fetch_status:kinds.join('+'),last_error:null,updated_at:now});
    return {
      ok:true,
      fetchedAt:now,
      kinds,
      telematicConfigured:Boolean(container.id),
      containerSource:container.source,
      containerCount:container.count ?? null
    };
  } catch (err) {
    const message = err?.message || String(err);
    await saveState(env, {last_fetch_at:now,last_fetch_status:'error',last_error:message,updated_at:now});
    return {ok:false,error:message};
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
