#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');
const net = require('net');
const crypto = require('crypto');

const VERSION = '1.0.0';
const PROVIDER = 'hyehost';
const HOST = '0.0.0.0';

function clean(v) { return String(v || '').trim(); }
function validPort(v) {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 && n <= 65535 ? n : 0;
}
function rand(bytes = 18) { return crypto.randomBytes(bytes).toString('base64url'); }
function sha256(v) { return crypto.createHash('sha256').update(String(v)).digest('hex'); }
function validUuid(v) { return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(clean(v)); }
function validCountry(v) {
  const s = clean(v).toUpperCase();
  return /^[A-Z]{2}$/.test(s) ? s : null;
}
function equal(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return {}; }
}
function writePrivate(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  fs.writeFileSync(tmp, text, { mode: 0o600 });
  fs.renameSync(tmp, file);
  try { fs.chmodSync(file, 0o600); } catch {}
}
function normalizeWsPath(v) {
  const s = clean(v).replace(/^\/+|\/+$/g, '');
  return '/' + (s || `ws-${rand(12)}`);
}
function stripCountryPrefix(v) {
  const s = clean(v) || 'HYEHOST-01';
  return s.replace(/^[A-Z]{2}-/i, '') || 'HYEHOST-01';
}
function formatHost(host) { return net.isIP(host) === 6 ? `[${host}]` : host; }

const PORT = validPort(process.env.PORT) || validPort(process.env.SERVER_PORT) || 8080;
const STATE_DIR = clean(process.env.HYEHOST_STATE_DIR) || path.join(os.homedir(), '.hyehost-node');
const ID_FILE = path.join(STATE_DIR, 'identity.json');
const EP_FILE = path.join(STATE_DIR, 'public-endpoint.json');
const PROOF_FILE = path.join(STATE_DIR, 'registry-proof.txt');
const TRAFFIC_FILE = path.join(STATE_DIR, 'traffic.json');
const VALIDATION_FILE = path.join(STATE_DIR, 'validation.json');
const OPERATOR_FILE = path.join(STATE_DIR, 'operator.json');
const HOME_FILE = path.join(__dirname, 'index.html');

const REGISTRY_URL = clean(process.env.REGISTRY_URL || 'https://subscription-server-v2-production.up.railway.app').replace(/\/+$/, '');
const REGISTRY_TOKEN = clean(process.env.REGISTRY_TOKEN);
const PUBLIC_OVERRIDE = clean(process.env.PUBLIC_ENDPOINT);
const HEARTBEAT_MS = Math.max(60_000, Number(process.env.HEARTBEAT_MS || 600000) || 600000);
const GEO_RETRY_MS = Math.max(60_000, Number(process.env.GEO_RETRY_MS || 300000) || 300000);
const RETENTION_DAYS = Math.max(1, Math.min(3650, Number(process.env.TRAFFIC_RETENTION_DAYS || 90) || 90));

function loadIdentity() {
  const old = readJson(ID_FILE);
  const envUuid = clean(process.env.UUID);
  const id = {
    identity_version: 1,
    uuid: validUuid(envUuid) ? envUuid : (validUuid(old.uuid) ? old.uuid : crypto.randomUUID()),
    wsPath: normalizeWsPath(process.env.WS_PATH || old.wsPath),
    subToken: clean(process.env.SUB_TOKEN) || old.subToken || rand(24),
    nodeId: clean(process.env.NODE_ID) || old.nodeId || `hyehost-${rand(10).toLowerCase()}`,
    nodeNameBase: stripCountryPrefix(process.env.NODE_NAME || old.nodeNameBase || 'HYEHOST-01')
  };
  writePrivate(ID_FILE, id);
  return id;
}

function loadRegistryProof() {
  const fromEnv = clean(process.env.REGISTRY_PROOF);
  if (fromEnv.length >= 32) return fromEnv;
  try {
    const saved = clean(fs.readFileSync(PROOF_FILE, 'utf8'));
    if (saved.length >= 32) return saved;
  } catch {}
  const proof = rand(32);
  writePrivate(PROOF_FILE, proof + '\n');
  return proof;
}

const ID = loadIdentity();
const REGISTRY_PROOF = loadRegistryProof();
const REGISTRY_PROOF_SHA256 = sha256(REGISTRY_PROOF);

let validation = readJson(VALIDATION_FILE);
if (!validation || typeof validation !== 'object') validation = {};
let proxyVerified = !!validation.proxy_verified_at;
let endpointConfirmedThisBoot = false;

function markProxyVerified() {
  const now = new Date().toISOString();
  if (!proxyVerified) {
    proxyVerified = true;
    validation = { ...validation, proxy_verified_at: now };
    writePrivate(VALIDATION_FILE, validation);
    console.log(`[verify] first successful VLESS TCP connection at ${now}; registry is now eligible`);
  }
}

function blankTraffic() {
  return {
    version: 1,
    node_id: ID.nodeId,
    tracking_since: new Date().toISOString(),
    totals: { uplink_bytes: 0, downlink_bytes: 0, total_bytes: 0, connections: 0 },
    days: {},
    updated_at: null
  };
}
let traffic = readJson(TRAFFIC_FILE);
if (traffic.version !== 1) traffic = blankTraffic();
traffic.node_id = ID.nodeId;
traffic.tracking_since = traffic.tracking_since || new Date().toISOString();
traffic.totals = traffic.totals || {};
for (const k of ['uplink_bytes', 'downlink_bytes', 'total_bytes', 'connections']) {
  traffic.totals[k] = Math.max(0, Number(traffic.totals[k]) || 0);
}
traffic.days = traffic.days && typeof traffic.days === 'object' ? traffic.days : {};
let trafficFlushTimer = null;

function utcDay() { return new Date().toISOString().slice(0, 10); }
function flushTraffic() {
  if (trafficFlushTimer) clearTimeout(trafficFlushTimer);
  trafficFlushTimer = null;
  const cutoff = new Date();
  cutoff.setUTCDate(cutoff.getUTCDate() - RETENTION_DAYS + 1);
  const min = cutoff.toISOString().slice(0, 10);
  for (const day of Object.keys(traffic.days)) if (day < min) delete traffic.days[day];
  traffic.updated_at = new Date().toISOString();
  writePrivate(TRAFFIC_FILE, traffic);
}
function addTraffic(up = 0, down = 0, conn = 0) {
  up = Math.max(0, Number(up) || 0);
  down = Math.max(0, Number(down) || 0);
  conn = Math.max(0, Number(conn) || 0);
  if (!up && !down && !conn) return;
  const day = utcDay();
  if (!traffic.days[day]) traffic.days[day] = { uplink_bytes: 0, downlink_bytes: 0, total_bytes: 0, connections: 0 };
  const d = traffic.days[day];
  d.uplink_bytes += up;
  d.downlink_bytes += down;
  d.total_bytes += up + down;
  d.connections += conn;
  traffic.totals.uplink_bytes += up;
  traffic.totals.downlink_bytes += down;
  traffic.totals.total_bytes += up + down;
  traffic.totals.connections += conn;
  if (!trafficFlushTimer) {
    trafficFlushTimer = setTimeout(flushTraffic, 1500);
    trafficFlushTimer.unref?.();
  }
}
function localTraffic(days = 30) {
  const n = Math.max(1, Math.min(RETENTION_DAYS, Number(days) || 30));
  const keys = Object.keys(traffic.days).sort().slice(-n);
  const zero = { uplink_bytes: 0, downlink_bytes: 0, total_bytes: 0, connections: 0 };
  return {
    version: 1,
    provider: PROVIDER,
    node_id: ID.nodeId,
    retention_days: RETENTION_DAYS,
    accounting: 'vless-payload-bytes',
    totals: { ...traffic.totals },
    today: { ...(traffic.days[utcDay()] || zero) },
    daily: keys.map(date => ({ date, ...traffic.days[date] })),
    updated_at: traffic.updated_at
  };
}
function registryTraffic() {
  return {
    version: 1,
    name: nodeName(),
    tracking_since: traffic.tracking_since,
    updated_at: traffic.updated_at || new Date().toISOString(),
    upload_bytes: traffic.totals.uplink_bytes,
    download_bytes: traffic.totals.downlink_bytes,
    total_bytes: traffic.totals.total_bytes,
    connections: traffic.totals.connections
  };
}

let countryState = {
  code: 'XX',
  verified: false,
  mismatch: false,
  egressIp: null,
  checkedAt: null,
  sources: {}
};
let countryPromise = null;

async function fetchText(url, timeout = 7000) {
  const r = await fetch(url, {
    headers: { 'user-agent': `container-test-hyehost/${VERSION}` },
    signal: AbortSignal.timeout(timeout)
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.text();
}
async function fetchJson(url, timeout = 7000) {
  const r = await fetch(url, {
    headers: { 'user-agent': `container-test-hyehost/${VERSION}` },
    signal: AbortSignal.timeout(timeout)
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
async function verifyCountry(force = false) {
  if (!force && countryState.verified) return countryState;
  if (countryPromise) return countryPromise;

  countryPromise = (async () => {
    const sources = {};
    let cf = null;
    let ipinfo = null;

    try {
      const text = await fetchText('https://www.cloudflare.com/cdn-cgi/trace');
      const kv = Object.fromEntries(text.split(/\r?\n/).map(line => line.split('=')).filter(x => x.length === 2));
      cf = { country: validCountry(kv.loc), ip: clean(kv.ip) || null };
      if (cf.country) sources.cloudflare = cf;
    } catch (e) {
      sources.cloudflare_error = e.message;
    }

    try {
      const j = await fetchJson('https://ipinfo.io/json');
      ipinfo = { country: validCountry(j.country), ip: clean(j.ip) || null };
      if (ipinfo.country) sources.ipinfo = ipinfo;
    } catch (e) {
      sources.ipinfo_error = e.message;
    }

    const codes = [cf?.country, ipinfo?.country].filter(Boolean);
    let code = 'XX';
    let verified = false;
    let mismatch = false;

    if (codes.length >= 2) {
      if (codes.every(x => x === codes[0])) {
        code = codes[0];
        verified = true;
      } else {
        mismatch = true;
      }
    } else if (codes.length === 1) {
      code = codes[0];
    }

    const oldName = nodeName();
    countryState = {
      code: mismatch ? 'XX' : code,
      verified,
      mismatch,
      egressIp: cf?.ip || ipinfo?.ip || null,
      checkedAt: new Date().toISOString(),
      sources
    };

    if (verified) {
      console.log(`[geo] verified country=${code} egress_ip=${countryState.egressIp || 'unknown'} sources=cloudflare+ipinfo`);
    } else if (mismatch) {
      console.warn(`[geo] source mismatch; refusing country claim: ${JSON.stringify(sources)}`);
    } else {
      console.warn(`[geo] only one usable source; country=${code} remains unverified`);
    }

    if (oldName !== nodeName()) {
      writeOperatorFile();
      if (registryEligible()) queueRegistry(500);
    }
    return countryState;
  })().finally(() => { countryPromise = null; });

  return countryPromise;
}

function nodeName() { return `${countryState.code || 'XX'}-${ID.nodeNameBase}`; }

function parseEndpoint(v) {
  if (!v) return null;
  try {
    const u = new URL(v.includes('://') ? v : `http://${v}`);
    const protocol = u.protocol === 'https:' ? 'https' : 'http';
    const port = validPort(u.port) || (protocol === 'https' ? 443 : 80);
    if (!u.hostname) return null;
    return { protocol, host: u.hostname, port, source: 'override', learnedAt: new Date().toISOString() };
  } catch { return null; }
}
function isPrivateIpv4(host) {
  if (net.isIP(host) !== 4) return false;
  const p = host.split('.').map(Number);
  return p[0] === 10 ||
    p[0] === 127 ||
    (p[0] === 169 && p[1] === 254) ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168);
}
function acceptablePublicHost(host) {
  const h = clean(host).toLowerCase();
  if (!h || h === 'localhost' || h === '::1' || h === '0.0.0.0') return false;
  if (isPrivateIpv4(h)) return false;
  return true;
}
function endpointScore(ep) {
  if (!ep?.host) return -1;
  return (ep.source === 'override' ? 200 : 0) +
    (ep.protocol === 'https' ? 100 : 0) +
    (!net.isIP(ep.host) ? 40 : 0) +
    (ep.port === 443 ? 20 : 0);
}

let endpoint = parseEndpoint(PUBLIC_OVERRIDE) || readJson(EP_FILE);
if (!endpoint?.host || !validPort(endpoint.port)) endpoint = null;
if (PUBLIC_OVERRIDE && endpoint) endpointConfirmedThisBoot = true;

function baseUrl(ep = endpoint) {
  if (!ep) return null;
  const defaultPort = (ep.protocol === 'https' && ep.port === 443) || (ep.protocol === 'http' && ep.port === 80);
  return `${ep.protocol}://${formatHost(ep.host)}${defaultPort ? '' : ':' + ep.port}`;
}
function vlessUri(ep = endpoint) {
  if (!ep) return null;
  const tls = ep.protocol === 'https';
  const q = new URLSearchParams({
    encryption: 'none',
    security: tls ? 'tls' : 'none',
    type: 'ws',
    host: ep.host,
    path: ID.wsPath
  });
  if (tls) {
    q.set('sni', ep.host);
    q.set('alpn', 'http/1.1');
  }
  return `vless://${ID.uuid}@${formatHost(ep.host)}:${ep.port}?${q.toString()}#${encodeURIComponent(nodeName())}`;
}
function learnEndpoint(req) {
  if (PUBLIC_OVERRIDE) {
    endpointConfirmedThisBoot = true;
    return;
  }
  const xfProto = clean(String(req.headers['x-forwarded-proto'] || '').split(',')[0]).toLowerCase();
  const xfHost = clean(String(req.headers['x-forwarded-host'] || '').split(',')[0]);
  const rawHost = xfHost || clean(req.headers.host);
  if (!rawHost) return;

  let parsed;
  try { parsed = new URL(`http://${rawHost}`); } catch { return; }
  if (!acceptablePublicHost(parsed.hostname)) return;

  let protocol = req.socket.encrypted ? 'https' : 'http';
  if (xfProto === 'https') protocol = 'https';
  else if (xfProto === 'http') protocol = 'http';

  const xfPort = validPort(String(req.headers['x-forwarded-port'] || '').split(',')[0]);
  const port = xfPort || validPort(parsed.port) || (protocol === 'https' ? 443 : 80);
  const candidate = { protocol, host: parsed.hostname, port, source: 'request', learnedAt: new Date().toISOString() };

  endpointConfirmedThisBoot = true;
  const changed = !endpoint || candidate.protocol !== endpoint.protocol || candidate.host !== endpoint.host || candidate.port !== endpoint.port;
  if (!endpoint || endpointScore(candidate) >= endpointScore(endpoint) || changed) {
    endpoint = candidate;
    writePrivate(EP_FILE, candidate);
    writeOperatorFile();
    if (changed) {
      console.log(`[endpoint] learned ${baseUrl(candidate)}`);
      logClientOutputs(true);
      if (registryEligible()) queueRegistry(500);
    }
  }
}

let clientOutputKey = '';
function operatorData() {
  if (!endpoint) return null;
  return {
    version: VERSION,
    provider: PROVIDER,
    node_id: ID.nodeId,
    name: nodeName(),
    endpoint,
    country: {
      code: countryState.code,
      verified: countryState.verified,
      egress_ip: countryState.egressIp,
      checked_at: countryState.checkedAt
    },
    vless_uri: vlessUri(),
    individual_subscription: `${baseUrl()}/${ID.subToken}/sub`,
    individual_subscription_base64: `${baseUrl()}/${ID.subToken}/sub64`,
    node_info: `${baseUrl()}/${ID.subToken}/node`,
    traffic: `${baseUrl()}/${ID.subToken}/traffic`
  };
}
function writeOperatorFile() {
  if (!endpoint) return;
  writePrivate(OPERATOR_FILE, operatorData());
}
function logClientOutputs(force = false) {
  if (!endpoint) return;
  const key = `${baseUrl()}|${ID.uuid}|${ID.wsPath}|${ID.subToken}|${nodeName()}`;
  if (!force && key === clientOutputKey) return;
  clientOutputKey = key;
  console.log(`[client] Node name: ${nodeName()}`);
  console.log(`[client] VLESS URL: ${vlessUri()}`);
  console.log(`[client] Individual subscription: ${baseUrl()}/${ID.subToken}/sub`);
  console.log(`[client] Base64 subscription: ${baseUrl()}/${ID.subToken}/sub64`);
  console.log(`[client] Node info: ${baseUrl()}/${ID.subToken}/node`);
}

let registered = false;
let registryStatus = null;
let registryError = '';
let registryAttemptAt = null;
let registrySuccessAt = null;
let registryTimer = null;
let registerBusy = false;

function registryEligible() {
  return !!endpoint && endpointConfirmedThisBoot && proxyVerified;
}
function registryMode() { return REGISTRY_TOKEN ? 'bearer-token' : 'public-proof'; }

function requestJson(urlString, method, body, token = '', timeout = 10000) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(urlString); } catch (e) { return reject(e); }
    const lib = u.protocol === 'https:' ? https : http;
    const data = Buffer.from(JSON.stringify(body));
    const headers = {
      'content-type': 'application/json',
      'content-length': data.length,
      'user-agent': `container-test-hyehost/${VERSION}`
    };
    if (token) headers.authorization = `Bearer ${token}`;

    const req = lib.request({
      protocol: u.protocol,
      hostname: u.hostname,
      port: u.port || undefined,
      path: u.pathname + u.search,
      method,
      headers,
      timeout
    }, res => {
      let out = '';
      res.setEncoding('utf8');
      res.on('data', d => out += d);
      res.on('end', () => resolve({ status: res.statusCode, body: out }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end(data);
  });
}

function registryPayload() {
  return {
    kind: 'proxy',
    node_id: ID.nodeId,
    name: nodeName(),
    provider: PROVIDER,
    uri: vlessUri(),
    priority: 80,
    traffic: registryTraffic(),
    metadata: {
      location: countryState.code,
      platform: 'HYEHOST',
      egress_ip: countryState.egressIp,
      country_verified: countryState.verified
    }
  };
}

function queueRegistry(delay = 0) {
  if (!registryEligible()) return;
  if (registryTimer) clearTimeout(registryTimer);
  registryTimer = setTimeout(() => {
    registryTimer = null;
    registerNode().catch(() => {});
  }, delay);
  registryTimer.unref?.();
}

async function registerNode() {
  if (registerBusy || !registryEligible()) return false;
  registerBusy = true;
  registryAttemptAt = new Date().toISOString();
  registryError = '';

  try {
    await verifyCountry();
    let r;
    if (REGISTRY_TOKEN) {
      r = await requestJson(`${REGISTRY_URL}/api/v1/register`, 'POST', registryPayload(), REGISTRY_TOKEN);
    } else {
      const body = {
        ...registryPayload(),
        endpoint: baseUrl(),
        proof: REGISTRY_PROOF
      };
      r = await requestJson(`${REGISTRY_URL}/api/v1/register-public`, 'POST', body);
    }

    registryStatus = r.status;
    registered = r.status >= 200 && r.status < 300;
    if (!registered) throw new Error(`HTTP ${r.status}${r.body ? ': ' + r.body.slice(0, 200) : ''}`);
    registrySuccessAt = new Date().toISOString();
    console.log(`[registry] registered node_id=${ID.nodeId} name=${nodeName()} mode=${registryMode()}`);
    return true;
  } catch (e) {
    registered = false;
    registryError = e.message;
    console.warn(`[registry] register failed: ${e.message}`);
    return false;
  } finally {
    registerBusy = false;
  }
}

async function heartbeat() {
  if (!registryEligible()) return false;

  if (!countryState.verified) {
    try { await verifyCountry(true); } catch {}
  }

  if (!REGISTRY_TOKEN) {
    return registerNode();
  }

  try {
    const r = await requestJson(`${REGISTRY_URL}/api/v1/heartbeat`, 'POST', {
      node_id: ID.nodeId,
      status: 'online',
      traffic: registryTraffic(),
      metadata: {
        location: countryState.code,
        platform: 'HYEHOST',
        egress_ip: countryState.egressIp,
        country_verified: countryState.verified
      }
    }, REGISTRY_TOKEN);
    registryStatus = r.status;
    if (r.status < 200 || r.status >= 300) throw new Error(`HTTP ${r.status}`);
    registryError = '';
    if (!registered) return registerNode();
    return true;
  } catch (e) {
    registered = false;
    registryError = e.message;
    return registerNode();
  }
}

function send(res, status, body, type = 'text/plain; charset=utf-8') {
  res.writeHead(status, {
    'content-type': type,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'x-frame-options': 'DENY',
    'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
  });
  res.end(body);
}
function notFound(res) { send(res, 404, 'Not found\n'); }

const server = http.createServer((req, res) => {
  learnEndpoint(req);
  let u;
  try { u = new URL(req.url, 'http://local'); } catch { return notFound(res); }
  if (!['GET', 'HEAD'].includes(req.method)) return notFound(res);
  const head = req.method === 'HEAD';

  if (u.pathname === '/health') {
    const payload = {
      ok: true,
      service: 'hyehost-node',
      version: VERSION,
      provider: PROVIDER,
      node_id: ID.nodeId,
      node_name: nodeName(),
      listen: `${HOST}:${PORT}`,
      endpoint_ready: !!endpoint,
      endpoint_confirmed_this_boot: endpointConfirmedThisBoot,
      endpoint: endpoint ? baseUrl() : null,
      proxy_verified: proxyVerified,
      geo: {
        country: countryState.code,
        verified: countryState.verified,
        mismatch: countryState.mismatch,
        egress_ip: countryState.egressIp,
        checked_at: countryState.checkedAt
      },
      traffic: {
        upload_bytes: traffic.totals.uplink_bytes,
        download_bytes: traffic.totals.downlink_bytes,
        total_bytes: traffic.totals.total_bytes,
        connections: traffic.totals.connections,
        dashboard_mode: REGISTRY_TOKEN ? 'app-push' : 'public-proof-reregister'
      },
      registry_proof_sha256: REGISTRY_PROOF_SHA256,
      registry: {
        url: REGISTRY_URL,
        auth_mode: registryMode(),
        eligible: registryEligible(),
        registered,
        last_status: registryStatus,
        last_error: registryError || null,
        last_attempt_at: registryAttemptAt,
        last_success_at: registrySuccessAt
      }
    };
    return send(res, 200, head ? '' : JSON.stringify(payload), 'application/json; charset=utf-8');
  }

  const p = u.pathname.split('/').filter(Boolean);
  let action = null;
  let token = null;
  if (p.length === 2 && ['sub', 'sub64', 'node', 'traffic'].includes(p[1])) {
    token = p[0];
    action = p[1];
  } else if (p.length === 2 && p[0] === 'sub') {
    token = p[1];
    action = 'sub64';
  }

  if (action) {
    if (!equal(token, ID.subToken)) return notFound(res);
    if (!endpoint) return send(res, 503, 'Public endpoint not learned yet\n');
    const uri = vlessUri();
    if (action === 'sub') return send(res, 200, head ? '' : uri + '\n');
    if (action === 'sub64') return send(res, 200, head ? '' : Buffer.from(uri + '\n').toString('base64'));
    if (action === 'traffic') return send(res, 200, head ? '' : JSON.stringify(localTraffic(u.searchParams.get('days')), null, 2), 'application/json; charset=utf-8');
    return send(res, 200, head ? '' : JSON.stringify(operatorData(), null, 2), 'application/json; charset=utf-8');
  }

  if (u.pathname === '/') {
    let html = '<!doctype html><meta charset="utf-8"><title>Green Horizon</title><h1>Green Horizon</h1>';
    try { html = fs.readFileSync(HOME_FILE, 'utf8'); } catch {}
    return send(res, 200, head ? '' : html, 'text/html; charset=utf-8');
  }

  return notFound(res);
});

server.keepAliveTimeout = 65000;
server.headersTimeout = 70000;

function wsAccept(key) {
  return crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
}
function wsFrame(payload, opcode = 2) {
  payload = Buffer.from(payload);
  const n = payload.length;
  let h;
  if (n < 126) {
    h = Buffer.alloc(2);
    h[0] = 0x80 | opcode;
    h[1] = n;
  } else if (n <= 0xffff) {
    h = Buffer.alloc(4);
    h[0] = 0x80 | opcode;
    h[1] = 126;
    h.writeUInt16BE(n, 2);
  } else {
    h = Buffer.alloc(10);
    h[0] = 0x80 | opcode;
    h[1] = 127;
    h.writeBigUInt64BE(BigInt(n), 2);
  }
  return Buffer.concat([h, payload]);
}
function wsParser(onFrame, onClose) {
  let b = Buffer.alloc(0);
  return chunk => {
    b = Buffer.concat([b, chunk]);
    while (b.length >= 2) {
      const b0 = b[0], b1 = b[1];
      const opcode = b0 & 0x0f;
      const masked = !!(b1 & 0x80);
      let len = b1 & 0x7f;
      let off = 2;
      if (len === 126) {
        if (b.length < 4) return;
        len = b.readUInt16BE(2);
        off = 4;
      } else if (len === 127) {
        if (b.length < 10) return;
        const big = b.readBigUInt64BE(2);
        if (big > 8388608n) return onClose();
        len = Number(big);
        off = 10;
      }
      if (!masked || len > 8 * 1024 * 1024) return onClose();
      if (b.length < off + 4 + len) return;
      const mask = b.subarray(off, off + 4);
      off += 4;
      const payload = Buffer.from(b.subarray(off, off + len));
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
      b = b.subarray(off + len);
      if (opcode === 8) return onClose();
      onFrame(opcode, payload);
    }
  };
}
function parseVless(b) {
  if (!Buffer.isBuffer(b) || b.length < 24 || b[0] !== 0) return null;
  const id = [
    b.subarray(1, 5),
    b.subarray(5, 7),
    b.subarray(7, 9),
    b.subarray(9, 11),
    b.subarray(11, 17)
  ].map(x => x.toString('hex')).join('-');
  if (!equal(id.toLowerCase(), ID.uuid.toLowerCase())) return null;

  let p = 17;
  const optLen = b[p++];
  p += optLen;
  if (b.length < p + 4) return null;

  const command = b[p++];
  if (command !== 1) return null;

  const destPort = b.readUInt16BE(p);
  p += 2;
  const atyp = b[p++];
  let address;

  if (atyp === 1) {
    if (b.length < p + 4) return null;
    address = [...b.subarray(p, p + 4)].join('.');
    p += 4;
  } else if (atyp === 2) {
    if (b.length < p + 1) return null;
    const n = b[p++];
    if (b.length < p + n) return null;
    address = b.subarray(p, p + n).toString();
    p += n;
  } else if (atyp === 3) {
    if (b.length < p + 16) return null;
    const a = [];
    for (let i = 0; i < 8; i++) a.push(b.readUInt16BE(p + i * 2).toString(16));
    address = a.join(':');
    p += 16;
  } else {
    return null;
  }

  return { address, port: destPort, payload: b.subarray(p) };
}

server.on('upgrade', (req, socket, head) => {
  learnEndpoint(req);
  let pathname = '';
  try { pathname = new URL(req.url, 'http://local').pathname; } catch {}
  if (pathname !== ID.wsPath || clean(req.headers.upgrade).toLowerCase() !== 'websocket') {
    socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
    return;
  }
  const key = clean(req.headers['sec-websocket-key']);
  if (!key) return socket.destroy();

  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${wsAccept(key)}\r\n\r\n`
  );
  socket.setNoDelay(true);

  let remote = null;
  let initialized = false;
  let connected = false;
  let closed = false;
  const pending = [];

  const close = () => {
    if (closed) return;
    closed = true;
    try { remote?.destroy(); } catch {}
    try { socket.destroy(); } catch {}
  };
  const sendRemote = data => {
    if (!remote || remote.destroyed) return;
    if (!connected) {
      pending.push(Buffer.from(data));
      return;
    }
    addTraffic(data.length, 0, 0);
    remote.write(data);
  };

  const parse = wsParser((opcode, payload) => {
    if (opcode === 9) {
      try { socket.write(wsFrame(payload, 10)); } catch {}
      return;
    }
    if (opcode !== 2) return;

    if (!initialized) {
      initialized = true;
      const info = parseVless(payload);
      if (!info) return close();

      remote = net.connect({ host: info.address, port: info.port, timeout: 12000 });
      remote.setNoDelay(true);
      remote.once('connect', () => {
        connected = true;
        addTraffic(0, 0, 1);
        markProxyVerified();
        socket.write(wsFrame(Buffer.from([0, 0])));
        if (info.payload.length) sendRemote(info.payload);
        while (pending.length) sendRemote(pending.shift());
        logClientOutputs();
        queueRegistry(250);
      });
      remote.on('data', d => {
        addTraffic(0, d.length, 0);
        if (!socket.destroyed) {
          try { socket.write(wsFrame(d)); } catch { close(); }
        }
      });
      remote.on('timeout', close);
      remote.on('error', close);
      remote.on('close', close);
    } else {
      sendRemote(payload);
    }
  }, close);

  if (head?.length) parse(head);
  socket.on('data', parse);
  socket.on('error', close);
  socket.on('close', () => { try { remote?.destroy(); } catch {} });
});

server.listen(PORT, HOST, () => {
  console.log(`[ready] hyehost-node v${VERSION} listening on ${HOST}:${PORT} (http/ws)`);
  console.log(`[ready] Node.js ${process.version}; state=${STATE_DIR}`);
  console.log(`[ready] node_id=${ID.nodeId} registry=${REGISTRY_URL} mode=${registryMode()}`);
  console.log('[ready] root path is a static cover page; UUID/WS path are not exposed there');

  if (endpoint) {
    console.log(`[ready] saved/override public endpoint ${baseUrl()}`);
    logClientOutputs(true);
  } else {
    console.log('[ready] waiting for the first real public request to learn HYEHOST NAT host:port');
  }

  if (proxyVerified) {
    console.log('[verify] a previous successful VLESS TCP validation is stored; this boot still waits for a real public endpoint confirmation before registry updates');
  } else {
    console.log('[verify] registry will wait until the first successful VLESS TCP connection');
  }

  verifyCountry().catch(e => console.warn(`[geo] initial verification failed: ${e.message}`));
  setInterval(() => verifyCountry(true).catch(() => {}), GEO_RETRY_MS).unref();
  setInterval(() => heartbeat().catch(() => {}), HEARTBEAT_MS).unref();
});

for (const sig of ['SIGTERM', 'SIGINT']) {
  process.once(sig, () => {
    try { flushTraffic(); } catch {}
    process.exit(0);
  });
}
