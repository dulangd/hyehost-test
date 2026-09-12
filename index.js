#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const net = require('net');
const crypto = require('crypto');

const VERSION = '1.2.0';
const PROVIDER = 'hyehost';
const HOST = '0.0.0.0';

const clean = v => String(v || '').trim();
const validPort = v => {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 && n <= 65535 ? n : 0;
};
const rand = (n = 18) => crypto.randomBytes(n).toString('base64url');
const validUuid = v => /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(clean(v));
const validCountry = v => /^[A-Z]{2}$/.test(clean(v).toUpperCase()) ? clean(v).toUpperCase() : null;
const fmtHost = v => net.isIP(v) === 6 ? `[${v}]` : v;

function same(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return {}; }
}
function writePrivate(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  const body = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  fs.writeFileSync(tmp, body, { mode: 0o600 });
  fs.renameSync(tmp, file);
  try { fs.chmodSync(file, 0o600); } catch {}
}
function normalizePath(v) {
  const s = clean(v).replace(/^\/+|\/+$/g, '');
  return '/' + (s || `c-${rand(10)}`);
}
function stripCountry(v) {
  const s = clean(v) || 'HYEHOST-01';
  return s.replace(/^[A-Z]{2}-/i, '') || 'HYEHOST-01';
}

const PORT = validPort(process.env.PORT) || validPort(process.env.SERVER_PORT) || 8080;
const STATE_DIR = clean(process.env.SERVICE_STATE_DIR || process.env.HYEHOST_STATE_DIR) || path.join(os.homedir(), '.hyehost-node');
const ID_FILE = path.join(STATE_DIR, 'identity.json');
const EP_FILE = path.join(STATE_DIR, 'public-endpoint.json');
const PROOF_FILE = path.join(STATE_DIR, 'control-proof.txt');
const COUNTER_FILE = path.join(STATE_DIR, 'counters.json');
const CHECK_FILE = path.join(STATE_DIR, 'validation.json');
const HOME_FILE = path.join(__dirname, 'index.html');

const CONTROL_URL = clean(process.env.CONTROL_URL || process.env.REGISTRY_URL || 'https://subscription-server-v2-production.up.railway.app').replace(/\/+$/, '');
const CONTROL_TOKEN = clean(process.env.CONTROL_TOKEN || process.env.REGISTRY_TOKEN);
const PUBLIC_OVERRIDE = clean(process.env.PUBLIC_ENDPOINT);
const HEARTBEAT_MS = Math.max(60_000, Number(process.env.HEARTBEAT_MS || 600000) || 600000);
const GEO_RETRY_MS = Math.max(60_000, Number(process.env.GEO_RETRY_MS || 300000) || 300000);
const RETENTION_DAYS = Math.max(1, Math.min(3650, Number(process.env.RETENTION_DAYS || process.env.TRAFFIC_RETENTION_DAYS || 90) || 90));

function loadIdentity() {
  const old = readJson(ID_FILE);
  const requested = clean(process.env.CLIENT_ID || process.env.UUID);
  const item = {
    identity_version: 3,
    uuid: validUuid(requested) ? requested : (validUuid(old.uuid) ? old.uuid : crypto.randomUUID()),
    channelPath: normalizePath(process.env.CHANNEL_PATH || process.env.WS_PATH || old.channelPath || old.wsPath),
    accessToken: clean(process.env.ACCESS_TOKEN || process.env.SUB_TOKEN) || old.accessToken || old.subToken || rand(24),
    instanceId: clean(process.env.INSTANCE_ID || process.env.NODE_ID) || old.instanceId || old.nodeId || `hyehost-${rand(10).toLowerCase()}`,
    displayBase: stripCountry(process.env.DISPLAY_NAME || process.env.NODE_NAME || old.displayBase || old.nodeNameBase || 'HYEHOST-01')
  };
  writePrivate(ID_FILE, item);
  return item;
}
function loadProof() {
  const fromEnv = clean(process.env.CONTROL_PROOF || process.env.REGISTRY_PROOF);
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
const CONTROL_PROOF = loadProof();

let validation = readJson(CHECK_FILE);
if (!validation || typeof validation !== 'object') validation = {};
let dataVerified = !!validation.data_verified_at;
function markDataVerified() {
  if (dataVerified) return;
  dataVerified = true;
  validation = { ...validation, data_verified_at: new Date().toISOString() };
  writePrivate(CHECK_FILE, validation);
  console.log('[check] first external data session established');
}

function blankCounters() {
  return {
    version: 1,
    instance_id: ID.instanceId,
    tracking_since: new Date().toISOString(),
    totals: { sent_bytes: 0, received_bytes: 0, total_bytes: 0, sessions: 0 },
    days: {},
    updated_at: null
  };
}
let counters = readJson(COUNTER_FILE);
if (counters.version !== 1) counters = blankCounters();
counters.instance_id = ID.instanceId;
counters.tracking_since = counters.tracking_since || new Date().toISOString();
counters.totals = counters.totals || {};
for (const k of ['sent_bytes', 'received_bytes', 'total_bytes', 'sessions']) {
  counters.totals[k] = Math.max(0, Number(counters.totals[k]) || 0);
}
counters.days = counters.days && typeof counters.days === 'object' ? counters.days : {};
let flushTimer = null;

function utcDay() { return new Date().toISOString().slice(0, 10); }
function flushCounters() {
  if (flushTimer) clearTimeout(flushTimer);
  flushTimer = null;
  const cutoff = new Date();
  cutoff.setUTCDate(cutoff.getUTCDate() - RETENTION_DAYS + 1);
  const min = cutoff.toISOString().slice(0, 10);
  for (const d of Object.keys(counters.days)) if (d < min) delete counters.days[d];
  counters.updated_at = new Date().toISOString();
  writePrivate(COUNTER_FILE, counters);
}
function addCounters(sent = 0, received = 0, sessions = 0) {
  sent = Math.max(0, Number(sent) || 0);
  received = Math.max(0, Number(received) || 0);
  sessions = Math.max(0, Number(sessions) || 0);
  if (!sent && !received && !sessions) return;
  const day = utcDay();
  if (!counters.days[day]) counters.days[day] = { sent_bytes: 0, received_bytes: 0, total_bytes: 0, sessions: 0 };
  const d = counters.days[day];
  d.sent_bytes += sent;
  d.received_bytes += received;
  d.total_bytes += sent + received;
  d.sessions += sessions;
  counters.totals.sent_bytes += sent;
  counters.totals.received_bytes += received;
  counters.totals.total_bytes += sent + received;
  counters.totals.sessions += sessions;
  if (!flushTimer) {
    flushTimer = setTimeout(flushCounters, 1500);
    flushTimer.unref?.();
  }
}
function controlCounters() {
  return {
    version: 1,
    name: displayName(),
    tracking_since: counters.tracking_since,
    updated_at: counters.updated_at || new Date().toISOString(),
    upload_bytes: counters.totals.sent_bytes,
    download_bytes: counters.totals.received_bytes,
    total_bytes: counters.totals.total_bytes,
    connections: counters.totals.sessions
  };
}

let country = { code: 'XX', verified: false, mismatch: false, egressIp: null, checkedAt: null };
let geoBusy = null;
let geoChecked = false;

async function fetchText(url, timeout = 6000) {
  const r = await fetch(url, {
    headers: { 'user-agent': `hyehost-service/${VERSION}` },
    signal: AbortSignal.timeout(timeout)
  });
  if (!r.ok) throw new Error(`status ${r.status}`);
  return r.text();
}
async function fetchJson(url, timeout = 6000) {
  const r = await fetch(url, {
    headers: { 'user-agent': `hyehost-service/${VERSION}` },
    signal: AbortSignal.timeout(timeout)
  });
  if (!r.ok) throw new Error(`status ${r.status}`);
  return r.json();
}
async function verifyCountry(force = false) {
  if (!force && geoChecked) return country;
  if (geoBusy) return geoBusy;
  geoBusy = (async () => {
    let a = null, b = null;
    try {
      const text = await fetchText('https://www.cloudflare.com/cdn-cgi/trace');
      const kv = Object.fromEntries(text.split(/\r?\n/).map(x => x.split('=')).filter(x => x.length === 2));
      a = { code: validCountry(kv.loc), ip: clean(kv.ip) || null };
    } catch {}
    try {
      const j = await fetchJson('https://ipinfo.io/json');
      b = { code: validCountry(j.country), ip: clean(j.ip) || null };
    } catch {}
    const codes = [a?.code, b?.code].filter(Boolean);
    if (codes.length >= 2 && codes.every(x => x === codes[0])) {
      country = { code: codes[0], verified: true, mismatch: false, egressIp: a?.ip || b?.ip || null, checkedAt: new Date().toISOString() };
      console.log(`[geo] verified country=${country.code}`);
    } else if (codes.length >= 2) {
      country = { code: 'XX', verified: false, mismatch: true, egressIp: a?.ip || b?.ip || null, checkedAt: new Date().toISOString() };
      console.warn('[geo] sources disagree; country left unknown');
    } else {
      country = { code: codes[0] || 'XX', verified: false, mismatch: false, egressIp: a?.ip || b?.ip || null, checkedAt: new Date().toISOString() };
      console.warn(`[geo] verification incomplete; country=${country.code}`);
    }
    geoChecked = true;
    if (controlEligible()) queueControl(250);
    return country;
  })().finally(() => { geoBusy = null; });
  return geoBusy;
}
function displayName() { return `${country.code || 'XX'}-${ID.displayBase}`; }

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
function privateV4(host) {
  if (net.isIP(host) !== 4) return false;
  const p = host.split('.').map(Number);
  return p[0] === 10 || p[0] === 127 || (p[0] === 169 && p[1] === 254) ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168);
}
function publicHost(host) {
  const h = clean(host).toLowerCase();
  return !!h && !['localhost', '::1', '0.0.0.0'].includes(h) && !privateV4(h);
}
let endpoint = parseEndpoint(PUBLIC_OVERRIDE) || readJson(EP_FILE);
if (!endpoint?.host || !validPort(endpoint.port)) endpoint = null;
let endpointConfirmed = !!(PUBLIC_OVERRIDE && endpoint);

function baseUrl(ep = endpoint) {
  if (!ep) return null;
  const normal = (ep.protocol === 'https' && ep.port === 443) || (ep.protocol === 'http' && ep.port === 80);
  return `${ep.protocol}://${fmtHost(ep.host)}${normal ? '' : ':' + ep.port}`;
}
function clientLink(ep = endpoint) {
  if (!ep) return null;
  const secure = ep.protocol === 'https';
  const q = new URLSearchParams({
    encryption: 'none',
    security: secure ? 'tls' : 'none',
    type: 'ws',
    host: ep.host,
    path: ID.channelPath
  });
  if (secure) {
    q.set('sni', ep.host);
    q.set('alpn', 'http/1.1');
  }
  return `vless://${ID.uuid}@${fmtHost(ep.host)}:${ep.port}?${q.toString()}#${encodeURIComponent(displayName())}`;
}
function learnEndpoint(req) {
  if (PUBLIC_OVERRIDE) {
    endpointConfirmed = true;
    return;
  }
  const fproto = clean(String(req.headers['x-forwarded-proto'] || '').split(',')[0]).toLowerCase();
  const fhost = clean(String(req.headers['x-forwarded-host'] || '').split(',')[0]);
  const raw = fhost || clean(req.headers.host);
  if (!raw) return;

  let u;
  try { u = new URL(`http://${raw}`); } catch { return; }
  if (!publicHost(u.hostname)) return;

  let protocol = req.socket.encrypted ? 'https' : 'http';
  if (fproto === 'https') protocol = 'https';
  else if (fproto === 'http') protocol = 'http';

  const fport = validPort(String(req.headers['x-forwarded-port'] || '').split(',')[0]);
  const port = fport || validPort(u.port) || (protocol === 'https' ? 443 : 80);
  const next = { protocol, host: u.hostname, port, source: 'request', learnedAt: new Date().toISOString() };
  const changed = !endpoint || endpoint.protocol !== next.protocol || endpoint.host !== next.host || endpoint.port !== next.port;

  endpointConfirmed = true;
  if (!changed) return;

  endpoint = next;
  writePrivate(EP_FILE, endpoint);
  console.log(`[route] public address learned ${baseUrl()}`);

  setTimeout(() => verifyCountry().catch(() => {}), 1500).unref();
  if (controlEligible()) queueControl(250);
}

function accessData() {
  if (!endpoint) return null;
  return {
    version: VERSION,
    provider: PROVIDER,
    instance_id: ID.instanceId,
    name: displayName(),
    endpoint,
    country: { code: country.code, verified: country.verified, egress_ip: country.egressIp, checked_at: country.checkedAt },
    client_uri: clientLink(),
    access_a: `${baseUrl()}/${ID.accessToken}/sub`,
    access_b: `${baseUrl()}/${ID.accessToken}/sub64`,
    info: `${baseUrl()}/${ID.accessToken}/node`,
    counters: `${baseUrl()}/${ID.accessToken}/traffic`
  };
}

let registered = false;
let controlStatus = null;
let controlError = '';
let controlAttemptAt = null;
let controlSuccessAt = null;
let controlBusy = false;
let controlTimer = null;

function controlMode() { return CONTROL_TOKEN ? 'credential' : 'proof'; }
function controlEligible() { return !!endpoint && endpointConfirmed && dataVerified && geoChecked; }

async function postJson(url, body, token = '', timeout = 8000) {
  const headers = { 'content-type': 'application/json', 'user-agent': `hyehost-service/${VERSION}` };
  if (token) headers.authorization = `Bearer ${token}`;
  const r = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeout)
  });
  const text = await r.text().catch(() => '');
  return { status: r.status, body: text };
}
function controlPayload() {
  return {
    kind: 'proxy',
    node_id: ID.instanceId,
    name: displayName(),
    provider: PROVIDER,
    uri: clientLink(),
    priority: 80,
    traffic: controlCounters(),
    metadata: {
      location: country.code,
      platform: 'HYEHOST',
      egress_ip: country.egressIp,
      country_verified: country.verified
    }
  };
}
function queueControl(delay = 0) {
  if (!controlEligible()) return;
  if (controlTimer) clearTimeout(controlTimer);
  controlTimer = setTimeout(() => {
    controlTimer = null;
    syncControl().catch(() => {});
  }, delay);
  controlTimer.unref?.();
}
async function syncControl() {
  if (controlBusy || !controlEligible()) return false;
  controlBusy = true;
  controlAttemptAt = new Date().toISOString();
  controlError = '';
  try {
    let r;
    if (CONTROL_TOKEN) {
      r = await postJson(`${CONTROL_URL}/api/v1/register`, controlPayload(), CONTROL_TOKEN);
    } else {
      r = await postJson(`${CONTROL_URL}/api/v1/register-public`, {
        ...controlPayload(),
        endpoint: baseUrl(),
        proof: CONTROL_PROOF
      });
    }
    controlStatus = r.status;
    registered = r.status >= 200 && r.status < 300;
    if (!registered) throw new Error(`status ${r.status}`);
    controlSuccessAt = new Date().toISOString();
    console.log(`[control] sync ok instance=${ID.instanceId} name=${displayName()} mode=${controlMode()}`);
    return true;
  } catch (e) {
    registered = false;
    controlError = e.message;
    console.warn(`[control] sync pending: ${e.message}`);
    return false;
  } finally {
    controlBusy = false;
  }
}
async function heartbeat() {
  if (!controlEligible()) return false;
  if (!CONTROL_TOKEN) return syncControl();
  try {
    const r = await postJson(`${CONTROL_URL}/api/v1/heartbeat`, {
      node_id: ID.instanceId,
      status: 'online',
      traffic: controlCounters(),
      metadata: {
        location: country.code,
        platform: 'HYEHOST',
        egress_ip: country.egressIp,
        country_verified: country.verified
      }
    }, CONTROL_TOKEN);
    controlStatus = r.status;
    if (r.status < 200 || r.status >= 300) throw new Error(`status ${r.status}`);
    controlError = '';
    registered = true;
    return true;
  } catch (e) {
    registered = false;
    controlError = e.message;
    return syncControl();
  }
}

function send(res, status, body, type = 'text/plain; charset=utf-8') {
  res.writeHead(status, {
    'content-type': type,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'x-frame-options': 'DENY'
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
    const mem = process.memoryUsage();
    const body = {
      ok: true,
      service: 'hyehost-service',
      version: VERSION,
      instance_id: ID.instanceId,
      name: displayName(),
      runtime: process.version,
      uptime_s: Math.floor(process.uptime()),
      rss_mb: Math.round(mem.rss / 1024 / 1024),
      heap_mb: Math.round(mem.heapUsed / 1024 / 1024),
      endpoint_ready: !!endpoint,
      endpoint_confirmed_this_boot: endpointConfirmed,
      endpoint: endpoint ? baseUrl() : null,
      data_verified: dataVerified,
      geo: {
        country: country.code,
        verified: country.verified,
        mismatch: country.mismatch,
        address: country.egressIp,
        checked_at: country.checkedAt
      },
      counters: {
        sent_bytes: counters.totals.sent_bytes,
        received_bytes: counters.totals.received_bytes,
        total_bytes: counters.totals.total_bytes,
        sessions: counters.totals.sessions
      },
      control: {
        url: CONTROL_URL,
        mode: controlMode(),
        eligible: controlEligible(),
        synced: registered,
        last_status: controlStatus,
        last_error: controlError || null,
        last_attempt_at: controlAttemptAt,
        last_success_at: controlSuccessAt
      }
    };
    return send(res, 200, head ? '' : JSON.stringify(body), 'application/json; charset=utf-8');
  }

  const parts = u.pathname.split('/').filter(Boolean);
  let action = null, token = null;
  if (parts.length === 2 && ['sub', 'sub64', 'node', 'traffic'].includes(parts[1])) {
    token = parts[0];
    action = parts[1];
  } else if (parts.length === 2 && parts[0] === 'sub') {
    token = parts[1];
    action = 'sub64';
  }

  if (action) {
    if (!same(token, ID.accessToken)) return notFound(res);
    if (!endpoint) return send(res, 503, 'Service route not ready\n');
    const link = clientLink();
    if (action === 'sub') return send(res, 200, head ? '' : link + '\n');
    if (action === 'sub64') return send(res, 200, head ? '' : Buffer.from(link + '\n').toString('base64'));
    if (action === 'traffic') {
      return send(res, 200, head ? '' : JSON.stringify({
        version: 1,
        provider: PROVIDER,
        instance_id: ID.instanceId,
        retention_days: RETENTION_DAYS,
        totals: counters.totals,
        days: counters.days,
        updated_at: counters.updated_at
      }), 'application/json; charset=utf-8');
    }
    return send(res, 200, head ? '' : JSON.stringify(accessData()), 'application/json; charset=utf-8');
  }

  if (u.pathname === '/') {
    let html = '<!doctype html><meta charset="utf-8"><title>Green Horizon</title><h1>Green Horizon</h1>';
    try { html = fs.readFileSync(HOME_FILE, 'utf8'); } catch {}
    return send(res, 200, head ? '' : html, 'text/html; charset=utf-8');
  }

  return notFound(res);
});

server.keepAliveTimeout = 30_000;
server.headersTimeout = 35_000;
server.requestTimeout = 30_000;

function acceptKey(key) {
  return crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
}
function frame(payload, opcode = 2) {
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
function parser(onFrame, onClose) {
  let b = Buffer.alloc(0);
  const MAX = 2 * 1024 * 1024;
  return chunk => {
    if (b.length + chunk.length > MAX) return onClose();
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
        if (big > BigInt(MAX)) return onClose();
        len = Number(big);
        off = 10;
      }
      if (!masked || len > MAX) return onClose();
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
function parseClientHeader(b) {
  if (!Buffer.isBuffer(b) || b.length < 24 || b[0] !== 0) return null;
  const id = [
    b.subarray(1, 5), b.subarray(5, 7), b.subarray(7, 9),
    b.subarray(9, 11), b.subarray(11, 17)
  ].map(x => x.toString('hex')).join('-');
  if (!same(id.toLowerCase(), ID.uuid.toLowerCase())) return null;

  let p = 17;
  const opt = b[p++];
  p += opt;
  if (b.length < p + 4 || b[p++] !== 1) return null;

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
  if (pathname !== ID.channelPath || clean(req.headers.upgrade).toLowerCase() !== 'websocket') {
    socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
    return;
  }

  const key = clean(req.headers['sec-websocket-key']);
  if (!key) return socket.destroy();

  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + acceptKey(key) + '\r\n\r\n'
  );
  socket.setNoDelay(true);

  let remote = null;
  let initialized = false;
  let connected = false;
  let closed = false;
  const pending = [];
  let pendingBytes = 0;
  const PENDING_MAX = 1024 * 1024;

  const close = () => {
    if (closed) return;
    closed = true;
    try { remote?.destroy(); } catch {}
    try { socket.destroy(); } catch {}
  };
  const sendRemote = data => {
    if (!remote || remote.destroyed) return;
    if (!connected) {
      const copy = Buffer.from(data);
      pendingBytes += copy.length;
      if (pendingBytes > PENDING_MAX) return close();
      pending.push(copy);
      return;
    }
    addCounters(data.length, 0, 0);
    remote.write(data);
  };

  const parse = parser((opcode, payload) => {
    if (opcode === 9) {
      try { socket.write(frame(payload, 10)); } catch {}
      return;
    }
    if (opcode !== 2) return;

    if (!initialized) {
      initialized = true;
      const info = parseClientHeader(payload);
      if (!info) return close();

      remote = net.connect({ host: info.address, port: info.port, timeout: 10_000 });
      remote.setNoDelay(true);
      remote.once('connect', () => {
        connected = true;
        addCounters(0, 0, 1);
        markDataVerified();
        try { socket.write(frame(Buffer.from([0, 0]))); } catch { return close(); }
        if (info.payload.length) sendRemote(info.payload);
        while (pending.length) {
          const item = pending.shift();
          pendingBytes -= item.length;
          sendRemote(item);
        }
        if (!geoChecked) verifyCountry().catch(() => {});
        else queueControl(250);
      });
      remote.on('data', d => {
        addCounters(0, d.length, 0);
        if (!socket.destroyed) {
          try { socket.write(frame(d)); } catch { close(); }
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

server.on('error', e => {
  console.error(`[fault] server error: ${e.message}`);
  process.exit(1);
});
process.on('uncaughtException', e => {
  console.error(`[fault] uncaught: ${e?.stack || e}`);
  process.exit(1);
});
process.on('unhandledRejection', e => {
  console.error(`[fault] rejected: ${e?.stack || e}`);
  process.exit(1);
});
process.on('beforeExit', code => {
  console.error(`[fault] beforeExit code=${code}`);
});

server.listen(PORT, HOST, () => {
  const mem = Math.round(process.memoryUsage().rss / 1024 / 1024);
  console.log(`[ready] hyehost-service v${VERSION} address=${HOST}:${PORT}`);
  console.log(`[ready] runtime=${process.version} workspace=${__dirname} state=${STATE_DIR} rss=${mem}MB`);
  console.log(`[ready] instance=${ID.instanceId} control=${CONTROL_URL} mode=${controlMode()}`);
  console.log('[ready] public page enabled; private access values are not printed');
  if (endpoint) console.log(`[route] saved public address ${baseUrl()}`);
  else console.log('[route] waiting for first public request');
  console.log(dataVerified ? '[check] previous data validation found; waiting for current route confirmation' : '[check] waiting for first valid data session');

  setInterval(() => {
    if (endpointConfirmed) verifyCountry(true).catch(() => {});
  }, GEO_RETRY_MS).unref();

  setInterval(() => heartbeat().catch(() => {}), HEARTBEAT_MS).unref();
});

for (const sig of ['SIGTERM', 'SIGINT']) {
  process.once(sig, () => {
    console.log(`[stop] received ${sig}`);
    try { flushCounters(); } catch {}
    process.exit(0);
  });
}
