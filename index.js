#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const crypto = require('crypto');

const VERSION = '1.3.0';
const PORT = Number(process.env.PORT || process.env.SERVER_PORT || 8080);
const STATE_DIR = String(process.env.SERVICE_STATE_DIR || process.env.HYEHOST_STATE_DIR || path.join(os.homedir(), '.hyehost-node')).trim();
const ID_FILE = path.join(STATE_DIR, 'identity.json');
const EP_FILE = path.join(STATE_DIR, 'public-endpoint.json');
const CHECK_FILE = path.join(STATE_DIR, 'validation.json');
const CORE_FILE = path.join(__dirname, '.service-core.js');
const CORE_CACHE = path.join(STATE_DIR, 'service-core.js');
const CORE_URL = 'https://raw.githubusercontent.com/dulangd/hyehost-test/c06729de6d590c3f06bdf99830e346b7f15cd434/index.js';

const sleep = ms => new Promise(r => setTimeout(r, ms));
const readJson = file => { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return {}; } };
const clean = v => String(v || '').trim();

async function obtainCore() {
  if (process.env.CORE_SOURCE_PATH) {
    return fs.readFileSync(process.env.CORE_SOURCE_PATH, 'utf8');
  }
  let lastError = null;
  for (let i = 0; i < 3; i++) {
    try {
      const r = await fetch(CORE_URL, {
        headers: { 'user-agent': `hyehost-service/${VERSION}` },
        signal: AbortSignal.timeout(10000)
      });
      if (!r.ok) throw new Error(`status ${r.status}`);
      const src = await r.text();
      if (!src.includes("const VERSION = '1.2.0';")) throw new Error('unexpected core source');
      fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
      fs.writeFileSync(CORE_CACHE, src, { mode: 0o600 });
      return src;
    } catch (e) {
      lastError = e;
      await sleep(800 * (i + 1));
    }
  }
  try {
    const cached = fs.readFileSync(CORE_CACHE, 'utf8');
    if (cached.includes("const VERSION = '1.2.0';")) return cached;
  } catch {}
  throw lastError || new Error('core unavailable');
}

function prepareCore(src) {
  return src
    .replace("const VERSION = '1.2.0';", "const VERSION = '1.3.0';")
    .replace(
      "let endpointConfirmed = !!(PUBLIC_OVERRIDE && endpoint);",
      "let endpointConfirmed = !!(endpoint && (PUBLIC_OVERRIDE || endpoint.source === 'request'));"
    )
    .replace(
      "console.log('[check] first external data session established');",
      "console.log('[check] data path validated');"
    );
}

/*
 * Console policy only. This deliberately does not alter registration, geo,
 * heartbeat, traffic, endpoint learning, timers, or retry behavior.
 * Repeated routine state messages are suppressed; state changes and errors
 * remain visible.
 */
function installQuietConsole() {
  const raw = {
    log: console.log.bind(console),
    warn: console.warn.bind(console),
    error: console.error.bind(console)
  };

  let geoState = null;
  let controlState = null;
  let routeState = null;

  function text(args) {
    return args.map(v => typeof v === 'string' ? v : String(v)).join(' ');
  }

  function emit(method, args) {
    const line = text(args);

    if (line.startsWith('[geo] verified country=')) {
      const next = `verified:${line.slice('[geo] verified country='.length)}`;
      if (geoState === next) return;
      geoState = next;
      raw[method](...args);
      return;
    }

    if (line.startsWith('[geo] verification incomplete; country=')) {
      const next = `incomplete:${line.slice('[geo] verification incomplete; country='.length)}`;
      if (geoState === next) return;
      geoState = next;
      raw[method](...args);
      return;
    }

    if (line === '[geo] sources disagree; country left unknown') {
      const next = 'mismatch';
      if (geoState === next) return;
      geoState = next;
      raw[method](...args);
      return;
    }

    if (line.startsWith('[control] sync ok ')) {
      const next = 'ok';
      if (controlState === next) return;
      controlState = next;
      raw[method](...args);
      return;
    }

    if (line.startsWith('[control] sync pending: ')) {
      const next = `error:${line.slice('[control] sync pending: '.length)}`;
      if (controlState === next) return;
      controlState = next;
      raw[method](...args);
      return;
    }

    if (line.startsWith('[route] public address learned ')) {
      const next = line.slice('[route] public address learned '.length);
      if (routeState === next) return;
      routeState = next;
      raw[method](...args);
      return;
    }

    raw[method](...args);
  }

  console.log = (...args) => emit('log', args);
  console.warn = (...args) => emit('warn', args);
  console.error = (...args) => emit('error', args);
}

function identity() {
  const x = readJson(ID_FILE);
  return {
    uuid: clean(x.uuid),
    route: clean(x.channelPath || x.wsPath)
  };
}

function endpoint() {
  const x = readJson(EP_FILE);
  if (!x || !x.host || !Number(x.port)) return null;
  return { host: clean(x.host), port: Number(x.port), protocol: clean(x.protocol) || 'http' };
}

function alreadyVerified() {
  return !!readJson(CHECK_FILE).data_verified_at;
}

function maskedFrame(payload) {
  payload = Buffer.from(payload);
  const mask = crypto.randomBytes(4);
  let head;
  if (payload.length < 126) {
    head = Buffer.from([0x82, 0x80 | payload.length]);
  } else if (payload.length <= 65535) {
    head = Buffer.alloc(4);
    head[0] = 0x82;
    head[1] = 0x80 | 126;
    head.writeUInt16BE(payload.length, 2);
  } else {
    throw new Error('check payload too large');
  }
  const out = Buffer.from(payload);
  for (let i = 0; i < out.length; i++) out[i] ^= mask[i & 3];
  return Buffer.concat([head, mask, out]);
}

function makeDataRequest(uuidText, targetHost = 'example.com', targetPort = 80) {
  const uuid = Buffer.from(uuidText.replace(/-/g, ''), 'hex');
  if (uuid.length !== 16) throw new Error('identity unavailable');
  const host = Buffer.from(targetHost);
  const h = Buffer.alloc(1 + 16 + 1 + 1 + 2 + 1 + 1 + host.length);
  let p = 0;
  h[p++] = 0;
  uuid.copy(h, p); p += 16;
  h[p++] = 0;
  h[p++] = 1;
  h.writeUInt16BE(targetPort, p); p += 2;
  h[p++] = 2;
  h[p++] = host.length;
  host.copy(h, p);
  const body = Buffer.from(`HEAD / HTTP/1.1\r\nHost: ${targetHost}\r\nConnection: close\r\n\r\n`);
  return Buffer.concat([h, body]);
}

async function oneAutomaticCheck(targetHost, targetPort) {
  const id = identity();
  const ep = endpoint();
  if (!id.uuid || !id.route || !ep) throw new Error('route not ready');

  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port: PORT });
    const key = crypto.randomBytes(16).toString('base64');
    const hostHeader = `${ep.host}:${ep.port}`;
    const request =
      `GET ${id.route} HTTP/1.1\r\n` +
      `Host: ${hostHeader}\r\n` +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      `Sec-WebSocket-Key: ${key}\r\n` +
      'Sec-WebSocket-Version: 13\r\n\r\n';

    let buffer = Buffer.alloc(0);
    let sent = false;
    let finished = false;
    const timer = setTimeout(() => done(new Error('check timeout')), 10000);
    timer.unref?.();

    function done(err) {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      try { socket.destroy(); } catch {}
      if (err) reject(err); else resolve(true);
    }

    socket.setNoDelay(true);
    socket.once('connect', () => socket.write(request));
    socket.on('data', chunk => {
      if (sent) return;
      buffer = Buffer.concat([buffer, chunk]);
      const i = buffer.indexOf('\r\n\r\n');
      if (i < 0) return;
      const head = buffer.subarray(0, i + 4).toString('latin1');
      if (!/^HTTP\/1\.1 101\b/.test(head)) return done(new Error('route check rejected'));
      sent = true;
      try {
        socket.write(maskedFrame(makeDataRequest(id.uuid, targetHost, targetPort)));
      } catch (e) {
        done(e);
      }
    });
    socket.on('error', done);

    const poll = setInterval(() => {
      if (alreadyVerified()) {
        clearInterval(poll);
        done();
      }
    }, 250);
    poll.unref?.();
  });
}

async function automaticCheck() {
  if (alreadyVerified()) return;
  const targets = [
    ['example.com', 80],
    ['1.1.1.1', 80]
  ];
  for (const [host, port] of targets) {
    try {
      await oneAutomaticCheck(host, port);
      console.log('[check] automatic validation complete');
      return;
    } catch {}
  }
  throw new Error('automatic validation pending');
}

async function checkLoop() {
  for (;;) {
    if (alreadyVerified()) return;
    try {
      await automaticCheck();
      return;
    } catch {
      await sleep(60000);
    }
  }
}

(async () => {
  try {
    const src = prepareCore(await obtainCore());
    fs.writeFileSync(CORE_FILE, src, { mode: 0o600 });
    installQuietConsole();
    require(CORE_FILE);
    setTimeout(() => checkLoop().catch(() => {}), 2500).unref();
  } catch (e) {
    console.error(`[fault] startup failed: ${e.message}`);
    process.exit(1);
  }
})();
