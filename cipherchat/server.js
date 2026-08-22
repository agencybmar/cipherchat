'use strict';

require('dotenv').config();

const crypto = require('crypto');
const http = require('http');
const path = require('path');

const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { Server } = require('socket.io');

const { Store } = require('./lib/store');

const PORT = Number.parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const TOKEN_PEPPER = process.env.TOKEN_PEPPER || 'cipherchat-development-only-pepper';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

if (IS_PRODUCTION && TOKEN_PEPPER.length < 32) {
  throw new Error('TOKEN_PEPPER must contain at least 32 characters in production.');
}

if (!IS_PRODUCTION && !process.env.TOKEN_PEPPER) {
  console.warn('Warning: using the development TOKEN_PEPPER. Set TOKEN_PEPPER before deployment.');
}

const store = new Store(DATA_DIR);
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  maxHttpBufferSize: 200000,
  serveClient: true
});

const onlineSockets = new Map();
const claimedSockets = new Map();

if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(
  helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        connectSrc: ["'self'", 'ws:', 'wss:'],
        fontSrc: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        imgSrc: ["'self'", 'data:'],
        mediaSrc: ["'self'", 'blob:'],
        objectSrc: ["'none'"],
        scriptSrc: ["'self'"],
        scriptSrcAttr: ["'none'"],
        styleSrc: ["'self'", "'unsafe-inline'"]
      }
    },
    referrerPolicy: { policy: 'no-referrer' }
  })
);
app.use((request, response, next) => {
  response.set('Permissions-Policy', 'camera=(self), microphone=(self), geolocation=()');
  next();
});
app.use(express.json({ limit: '24kb' }));
app.use((error, request, response, next) => {
  if (error && error.type === 'entity.parse.failed') {
    return response.status(400).json({ error: 'Invalid JSON request body.' });
  }
  if (error && error.type === 'entity.too.large') {
    return response.status(413).json({ error: 'Request body is too large.' });
  }
  return next(error);
});
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 180,
    standardHeaders: true,
    legacyHeaders: false
  })
);

function isCode(value) {
  return typeof value === 'string' && /^\d{4}$/.test(value);
}

function hashToken(token) {
  return crypto.createHmac('sha256', TOKEN_PEPPER).update(token).digest('hex');
}

function parseBearerToken(request) {
  const header = request.get('authorization') || '';
  const match = /^Bearer\s+([A-Za-z0-9_-]{20,200})$/.exec(header);
  return match ? match[1] : null;
}

function requireAuth(request, response, next) {
  const code = request.get('x-user-code');
  const token = parseBearerToken(request);

  if (!isCode(code) || !token || !store.authenticate(code, hashToken(token))) {
    return response.status(401).json({ error: 'Invalid session.' });
  }

  request.userCode = code;
  return next();
}

function isPublicJwk(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  if (value.kty !== 'EC' || value.crv !== 'P-256') return false;
  if (typeof value.x !== 'string' || typeof value.y !== 'string') return false;
  if (!/^[A-Za-z0-9_-]{40,60}$/.test(value.x)) return false;
  if (!/^[A-Za-z0-9_-]{40,60}$/.test(value.y)) return false;
  if (Object.prototype.hasOwnProperty.call(value, 'd')) return false;
  return true;
}

function samePublicJwk(left, right) {
  return Boolean(
    left &&
    right &&
    left.kty === right.kty &&
    left.crv === right.crv &&
    left.x === right.x &&
    left.y === right.y
  );
}

function getIceServers() {
  const stunUrls = (process.env.STUN_URLS || 'stun:stun.l.google.com:19302')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  const iceServers = stunUrls.length > 0 ? [{ urls: stunUrls }] : [];
  const turnUrls = (process.env.TURN_URLS || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);

  if (turnUrls.length > 0) {
    iceServers.push({
      urls: turnUrls,
      username: process.env.TURN_USERNAME || '',
      credential: process.env.TURN_CREDENTIAL || ''
    });
  }

  return iceServers;
}

const availabilityLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many availability checks. Try again later.' }
});

const registrationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many registration attempts. Try again later.' }
});

app.get('/api/health', (request, response) => {
  response.json({ ok: true });
});

app.get('/api/config', requireAuth, (request, response) => {
  response.set('Cache-Control', 'no-store');
  response.json({ iceServers: getIceServers() });
});

app.get('/api/availability/:code', availabilityLimiter, (request, response) => {
  const { code } = request.params;
  if (!isCode(code)) return response.status(400).json({ error: 'Use exactly four digits.' });
  return response.json({ code, available: !store.hasUser(code) });
});

app.post('/api/register', registrationLimiter, (request, response) => {
  const code = request.body && request.body.code;
  if (!isCode(code)) {
    return response.status(400).json({ error: 'Choose an ID containing exactly four digits.' });
  }

  if (store.hasUser(code)) {
    return response.status(409).json({ error: 'That ID has already been reserved.' });
  }

  const token = crypto.randomBytes(32).toString('base64url');
  const created = store.createUser(code, hashToken(token));
  if (!created) {
    return response.status(409).json({ error: 'That ID has already been reserved.' });
  }

  response.set('Cache-Control', 'no-store');
  return response.status(201).json({ code, token });
});

app.post('/api/session', requireAuth, (request, response) => {
  const user = store.getUser(request.userCode);
  response.set('Cache-Control', 'no-store');
  return response.json({
    ok: true,
    code: request.userCode,
    hasPublicKey: Boolean(user && user.publicKey)
  });
});

app.put('/api/profile/key', requireAuth, (request, response) => {
  const publicKey = request.body && request.body.publicKey;
  if (!isPublicJwk(publicKey)) {
    return response.status(400).json({ error: 'Invalid P-256 public key.' });
  }

  const normalizedKey = {
    kty: 'EC',
    crv: 'P-256',
    x: publicKey.x,
    y: publicKey.y,
    ext: true
  };
  const currentUser = store.getUser(request.userCode);
  if (currentUser && currentUser.publicKey && !samePublicJwk(currentUser.publicKey, normalizedKey)) {
    return response.status(409).json({
      error: 'This ID already has a different encryption key. Restore its original account backup.'
    });
  }

  if (!currentUser || !currentUser.publicKey) store.setPublicKey(request.userCode, normalizedKey);
  return response.json({ ok: true });
});

app.get('/api/users/:code', requireAuth, (request, response) => {
  const { code } = request.params;
  if (!isCode(code)) return response.status(400).json({ error: 'Invalid ID.' });

  const user = store.getUser(code);
  if (!user) return response.status(404).json({ error: 'No user has reserved that ID.' });
  if (!user.publicKey) {
    return response.status(409).json({ error: 'That user has not finished setting up encryption.' });
  }

  response.set('Cache-Control', 'no-store');
  return response.json({
    code,
    publicKey: user.publicKey,
    online: onlineSockets.has(code)
  });
});

app.get('/api/messages/:peer', requireAuth, (request, response) => {
  const peer = request.params.peer;
  if (!isCode(peer)) return response.status(400).json({ error: 'Invalid ID.' });
  if (!store.hasUser(peer)) return response.status(404).json({ error: 'Unknown ID.' });

  response.set('Cache-Control', 'no-store');
  return response.json({
    messages: store.getConversation(request.userCode, peer, 2000)
  });
});

app.use('/api', (request, response) => {
  response.status(404).json({ error: 'API endpoint not found.' });
});

app.get('/favicon.ico', (request, response) => response.status(204).end());

app.use(express.static(path.join(__dirname, 'public'), {
  etag: true,
  maxAge: IS_PRODUCTION ? '1h' : 0
}));

app.get('*', (request, response) => {
  response.sendFile(path.join(__dirname, 'public', 'index.html'));
});

function socketRateAllowed(socket, key, limit, windowMs) {
  const now = Date.now();
  if (!socket.data.rateBuckets) socket.data.rateBuckets = new Map();
  const existing = socket.data.rateBuckets.get(key) || [];
  const recent = existing.filter((timestamp) => now - timestamp < windowMs);
  if (recent.length >= limit) {
    socket.data.rateBuckets.set(key, recent);
    return false;
  }
  recent.push(now);
  socket.data.rateBuckets.set(key, recent);
  return true;
}

function ackWith(ack, value) {
  if (typeof ack === 'function') ack(value);
}

function relayTo(code, eventName, payload) {
  const socketId = onlineSockets.get(code);
  if (!socketId) return false;
  io.to(socketId).emit(eventName, payload);
  return true;
}

function notifyPresence(code, online) {
  for (const socket of io.sockets.sockets.values()) {
    const subscriptions = socket.data.presenceSubscriptions;
    if (subscriptions && subscriptions.has(code)) {
      socket.emit('presence:update', { code, online });
    }
  }
}

function isUuid(value) {
  return typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value);
}

function isBase64(value, maxLength) {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maxLength &&
    /^[A-Za-z0-9+/]+={0,2}$/.test(value)
  );
}

function isEncryptedSignal(signal, maxCiphertextLength) {
  return Boolean(
    signal &&
    typeof signal === 'object' &&
    signal.version === 1 &&
    isBase64(signal.iv, 64) &&
    isBase64(signal.ciphertext, maxCiphertextLength)
  );
}

io.use((socket, next) => {
  const auth = socket.handshake.auth || {};
  const code = auth.code;
  const token = auth.token;

  if (!isCode(code) || typeof token !== 'string' || !store.authenticate(code, hashToken(token))) {
    return next(new Error('Invalid session.'));
  }

  if (claimedSockets.has(code)) {
    return next(new Error('This ID is already active in another tab or device.'));
  }

  claimedSockets.set(code, socket.id);
  socket.conn.once('close', () => {
    if (claimedSockets.get(code) === socket.id) claimedSockets.delete(code);
  });
  socket.data.userCode = code;
  socket.data.presenceSubscriptions = new Set();
  return next();
});

io.on('connection', (socket) => {
  const code = socket.data.userCode;
  onlineSockets.set(code, socket.id);
  notifyPresence(code, true);

  const pendingMessages = store.getUndelivered(code, 2000);
  if (pendingMessages.length > 0) {
    socket.emit('message:sync', { messages: pendingMessages });
  }

  socket.on('presence:subscribe', (payload, ack) => {
    const requested = payload && Array.isArray(payload.codes) ? payload.codes : [];
    const codes = [...new Set(requested.filter(isCode))].slice(0, 100);
    socket.data.presenceSubscriptions = new Set(codes);

    const statuses = {};
    for (const targetCode of codes) statuses[targetCode] = onlineSockets.has(targetCode);
    ackWith(ack, { ok: true, statuses });
  });

  socket.on('message:send', (payload, ack) => {
    if (!socketRateAllowed(socket, 'message', 60, 60 * 1000)) {
      return ackWith(ack, { ok: false, error: 'You are sending messages too quickly.' });
    }

    const to = payload && payload.to;
    const id = payload && payload.id;
    const ts = payload && payload.ts;
    const iv = payload && payload.iv;
    const ciphertext = payload && payload.ciphertext;
    const version = payload && payload.version;

    if (!isCode(to) || to === code || !store.hasUser(to)) {
      return ackWith(ack, { ok: false, error: 'Invalid recipient.' });
    }
    if (!isUuid(id)) return ackWith(ack, { ok: false, error: 'Invalid message ID.' });
    if (!Number.isSafeInteger(ts) || Math.abs(Date.now() - ts) > 7 * 24 * 60 * 60 * 1000) {
      return ackWith(ack, { ok: false, error: 'Invalid message timestamp.' });
    }
    if (!isBase64(iv, 64) || !isBase64(ciphertext, 24000) || version !== 1) {
      return ackWith(ack, { ok: false, error: 'Invalid encrypted message.' });
    }

    const message = {
      id,
      from: code,
      to,
      ts,
      receivedAt: Date.now(),
      deliveredAt: null,
      iv,
      ciphertext,
      version: 1
    };

    const inserted = store.addMessage(message);
    if (inserted) relayTo(to, 'message:new', message);
    return ackWith(ack, { ok: true, duplicate: !inserted, receivedAt: message.receivedAt });
  });

  socket.on('message:received', (payload) => {
    if (!socketRateAllowed(socket, 'message-received', 120, 60 * 1000)) return;
    const requested = payload && Array.isArray(payload.ids) ? payload.ids : [payload && payload.id];
    const messageIds = [...new Set(requested.filter(isUuid))].slice(0, 100);
    if (messageIds.length === 0) return;
    const deliveredMessages = store.markDeliveredBatch(messageIds, code);
    for (const delivered of deliveredMessages) {
      relayTo(delivered.from, 'message:delivered', {
        id: delivered.id,
        by: code,
        deliveredAt: delivered.deliveredAt
      });
    }
  });

  socket.on('chat:typing', (payload) => {
    if (!socketRateAllowed(socket, 'typing', 12, 10 * 1000)) return;
    const to = payload && payload.to;
    if (!isCode(to) || to === code || !store.hasUser(to)) return;
    relayTo(to, 'chat:typing', { from: code, typing: Boolean(payload.typing) });
  });

  socket.on('call:offer', (payload, ack) => {
    if (!socketRateAllowed(socket, 'call-offer', 5, 60 * 1000)) {
      return ackWith(ack, { ok: false, error: 'Too many call attempts.' });
    }

    const to = payload && payload.to;
    const callId = payload && payload.callId;
    const signal = payload && payload.signal;
    if (!isCode(to) || to === code || !store.hasUser(to) || !isUuid(callId)) {
      return ackWith(ack, { ok: false, error: 'Invalid call.' });
    }
    if (!isEncryptedSignal(signal, 140000)) {
      return ackWith(ack, { ok: false, error: 'Invalid encrypted call offer.' });
    }
    if (!onlineSockets.has(to)) {
      return ackWith(ack, { ok: false, error: 'That user is offline.' });
    }

    relayTo(to, 'call:incoming', { from: code, callId, signal });
    return ackWith(ack, { ok: true });
  });

  socket.on('call:answer', (payload, ack) => {
    if (!socketRateAllowed(socket, 'call-answer', 10, 60 * 1000)) {
      return ackWith(ack, { ok: false, error: 'Too many call responses.' });
    }

    const to = payload && payload.to;
    const callId = payload && payload.callId;
    const signal = payload && payload.signal;
    if (!isCode(to) || to === code || !store.hasUser(to) || !isUuid(callId) || !isEncryptedSignal(signal, 140000)) {
      return ackWith(ack, { ok: false, error: 'Invalid encrypted call answer.' });
    }

    const relayed = relayTo(to, 'call:answer', { from: code, callId, signal });
    return ackWith(ack, relayed ? { ok: true } : { ok: false, error: 'Caller is offline.' });
  });

  socket.on('call:ice', (payload) => {
    if (!socketRateAllowed(socket, 'call-ice', 120, 60 * 1000)) return;
    const to = payload && payload.to;
    const callId = payload && payload.callId;
    const signal = payload && payload.signal;
    if (!isCode(to) || to === code || !store.hasUser(to) || !isUuid(callId) || !isEncryptedSignal(signal, 16000)) return;

    relayTo(to, 'call:ice', {
      from: code,
      callId,
      signal
    });
  });

  socket.on('call:decline', (payload) => {
    if (!socketRateAllowed(socket, 'call-decline', 20, 60 * 1000)) return;
    const to = payload && payload.to;
    const callId = payload && payload.callId;
    if (!isCode(to) || to === code || !store.hasUser(to) || !isUuid(callId)) return;
    relayTo(to, 'call:decline', { from: code, callId, reason: 'declined' });
  });

  socket.on('call:end', (payload) => {
    if (!socketRateAllowed(socket, 'call-end', 30, 60 * 1000)) return;
    const to = payload && payload.to;
    const callId = payload && payload.callId;
    if (!isCode(to) || to === code || !store.hasUser(to) || !isUuid(callId)) return;
    relayTo(to, 'call:end', { from: code, callId });
  });

  socket.on('disconnect', () => {
    if (claimedSockets.get(code) === socket.id) claimedSockets.delete(code);
    if (onlineSockets.get(code) === socket.id) {
      onlineSockets.delete(code);
      notifyPresence(code, false);
    }
  });
});

server.listen(PORT, HOST, () => {
  console.log(`CipherChat is running at http://${HOST}:${PORT}`);
});
