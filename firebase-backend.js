'use strict';

(() => {
  const cfg = window.CIPHERCHAT_FIREBASE_CONFIG || {};
  const configured = cfg.apiKey && !String(cfg.apiKey).includes('PASTE_') && cfg.databaseURL && !String(cfg.databaseURL).includes('PASTE_');
  let app = null;
  let auth = null;
  let db = null;
  const DOMAIN = 'cipherchat.invalid';

  class BackendError extends Error {
    constructor(message, status = 500) {
      super(message);
      this.name = 'BackendError';
      this.status = status;
    }
  }

  function requireConfigured() {
    if (!configured) {
      throw new BackendError('Firebase is not configured yet. Open firebase-config.js and paste your Firebase web app config.', 503);
    }
    if (!app) {
      app = firebase.initializeApp(cfg);
      auth = firebase.auth();
      db = firebase.database();
    }
  }

  function isCode(value) { return /^\d{4}$/.test(String(value || '')); }
  function emailFor(code) { return `${code}@${DOMAIN}`; }
  function codeFromUser(user) {
    const email = user && user.email;
    const match = typeof email === 'string' ? email.match(/^(\d{4})@cipherchat\.invalid$/) : null;
    return match ? match[1] : null;
  }
  function randomToken() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  }
  function pair(a, b) { return [a, b].sort(); }
  function conversationRef(a, b) {
    const [left, right] = pair(a, b);
    return db.ref(`conversations/${left}/${right}`);
  }
  function normalizeFirebaseError(error) {
    const code = error && error.code;
    if (code === 'auth/email-already-in-use') return new BackendError('That ID has already been reserved.', 409);
    if (code === 'auth/wrong-password' || code === 'auth/user-not-found' || code === 'auth/invalid-credential' || code === 'auth/invalid-login-credentials') {
      return new BackendError('Invalid session. Restore the correct account backup for this ID.', 401);
    }
    if (code === 'auth/too-many-requests') return new BackendError('Too many attempts. Try again later.', 429);
    if (code === 'PERMISSION_DENIED') return new BackendError('Firebase rejected this request. Check that the supplied database rules are installed.', 403);
    return new BackendError((error && error.message) || 'Firebase request failed.', 500);
  }

  async function signInSession(session) {
    requireConfigured();
    if (!session || !isCode(session.code) || typeof session.token !== 'string' || session.token.length < 6) {
      throw new BackendError('Invalid session.', 401);
    }
    const currentCode = codeFromUser(auth.currentUser);
    if (currentCode === session.code) return auth.currentUser;
    try {
      return (await auth.signInWithEmailAndPassword(emailFor(session.code), session.token)).user;
    } catch (error) {
      throw normalizeFirebaseError(error);
    }
  }

  async function apiRequest(path, options = {}) {
    requireConfigured();
    const method = options.method || 'GET';
    const session = options.session;
    const body = options.body || {};

    try {
      let match;
      if ((match = path.match(/^\/api\/availability\/(\d{4})$/)) && method === 'GET') {
        // Firebase intentionally prevents unauthenticated email-enumeration APIs.
        // We use the public profile registry for the friendly availability hint;
        // final uniqueness is enforced atomically by Firebase Authentication.
        const snap = await db.ref(`reserved/${match[1]}`).once('value');
        return { code: match[1], available: !snap.exists() };
      }

      if (path === '/api/register' && method === 'POST') {
        const code = body.code;
        if (!isCode(code)) throw new BackendError('Choose an ID containing exactly four digits.', 400);
        const token = randomToken();
        try {
          await auth.createUserWithEmailAndPassword(emailFor(code), token);
        } catch (error) {
          throw normalizeFirebaseError(error);
        }
        await db.ref().update({
          [`users/${code}`]: { createdAt: firebase.database.ServerValue.TIMESTAMP },
          [`reserved/${code}`]: true
        });
        return { code, token };
      }

      await signInSession(session);
      const ownCode = session.code;

      if (path === '/api/session' && method === 'POST') {
        const snap = await db.ref(`users/${ownCode}`).once('value');
        if (!snap.exists()) throw new BackendError('This ID profile is missing.', 404);
        return { ok: true, code: ownCode, hasPublicKey: Boolean(snap.child('publicKey').val()) };
      }

      if (path === '/api/profile/key' && method === 'PUT') {
        const publicKey = body.publicKey;
        const ref = db.ref(`users/${ownCode}/publicKey`);
        const snap = await ref.once('value');
        if (snap.exists()) {
          const existing = snap.val();
          if (!existing || existing.x !== publicKey.x || existing.y !== publicKey.y) {
            throw new BackendError('This ID already has a different encryption key. Restore its original account backup.', 409);
          }
        } else {
          await ref.set(publicKey);
        }
        return { ok: true };
      }

      if ((match = path.match(/^\/api\/users\/(\d{4})$/)) && method === 'GET') {
        const code = match[1];
        const [userSnap, presenceSnap] = await Promise.all([
          db.ref(`users/${code}`).once('value'),
          db.ref(`presence/${code}`).once('value')
        ]);
        if (!userSnap.exists()) throw new BackendError('No user has reserved that ID.', 404);
        const user = userSnap.val() || {};
        if (!user.publicKey) throw new BackendError('That user has not finished setting up encryption.', 409);
        const p = presenceSnap.val() || {};
        return { code, publicKey: user.publicKey, online: Boolean(p.online) && Date.now() - Number(p.lastSeen || 0) < 45000 };
      }

      if ((match = path.match(/^\/api\/messages\/(\d{4})$/)) && method === 'GET') {
        const peer = match[1];
        const peerSnap = await db.ref(`users/${peer}`).once('value');
        if (!peerSnap.exists()) throw new BackendError('Unknown ID.', 404);
        const snap = await conversationRef(ownCode, peer).limitToLast(2000).once('value');
        const messages = [];
        snap.forEach((child) => messages.push(child.val()));
        messages.sort((a, b) => Number(a.ts || 0) - Number(b.ts || 0));
        return { messages };
      }

      if (path === '/api/config' && method === 'GET') {
        return { iceServers: [{ urls: ['stun:stun.l.google.com:19302'] }] };
      }

      throw new BackendError('API endpoint not found.', 404);
    } catch (error) {
      if (error instanceof BackendError) throw error;
      throw normalizeFirebaseError(error);
    }
  }

  class FirebaseSocket {
    constructor(options = {}) {
      this.options = options;
      this.handlers = new Map();
      this.connected = false;
      this.code = options.auth && options.auth.code;
      this.token = options.auth && options.auth.token;
      this.tabId = crypto.randomUUID();
      this.listeners = [];
      this.presenceListeners = [];
      this.heartbeat = null;
      this.inboxCache = new Map();
      setTimeout(() => this.connect(), 0);
    }
    on(name, fn) {
      if (!this.handlers.has(name)) this.handlers.set(name, new Set());
      this.handlers.get(name).add(fn);
      return this;
    }
    fire(name, payload) {
      const set = this.handlers.get(name);
      if (set) for (const fn of [...set]) { try { fn(payload); } catch (e) { console.error(e); } }
    }
    async connect() {
      try {
        await signInSession({ code: this.code, token: this.token });
        const sessionRef = db.ref(`sessions/${this.code}`);
        const now = Date.now();
        const result = await sessionRef.transaction((current) => {
          if (!current || !current.tabId || now - Number(current.lastSeen || 0) > 45000 || current.tabId === this.tabId) {
            return { tabId: this.tabId, lastSeen: now };
          }
          return;
        });
        if (!result.committed || !result.snapshot.val() || result.snapshot.val().tabId !== this.tabId) {
          throw new BackendError('This ID is already active in another tab or device.', 409);
        }
        sessionRef.onDisconnect().remove();
        const presenceRef = db.ref(`presence/${this.code}`);
        await presenceRef.set({ online: true, lastSeen: firebase.database.ServerValue.TIMESTAMP, tabId: this.tabId });
        presenceRef.onDisconnect().set({ online: false, lastSeen: firebase.database.ServerValue.TIMESTAMP });
        this.heartbeat = setInterval(async () => {
          if (!this.connected) return;
          try {
            await sessionRef.update({ lastSeen: Date.now() });
            await presenceRef.update({ online: true, lastSeen: firebase.database.ServerValue.TIMESTAMP, tabId: this.tabId });
          } catch (_) {}
        }, 15000);
        this.connected = true;
        this.listenInbox();
        this.listenEvents();
        this.fire('connect');
      } catch (error) {
        this.connected = false;
        this.fire('connect_error', error instanceof BackendError ? error : normalizeFirebaseError(error));
      }
    }
    addListener(ref, event, fn) {
      ref.on(event, fn);
      this.listeners.push(() => ref.off(event, fn));
    }
    listenInbox() {
      const ref = db.ref(`inbox/${this.code}`);
      this.addListener(ref, 'child_added', (snap) => {
        const value = snap.val();
        if (!value) return;
        this.inboxCache.set(snap.key, value);
        this.fire('message:new', value);
      });
    }
    listenEvents() {
      const ref = db.ref(`events/${this.code}`);
      this.addListener(ref, 'child_added', async (snap) => {
        const event = snap.val();
        if (!event || !event.type || !event.payload) { snap.ref.remove().catch(() => {}); return; }
        this.fire(event.type, event.payload);
        snap.ref.remove().catch(() => {});
      });
    }
    async pushEvent(to, type, payload) {
      const ref = db.ref(`events/${to}`).push();
      await ref.set({ from: this.code, type, payload, ts: firebase.database.ServerValue.TIMESTAMP });
    }
    emit(name, payload = {}, ack) {
      this.performEmit(name, payload).then((response) => {
        if (typeof ack === 'function') ack(response);
      }).catch((error) => {
        if (typeof ack === 'function') ack({ ok: false, error: error.message || 'Request failed.' });
      });
      return this;
    }
    timeout(ms) {
      return {
        emit: (name, payload = {}, ack) => {
          let settled = false;
          const timer = setTimeout(() => {
            if (settled) return;
            settled = true;
            if (typeof ack === 'function') ack(new Error('timeout'));
          }, ms);
          this.performEmit(name, payload).then((response) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (typeof ack === 'function') ack(null, response);
          }).catch((error) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (typeof ack === 'function') ack(null, { ok: false, error: error.message || 'Request failed.' });
          });
        }
      };
    }
    async performEmit(name, payload) {
      if (!this.connected) throw new BackendError('Not connected.', 0);
      if (name === 'presence:subscribe') {
        for (const off of this.presenceListeners.splice(0)) off();
        const statuses = {};
        const codes = [...new Set((payload.codes || []).filter(isCode))].slice(0, 100);
        await Promise.all(codes.map(async (code) => {
          const ref = db.ref(`presence/${code}`);
          const snap = await ref.once('value');
          const value = snap.val() || {};
          statuses[code] = Boolean(value.online) && Date.now() - Number(value.lastSeen || 0) < 45000;
          const fn = (s) => {
            const p = s.val() || {};
            this.fire('presence:update', { code, online: Boolean(p.online) && Date.now() - Number(p.lastSeen || 0) < 45000 });
          };
          ref.on('value', fn);
          this.presenceListeners.push(() => ref.off('value', fn));
        }));
        return { ok: true, statuses };
      }
      if (name === 'message:send') {
        const to = payload.to;
        if (!isCode(to) || to === this.code) throw new BackendError('Invalid recipient.', 400);
        const exists = await db.ref(`users/${to}`).once('value');
        if (!exists.exists()) throw new BackendError('Invalid recipient.', 404);
        const message = {
          id: payload.id, from: this.code, to, ts: payload.ts,
          receivedAt: Date.now(), deliveredAt: null,
          iv: payload.iv, ciphertext: payload.ciphertext, version: 1
        };
        const [a, b] = pair(this.code, to);
        const updates = {};
        updates[`conversations/${a}/${b}/${message.id}`] = message;
        updates[`inbox/${to}/${message.id}`] = message;
        await db.ref().update(updates);
        return { ok: true, receivedAt: message.receivedAt };
      }
      if (name === 'message:received') {
        const ids = [...new Set((payload.ids || [payload.id]).filter(Boolean))].slice(0, 100);
        for (const id of ids) {
          let message = this.inboxCache.get(id);
          if (!message) message = (await db.ref(`inbox/${this.code}/${id}`).once('value')).val();
          if (!message || message.to !== this.code) continue;
          const deliveredAt = Date.now();
          const [a, b] = pair(message.from, message.to);
          const updates = {};
          updates[`conversations/${a}/${b}/${id}/deliveredAt`] = deliveredAt;
          updates[`inbox/${this.code}/${id}`] = null;
          await db.ref().update(updates);
          this.inboxCache.delete(id);
          await this.pushEvent(message.from, 'message:delivered', { id, by: this.code, deliveredAt });
        }
        return { ok: true };
      }
      if (name === 'chat:typing') {
        if (isCode(payload.to) && payload.to !== this.code) await this.pushEvent(payload.to, 'chat:typing', { from: this.code, typing: Boolean(payload.typing) });
        return { ok: true };
      }
      if (['call:offer','call:answer','call:ice','call:decline','call:end'].includes(name)) {
        const to = payload.to;
        if (!isCode(to) || to === this.code) throw new BackendError('Invalid call recipient.', 400);
        if (name === 'call:offer') {
          const p = (await db.ref(`presence/${to}`).once('value')).val() || {};
          if (!p.online || Date.now() - Number(p.lastSeen || 0) >= 45000) return { ok: false, error: 'That user is offline.' };
        }
        const eventName = name === 'call:offer' ? 'call:incoming' : name;
        const out = { from: this.code, callId: payload.callId };
        if (payload.signal) out.signal = payload.signal;
        if (name === 'call:decline') out.reason = 'declined';
        await this.pushEvent(to, eventName, out);
        return { ok: true };
      }
      return { ok: false, error: `Unsupported real-time event: ${name}` };
    }
    async disconnect() {
      if (!configured || !db) return;
      this.connected = false;
      clearInterval(this.heartbeat);
      for (const off of this.listeners.splice(0)) off();
      for (const off of this.presenceListeners.splice(0)) off();
      try {
        const sessionRef = db.ref(`sessions/${this.code}`);
        const snap = await sessionRef.once('value');
        if (snap.val() && snap.val().tabId === this.tabId) await sessionRef.remove();
        await db.ref(`presence/${this.code}`).set({ online: false, lastSeen: firebase.database.ServerValue.TIMESTAMP });
      } catch (_) {}
      this.fire('disconnect');
    }
  }

  window.CipherBackend = { apiRequest, BackendError, configured };
  window.io = (options) => new FirebaseSocket(options);
})();
