'use strict';

(() => {
  const cfg = window.CIPHERCHAT_FIREBASE_CONFIG || {};
  const configured = Boolean(
    cfg.apiKey && !String(cfg.apiKey).includes('PASTE_') &&
    cfg.authDomain && !String(cfg.authDomain).includes('PASTE_') &&
    cfg.databaseURL && !String(cfg.databaseURL).includes('PASTE_')
  );

  let app = null;
  let auth = null;
  let db = null;

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
      auth.useDeviceLanguage();
    }
  }

  function isCode(value) { return /^\d{4}$/.test(String(value || '')); }
  function pair(a, b) { return [a, b].sort(); }
  function conversationRef(a, b) {
    const [left, right] = pair(a, b);
    return db.ref(`conversations/${left}/${right}`);
  }

  function normalizeFirebaseError(error) {
    const code = error && error.code;
    if (code === 'auth/popup-closed-by-user') return new BackendError('Google sign-in was cancelled.', 400);
    if (code === 'auth/popup-blocked') return new BackendError('Your browser blocked the Google sign-in window. Allow pop-ups and try again.', 400);
    if (code === 'auth/unauthorized-domain') return new BackendError('This website is not authorized in Firebase Authentication. Add your GitHub Pages domain under Authentication > Settings > Authorized domains.', 403);
    if (code === 'auth/operation-not-allowed') return new BackendError('Google sign-in is disabled for this Firebase project. In Firebase, open Authentication > Sign-in method > Google, enable it, and save.', 403);
    if (code === 'PERMISSION_DENIED' || code === 'permission-denied') return new BackendError('Firebase rejected this request. Check that the Google-account database rules are published.', 403);
    return new BackendError((error && error.message) || 'Firebase request failed.', 500);
  }

  async function waitForAuth() {
    requireConfigured();
    return new Promise((resolve) => {
      const off = auth.onAuthStateChanged((user) => {
        off();
        resolve(user || null);
      }, () => resolve(null));
    });
  }

  async function signInWithGoogle() {
    requireConfigured();
    try {
      const provider = new firebase.auth.GoogleAuthProvider();
      provider.setCustomParameters({ prompt: 'select_account' });
      const result = await auth.signInWithPopup(provider);
      return publicUser(result.user);
    } catch (error) {
      throw normalizeFirebaseError(error);
    }
  }

  async function signOut() {
    requireConfigured();
    await auth.signOut();
  }

  function publicUser(user) {
    if (!user) return null;
    return {
      uid: user.uid,
      displayName: user.displayName || '',
      email: user.email || '',
      photoURL: user.photoURL || ''
    };
  }

  function isGoogleUser(user) {
    return Boolean(
      user &&
      Array.isArray(user.providerData) &&
      user.providerData.some((provider) => provider && provider.providerId === 'google.com')
    );
  }

  async function getAccount() {
    requireConfigured();
    const user = auth.currentUser || await waitForAuth();
    if (!user) return { user: null, code: null };

    // Remove any legacy Email/Password or anonymous session left by an older
    // CipherChat build so the account cannot bypass Google identity.
    if (!isGoogleUser(user)) {
      await auth.signOut();
      return { user: null, code: null };
    }

    const snap = await db.ref(`accounts/${user.uid}`).once('value');
    const account = snap.val() || {};
    return { user: publicUser(user), code: isCode(account.code) ? account.code : null };
  }

  async function requireGoogleUser() {
    requireConfigured();
    const user = auth.currentUser || await waitForAuth();
    if (!user || !isGoogleUser(user)) {
      if (user) await auth.signOut();
      throw new BackendError('Sign in with Google first.', 401);
    }
    return user;
  }

  async function signInSession(session) {
    const user = await requireGoogleUser();
    if (!session || !isCode(session.code)) throw new BackendError('Invalid account session.', 401);
    const accountSnap = await db.ref(`accounts/${user.uid}/code`).once('value');
    if (accountSnap.val() !== session.code) {
      throw new BackendError('This four-digit ID belongs to a different Google account.', 403);
    }
    return user;
  }

  function isPresenceOnline(snapshot) {
    let online = false;
    const now = Date.now();
    snapshot.forEach((child) => {
      const value = child.val() || {};
      if (value.online && now - Number(value.lastSeen || 0) < 60000) online = true;
    });
    return online;
  }

  async function reserveCode(code, user) {
    const reservedRef = db.ref(`reserved/${code}`);
    const result = await reservedRef.transaction((current) => {
      if (current === null) {
        return { uid: user.uid, createdAt: firebase.database.ServerValue.TIMESTAMP };
      }
      if (current && current.uid === user.uid) return current;
      return;
    });
    if (!result.committed || !result.snapshot.val() || result.snapshot.val().uid !== user.uid) {
      throw new BackendError('That ID has already been reserved.', 409);
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
        await requireGoogleUser();
        const snap = await db.ref(`reserved/${match[1]}`).once('value');
        return { code: match[1], available: !snap.exists() };
      }

      if (path === '/api/register' && method === 'POST') {
        const user = await requireGoogleUser();
        const code = body.code;
        if (!isCode(code)) throw new BackendError('Choose an ID containing exactly four digits.', 400);

        const existingAccount = await db.ref(`accounts/${user.uid}/code`).once('value');
        if (existingAccount.exists()) {
          const existingCode = existingAccount.val();
          if (existingCode === code) return { code };
          throw new BackendError(`Your Google account already owns ID #${existingCode}.`, 409);
        }

        await reserveCode(code, user);
        const profile = {
          ownerUid: user.uid,
          displayName: user.displayName || '',
          photoURL: user.photoURL || '',
          createdAt: firebase.database.ServerValue.TIMESTAMP
        };
        await db.ref().update({
          [`accounts/${user.uid}`]: { code, createdAt: firebase.database.ServerValue.TIMESTAMP },
          [`users/${code}`]: profile
        });
        return { code };
      }

      const currentUser = await signInSession(session);
      const ownCode = session.code;

      if (path === '/api/session' && method === 'POST') {
        const snap = await db.ref(`users/${ownCode}`).once('value');
        if (!snap.exists()) throw new BackendError('This ID profile is missing.', 404);
        const ownerUid = snap.child('ownerUid').val();
        if (ownerUid !== currentUser.uid) throw new BackendError('This ID is linked to a different Google account.', 403);
        return { ok: true, code: ownCode, hasPublicKey: Boolean(snap.child('publicKey').val()) };
      }

      if (path === '/api/profile/key' && method === 'PUT') {
        const publicKey = body.publicKey;
        const ref = db.ref(`users/${ownCode}/publicKey`);
        const snap = await ref.once('value');
        if (snap.exists()) {
          const existing = snap.val();
          if (!existing || existing.x !== publicKey.x || existing.y !== publicKey.y) {
            throw new BackendError('This account already has a different encryption key. Restore the account backup from your original device.', 409);
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
        const profile = userSnap.val() || {};
        if (!profile.publicKey) throw new BackendError('That user has not finished setting up encryption.', 409);
        return {
          code,
          publicKey: profile.publicKey,
          online: isPresenceOnline(presenceSnap),
          displayName: profile.displayName || '',
          photoURL: profile.photoURL || ''
        };
      }

      if (path === '/api/contacts' && method === 'GET') {
        const snap = await db.ref(`contacts/${ownCode}`).once('value');
        const contacts = [];
        snap.forEach((child) => {
          if (isCode(child.key)) {
            const value = child.val() || {};
            contacts.push({
              code: child.key,
              addedAt: Number(value.addedAt || 0),
              lastActivity: Number(value.lastActivity || 0),
              unread: 0
            });
          }
        });
        return { contacts };
      }

      if (path === '/api/contacts' && method === 'PUT') {
        const incoming = Array.isArray(body.contacts) ? body.contacts : [];
        const next = {};
        for (const contact of incoming.slice(0, 100)) {
          if (!contact || !isCode(contact.code) || contact.code === ownCode) continue;
          next[contact.code] = {
            addedAt: Number(contact.addedAt || Date.now()),
            lastActivity: Number(contact.lastActivity || 0)
          };
        }
        await db.ref(`contacts/${ownCode}`).set(next);
        return { ok: true };
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
    addListener(ref, event, fn) {
      ref.on(event, fn);
      this.listeners.push(() => ref.off(event, fn));
    }
    async connect() {
      try {
        await signInSession({ code: this.code });
        const presenceRef = db.ref(`presence/${this.code}/${this.tabId}`);
        await presenceRef.set({ online: true, lastSeen: firebase.database.ServerValue.TIMESTAMP });
        presenceRef.onDisconnect().remove();
        this.heartbeat = setInterval(async () => {
          if (!this.connected) return;
          try {
            await presenceRef.update({ online: true, lastSeen: firebase.database.ServerValue.TIMESTAMP });
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
          statuses[code] = isPresenceOnline(snap);
          const fn = (s) => this.fire('presence:update', { code, online: isPresenceOnline(s) });
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
          const p = await db.ref(`presence/${to}`).once('value');
          if (!isPresenceOnline(p)) return { ok: false, error: 'That user is offline.' };
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
      try { await db.ref(`presence/${this.code}/${this.tabId}`).remove(); } catch (_) {}
      this.fire('disconnect');
    }
  }

  window.CipherBackend = {
    apiRequest,
    BackendError,
    configured,
    waitForAuth,
    signInWithGoogle,
    signOut,
    getAccount,
    getCurrentUser: () => { requireConfigured(); return publicUser(auth.currentUser); }
  };
  window.io = (options) => new FirebaseSocket(options);
})();
