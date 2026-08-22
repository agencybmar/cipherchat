'use strict';

(() => {
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  const elements = {
    authScreen: document.getElementById('auth-screen'),
    idForm: document.getElementById('id-form'),
    idCode: document.getElementById('id-code'),
    idHint: document.getElementById('id-hint'),
    idError: document.getElementById('id-error'),
    availabilityDot: document.getElementById('availability-dot'),
    createIdButton: document.getElementById('create-id-button'),
    restoreButton: document.getElementById('restore-button'),
    restoreFile: document.getElementById('restore-file'),
    app: document.getElementById('app'),
    sidebar: document.getElementById('sidebar'),
    mainPanel: document.getElementById('main-panel'),
    ownCode: document.getElementById('own-code'),
    copyOwnId: document.getElementById('copy-own-id'),
    backupButton: document.getElementById('backup-button'),
    addChatButton: document.getElementById('add-chat-button'),
    emptyAddChatButton: document.getElementById('empty-add-chat-button'),
    chatSearch: document.getElementById('chat-search'),
    chatList: document.getElementById('chat-list'),
    noChats: document.getElementById('no-chats'),
    connectionLabel: document.getElementById('connection-label'),
    emptyState: document.getElementById('empty-state'),
    chatView: document.getElementById('chat-view'),
    mobileBackButton: document.getElementById('mobile-back-button'),
    peerAvatar: document.getElementById('peer-avatar'),
    peerCode: document.getElementById('peer-code'),
    peerStatus: document.getElementById('peer-status'),
    peerDetailsButton: document.getElementById('peer-details-button'),
    safetyButton: document.getElementById('safety-button'),
    videoCallButton: document.getElementById('video-call-button'),
    messageArea: document.getElementById('message-area'),
    messages: document.getElementById('messages'),
    composer: document.getElementById('composer'),
    messageInput: document.getElementById('message-input'),
    addChatModal: document.getElementById('add-chat-modal'),
    addChatForm: document.getElementById('add-chat-form'),
    contactCode: document.getElementById('contact-code'),
    addChatError: document.getElementById('add-chat-error'),
    addChatSubmit: document.getElementById('add-chat-submit'),
    safetyModal: document.getElementById('safety-modal'),
    safetyDescription: document.getElementById('safety-description'),
    safetyCode: document.getElementById('safety-code'),
    incomingCallModal: document.getElementById('incoming-call-modal'),
    incomingAvatar: document.getElementById('incoming-avatar'),
    incomingCallTitle: document.getElementById('incoming-call-title'),
    acceptCallButton: document.getElementById('accept-call-button'),
    declineCallButton: document.getElementById('decline-call-button'),
    callScreen: document.getElementById('call-screen'),
    callStatusLabel: document.getElementById('call-status-label'),
    callPeerLabel: document.getElementById('call-peer-label'),
    callAvatar: document.getElementById('call-avatar'),
    remotePlaceholder: document.getElementById('remote-placeholder'),
    remotePlaceholderText: document.getElementById('remote-placeholder-text'),
    remoteVideo: document.getElementById('remote-video'),
    localVideo: document.getElementById('local-video'),
    toggleMicButton: document.getElementById('toggle-mic-button'),
    toggleCameraButton: document.getElementById('toggle-camera-button'),
    endCallButton: document.getElementById('end-call-button'),
    toastRegion: document.getElementById('toast-region')
  };

  const state = {
    code: null,
    token: null,
    identity: null,
    ownPublicJwk: null,
    socket: null,
    contacts: [],
    activePeer: null,
    online: new Map(),
    messages: new Map(),
    loadedPeers: new Set(),
    publicKeys: new Map(),
    sharedKeys: new Map(),
    callKeys: new Map(),
    availabilityTimer: null,
    typingTimer: null,
    typingClearTimer: null,
    lastTypingSent: false,
    iceServers: [{ urls: ['stun:stun.l.google.com:19302'] }],
    peerConnection: null,
    localStream: null,
    remoteStream: null,
    callPeer: null,
    callId: null,
    callRole: null,
    pendingCall: null,
    pendingIce: [],
    earlyIce: new Map(),
    callSignalReady: false,
    outgoingIce: [],
    callTimer: null,
    callDisconnectTimer: null,
    restoring: false
  };

  const SESSION_KEY = 'cipherchat.session.v1';
  const KEY_DB_NAME = 'cipherchat-key-store';
  const KEY_DB_VERSION = 1;
  const KEY_STORE_NAME = 'identity-keys';

  class ApiError extends Error {
    constructor(message, status) {
      super(message);
      this.name = 'ApiError';
      this.status = status;
    }
  }

  function isCode(value) {
    return typeof value === 'string' && /^\d{4}$/.test(value);
  }

  function sanitizeCode(value) {
    return String(value || '').replace(/\D/g, '').slice(0, 4);
  }

  function getStoredSession() {
    try {
      const value = JSON.parse(localStorage.getItem(SESSION_KEY));
      if (!value || !isCode(value.code) || typeof value.token !== 'string') return null;
      return { code: value.code, token: value.token };
    } catch (error) {
      return null;
    }
  }

  function saveSession(session) {
    localStorage.setItem(SESSION_KEY, JSON.stringify({ code: session.code, token: session.token }));
  }

  function contactsStorageKey(code = state.code) {
    return `cipherchat.contacts.${code}`;
  }

  function publicKeysStorageKey(code = state.code) {
    return `cipherchat.public-keys.${code}`;
  }

  function isPublicJwk(value) {
    return Boolean(
      value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      value.kty === 'EC' &&
      value.crv === 'P-256' &&
      typeof value.x === 'string' &&
      /^[A-Za-z0-9_-]{40,60}$/.test(value.x) &&
      typeof value.y === 'string' &&
      /^[A-Za-z0-9_-]{40,60}$/.test(value.y) &&
      !Object.prototype.hasOwnProperty.call(value, 'd')
    );
  }

  function sanitizeContacts(value, ownerCode = state.code) {
    if (!Array.isArray(value)) return [];
    const seen = new Set();
    return value
      .filter((contact) => {
        if (!contact || !isCode(contact.code) || contact.code === ownerCode || seen.has(contact.code)) return false;
        seen.add(contact.code);
        return true;
      })
      .slice(0, 100)
      .map((contact) => ({
        code: contact.code,
        addedAt: Number.isFinite(contact.addedAt) ? contact.addedAt : Date.now(),
        lastActivity: Number.isFinite(contact.lastActivity) ? contact.lastActivity : 0,
        unread: Number.isInteger(contact.unread) && contact.unread > 0 ? Math.min(contact.unread, 9999) : 0
      }));
  }

  function loadContacts() {
    try {
      return sanitizeContacts(JSON.parse(localStorage.getItem(contactsStorageKey())));
    } catch (error) {
      return [];
    }
  }

  function saveContacts() {
    localStorage.setItem(contactsStorageKey(), JSON.stringify(state.contacts));
  }

  function sanitizePinnedKeys(value, ownerCode = state.code) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
    const result = {};
    for (const [code, publicKey] of Object.entries(value)) {
      if (Object.keys(result).length >= 100 || !isCode(code) || code === ownerCode || !isPublicJwk(publicKey)) continue;
      result[code] = {
        kty: 'EC',
        crv: 'P-256',
        x: publicKey.x,
        y: publicKey.y,
        ext: true
      };
    }
    return result;
  }

  function loadPinnedKeys(code = state.code) {
    try {
      const parsed = JSON.parse(localStorage.getItem(publicKeysStorageKey(code)));
      return new Map(Object.entries(sanitizePinnedKeys(parsed, code)));
    } catch (error) {
      return new Map();
    }
  }

  function savePinnedKeys() {
    const value = {};
    for (const [code, publicKey] of state.publicKeys) {
      if (isCode(code) && code !== state.code && isPublicJwk(publicKey)) value[code] = publicKey;
    }
    localStorage.setItem(publicKeysStorageKey(), JSON.stringify(value));
  }

  async function apiRequest(path, options = {}) {
    if (!window.CipherBackend) {
      throw new ApiError('The Firebase backend adapter failed to load.', 503);
    }
    const session = options.session || { code: state.code, token: state.token };
    try {
      return await window.CipherBackend.apiRequest(path, { ...options, session });
    } catch (error) {
      throw new ApiError(error.message || 'Backend request failed.', Number(error.status || 500));
    }
  }

  function openKeyDatabase() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(KEY_DB_NAME, KEY_DB_VERSION);
      request.onerror = () => reject(request.error || new Error('Could not open key storage.'));
      request.onupgradeneeded = () => {
        const database = request.result;
        if (!database.objectStoreNames.contains(KEY_STORE_NAME)) {
          database.createObjectStore(KEY_STORE_NAME, { keyPath: 'id' });
        }
      };
      request.onsuccess = () => resolve(request.result);
    });
  }

  async function readIdentityRecord(code) {
    const database = await openKeyDatabase();
    return new Promise((resolve, reject) => {
      const transaction = database.transaction(KEY_STORE_NAME, 'readonly');
      const request = transaction.objectStore(KEY_STORE_NAME).get(`identity:${code}`);
      request.onerror = () => reject(request.error || new Error('Could not read identity key.'));
      request.onsuccess = () => resolve(request.result || null);
      transaction.oncomplete = () => database.close();
    });
  }

  async function writeIdentityRecord(code, keyPair) {
    const database = await openKeyDatabase();
    return new Promise((resolve, reject) => {
      const transaction = database.transaction(KEY_STORE_NAME, 'readwrite');
      transaction.objectStore(KEY_STORE_NAME).put({
        id: `identity:${code}`,
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        savedAt: Date.now()
      });
      transaction.onerror = () => reject(transaction.error || new Error('Could not save identity key.'));
      transaction.oncomplete = () => {
        database.close();
        resolve();
      };
    });
  }

  async function getOrCreateIdentity(code) {
    let existing;
    try {
      existing = await readIdentityRecord(code);
    } catch (error) {
      throw new Error('This browser could not access the saved encryption key.');
    }
    if (existing && existing.privateKey && existing.publicKey) {
      return { privateKey: existing.privateKey, publicKey: existing.publicKey };
    }

    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );

    try {
      await writeIdentityRecord(code, keyPair);
    } catch (error) {
      throw new Error('This browser could not securely save the encryption key.');
    }

    return keyPair;
  }

  async function importIdentity(code, privateJwk, publicJwk) {
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      privateJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      publicJwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      []
    );
    await writeIdentityRecord(code, { privateKey, publicKey });
    return { privateKey, publicKey };
  }

  function samePublicKey(left, right) {
    return Boolean(
      left &&
      right &&
      left.kty === right.kty &&
      left.crv === right.crv &&
      left.x === right.x &&
      left.y === right.y
    );
  }

  function setAuthError(message) {
    elements.idError.textContent = message || '';
  }

  function setConnectionState(connected) {
    elements.connectionLabel.textContent = connected ? 'Online' : 'Offline';
    elements.connectionLabel.classList.toggle('online', connected);
  }

  function showToast(message, type = 'info', duration = 3400) {
    const toast = document.createElement('div');
    toast.className = `toast ${type === 'error' ? 'error' : ''}`.trim();
    toast.textContent = message;
    elements.toastRegion.appendChild(toast);

    window.setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(-8px)';
      window.setTimeout(() => toast.remove(), 180);
    }, duration);
  }

  function openModal(element) {
    element.classList.remove('hidden');
  }

  function closeModal(element) {
    element.classList.add('hidden');
  }

  function avatarText(code) {
    return isCode(code) ? code : '--';
  }

  function formatTime(timestamp) {
    if (!Number.isFinite(timestamp)) return '';
    return new Intl.DateTimeFormat(undefined, {
      hour: '2-digit',
      minute: '2-digit'
    }).format(new Date(timestamp));
  }

  function formatListTime(timestamp) {
    if (!Number.isFinite(timestamp) || timestamp <= 0) return '';
    const date = new Date(timestamp);
    const now = new Date();
    if (date.toDateString() === now.toDateString()) return formatTime(timestamp);
    return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' }).format(date);
  }

  function uuid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = [...bytes].map((value) => value.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  function bytesToBase64(bytes) {
    let binary = '';
    const chunkSize = 0x8000;
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
    }
    return btoa(binary);
  }

  function base64ToBytes(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  }

  function bytesToHex(bytes) {
    return [...bytes].map((value) => value.toString(16).padStart(2, '0')).join('');
  }

  async function sha256(value) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', value));
  }

  async function getPeerProfile(code, force = false) {
    if (!force && state.publicKeys.has(code)) {
      return {
        code,
        publicKey: state.publicKeys.get(code),
        online: Boolean(state.online.get(code))
      };
    }

    const profile = await apiRequest(`/api/users/${encodeURIComponent(code)}`);
    if (!isPublicJwk(profile.publicKey)) {
      throw new Error(`The server returned an invalid encryption key for #${code}.`);
    }
    const previousKey = state.publicKeys.get(code);
    if (previousKey && !samePublicKey(previousKey, profile.publicKey)) {
      state.sharedKeys.delete(code);
      state.callKeys.delete(code);
      throw new Error(`The pinned encryption key for #${code} changed. Stop and verify the contact before continuing.`);
    }
    state.publicKeys.set(code, profile.publicKey);
    savePinnedKeys();
    state.online.set(code, Boolean(profile.online));
    updateActivePeerStatus();
    renderContacts();
    return profile;
  }

  async function getSharedKey(peerCode) {
    if (state.sharedKeys.has(peerCode)) return state.sharedKeys.get(peerCode);

    const profile = await getPeerProfile(peerCode);
    const remotePublicKey = await crypto.subtle.importKey(
      'jwk',
      profile.publicKey,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: remotePublicKey },
      state.identity.privateKey,
      256
    );
    const keyMaterial = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
    const pair = [state.code, peerCode].sort().join(':');
    const salt = await sha256(textEncoder.encode(`cipherchat-salt-v1|${pair}`));
    const key = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt,
        info: textEncoder.encode(`cipherchat-message-key-v1|${pair}`)
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    state.sharedKeys.set(peerCode, key);
    return key;
  }

  async function getCallSignalKey(peerCode) {
    if (state.callKeys.has(peerCode)) return state.callKeys.get(peerCode);

    const profile = await getPeerProfile(peerCode);
    const remotePublicKey = await crypto.subtle.importKey(
      'jwk',
      profile.publicKey,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );
    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: remotePublicKey },
      state.identity.privateKey,
      256
    );
    const keyMaterial = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
    const pair = [state.code, peerCode].sort().join(':');
    const salt = await sha256(textEncoder.encode(`cipherchat-salt-v1|${pair}`));
    const key = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt,
        info: textEncoder.encode(`cipherchat-call-signal-key-v1|${pair}`)
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );

    state.callKeys.set(peerCode, key);
    return key;
  }

  function messageAad(message) {
    return textEncoder.encode(`${message.id}|${message.from}|${message.to}|${message.ts}|${message.version}`);
  }

  async function encryptMessage(peerCode, text) {
    const key = await getSharedKey(peerCode);
    const message = {
      id: uuid(),
      from: state.code,
      to: peerCode,
      ts: Date.now(),
      version: 1
    };
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: messageAad(message),
        tagLength: 128
      },
      key,
      textEncoder.encode(text)
    );

    return {
      ...message,
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(ciphertext))
    };
  }

  async function decryptMessage(envelope) {
    const peerCode = envelope.from === state.code ? envelope.to : envelope.from;
    try {
      const key = await getSharedKey(peerCode);
      const plaintext = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: base64ToBytes(envelope.iv),
          additionalData: messageAad(envelope),
          tagLength: 128
        },
        key,
        base64ToBytes(envelope.ciphertext)
      );

      return {
        ...envelope,
        text: textDecoder.decode(plaintext),
        status: envelope.from === state.code ? (envelope.deliveredAt ? 'delivered' : 'sent') : 'received',
        decryptFailed: false
      };
    } catch (error) {
      return {
        ...envelope,
        text: 'This message could not be decrypted on this device.',
        status: 'failed',
        decryptFailed: true
      };
    }
  }

  function callSignalAad(callId, fromCode, toCode, kind) {
    return textEncoder.encode(`cipherchat-call-signal-v1|${callId}|${fromCode}|${toCode}|${kind}`);
  }

  async function encryptCallSignal(peerCode, callId, kind, payload) {
    const key = await getCallSignalKey(peerCode);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: callSignalAad(callId, state.code, peerCode, kind),
        tagLength: 128
      },
      key,
      textEncoder.encode(JSON.stringify(payload))
    );
    return {
      version: 1,
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(ciphertext))
    };
  }

  async function decryptCallSignal(peerCode, callId, kind, signal) {
    if (!signal || signal.version !== 1 || typeof signal.iv !== 'string' || typeof signal.ciphertext !== 'string') {
      throw new Error('Invalid encrypted call signal.');
    }
    const key = await getCallSignalKey(peerCode);
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: base64ToBytes(signal.iv),
        additionalData: callSignalAad(callId, peerCode, state.code, kind),
        tagLength: 128
      },
      key,
      base64ToBytes(signal.ciphertext)
    );
    return JSON.parse(textDecoder.decode(plaintext));
  }

  function validSessionDescription(description, expectedType) {
    return Boolean(
      description &&
      description.type === expectedType &&
      typeof description.sdp === 'string' &&
      description.sdp.length > 0 &&
      description.sdp.length <= 100000
    );
  }

  function validIceCandidate(candidate) {
    return Boolean(
      candidate &&
      typeof candidate === 'object' &&
      typeof candidate.candidate === 'string' &&
      candidate.candidate.length <= 5000
    );
  }

  function earlyIceKey(fromCode, callId) {
    return `${fromCode}:${callId}`;
  }

  function getContact(code) {
    return state.contacts.find((contact) => contact.code === code) || null;
  }

  function ensureContact(code) {
    let contact = getContact(code);
    if (contact) return contact;

    contact = {
      code,
      addedAt: Date.now(),
      lastActivity: 0,
      unread: 0
    };
    state.contacts.push(contact);
    saveContacts();
    subscribeToPresence();
    return contact;
  }

  function messagePreview(code) {
    const messages = state.messages.get(code) || [];
    const last = messages[messages.length - 1];
    if (!last) return 'Private conversation';
    if (last.decryptFailed) return 'Unable to decrypt message';
    const prefix = last.from === state.code ? 'You: ' : '';
    return `${prefix}${last.text}`;
  }

  function renderContacts() {
    const query = elements.chatSearch.value.trim();
    const sorted = [...state.contacts].sort((left, right) => {
      const activityDifference = (right.lastActivity || 0) - (left.lastActivity || 0);
      if (activityDifference !== 0) return activityDifference;
      return (right.addedAt || 0) - (left.addedAt || 0);
    });
    const filtered = sorted.filter((contact) => !query || contact.code.includes(query));

    elements.chatList.replaceChildren();
    elements.noChats.classList.toggle('hidden', state.contacts.length > 0);
    elements.chatList.classList.toggle('hidden', state.contacts.length === 0);

    for (const contact of filtered) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = `chat-item${state.activePeer === contact.code ? ' active' : ''}`;
      button.setAttribute('role', 'listitem');
      button.addEventListener('click', () => openChat(contact.code));

      const avatar = document.createElement('div');
      avatar.className = `avatar${state.online.get(contact.code) ? ' online' : ''}`;
      avatar.textContent = avatarText(contact.code);

      const content = document.createElement('div');
      content.className = 'chat-item-content';

      const top = document.createElement('div');
      top.className = 'chat-item-top';
      const title = document.createElement('strong');
      title.textContent = `#${contact.code}`;
      const time = document.createElement('span');
      time.className = 'chat-item-time';
      time.textContent = formatListTime(contact.lastActivity);
      top.append(title, time);

      const bottom = document.createElement('div');
      bottom.className = 'chat-item-bottom';
      const preview = document.createElement('span');
      preview.className = 'chat-item-preview';
      preview.textContent = messagePreview(contact.code);
      bottom.appendChild(preview);

      if (contact.unread > 0) {
        const unread = document.createElement('span');
        unread.className = 'unread-badge';
        unread.textContent = contact.unread > 99 ? '99+' : String(contact.unread);
        bottom.appendChild(unread);
      }

      content.append(top, bottom);
      button.append(avatar, content);
      elements.chatList.appendChild(button);
    }

    if (state.contacts.length > 0 && filtered.length === 0) {
      const noResults = document.createElement('div');
      noResults.className = 'no-chats';
      const label = document.createElement('strong');
      label.textContent = 'No matching chats';
      const help = document.createElement('span');
      help.textContent = 'Try a different four-digit ID.';
      noResults.append(label, help);
      elements.chatList.appendChild(noResults);
    }
  }

  function addOrMergeMessage(peerCode, message) {
    const messages = state.messages.get(peerCode) || [];
    const existingIndex = messages.findIndex((item) => item.id === message.id);
    if (existingIndex >= 0) {
      messages[existingIndex] = { ...messages[existingIndex], ...message };
    } else {
      messages.push(message);
    }
    messages.sort((left, right) => left.ts - right.ts || left.id.localeCompare(right.id));
    state.messages.set(peerCode, messages);
  }

  function renderMessages() {
    if (!state.activePeer) return;
    const messages = state.messages.get(state.activePeer) || [];
    elements.messages.replaceChildren();

    if (messages.length === 0 && state.loadedPeers.has(state.activePeer)) {
      const emptyMessage = document.createElement('div');
      emptyMessage.className = 'message-system';
      emptyMessage.textContent = 'No messages yet. Say hello securely.';
      elements.messages.appendChild(emptyMessage);
    }

    for (const message of messages) {
      const row = document.createElement('div');
      const outgoing = message.from === state.code;
      row.className = `message-row ${outgoing ? 'outgoing' : 'incoming'}`;

      const bubble = document.createElement('div');
      bubble.className = 'message-bubble';

      const text = document.createElement('div');
      text.className = 'message-text';
      text.textContent = message.text;

      const meta = document.createElement('div');
      meta.className = 'message-meta';
      const time = document.createElement('span');
      time.textContent = formatTime(message.ts);
      meta.appendChild(time);

      if (outgoing) {
        const status = document.createElement('span');
        status.className = `message-status${message.status === 'failed' ? ' failed' : ''}${message.status === 'delivered' ? ' delivered' : ''}`;
        if (message.status === 'sending') status.textContent = '\u00b7';
        else if (message.status === 'failed') status.textContent = '!';
        else if (message.status === 'delivered') status.textContent = '\u2713\u2713';
        else status.textContent = '\u2713';
        meta.appendChild(status);
      }

      bubble.append(text, meta);
      row.appendChild(bubble);
      elements.messages.appendChild(row);
    }

    requestAnimationFrame(() => {
      elements.messageArea.scrollTop = elements.messageArea.scrollHeight;
    });
  }

  async function loadConversation(peerCode) {
    if (state.loadedPeers.has(peerCode)) return;

    elements.messages.replaceChildren();
    const loading = document.createElement('div');
    loading.className = 'message-system';
    loading.textContent = 'Decrypting conversation...';
    elements.messages.appendChild(loading);

    try {
      const data = await apiRequest(`/api/messages/${encodeURIComponent(peerCode)}`);
      const decrypted = await Promise.all(data.messages.map((message) => decryptMessage(message)));
      const existing = state.messages.get(peerCode) || [];
      const combined = new Map();
      for (const message of decrypted) combined.set(message.id, message);
      for (const message of existing) combined.set(message.id, { ...combined.get(message.id), ...message });
      const messages = [...combined.values()].sort((left, right) => left.ts - right.ts || left.id.localeCompare(right.id));
      state.messages.set(peerCode, messages);
      state.loadedPeers.add(peerCode);

      const contact = ensureContact(peerCode);
      const latest = messages[messages.length - 1];
      if (latest) contact.lastActivity = Math.max(contact.lastActivity || 0, latest.ts);
      saveContacts();
      renderContacts();
    } catch (error) {
      state.loadedPeers.add(peerCode);
      showToast(error.message || 'Could not load this conversation.', 'error');
    }

    if (state.activePeer === peerCode) renderMessages();
  }

  function updateActivePeerStatus() {
    if (!state.activePeer) return;
    const online = Boolean(state.online.get(state.activePeer));
    elements.peerStatus.textContent = online ? 'Online' : 'Offline';
    elements.peerAvatar.classList.toggle('online', online);
  }

  async function openChat(code) {
    if (!isCode(code) || code === state.code) return;
    const contact = ensureContact(code);
    contact.unread = 0;
    saveContacts();

    state.activePeer = code;
    elements.peerCode.textContent = `#${code}`;
    elements.peerAvatar.textContent = avatarText(code);
    elements.emptyState.classList.add('hidden');
    elements.chatView.classList.remove('hidden');
    elements.app.classList.add('mobile-chat-open');
    updateActivePeerStatus();
    renderContacts();
    await loadConversation(code);

    if (window.matchMedia('(min-width: 761px)').matches) {
      elements.messageInput.focus();
    }
  }

  async function addContactFromModal(event) {
    event.preventDefault();
    const code = sanitizeCode(elements.contactCode.value);
    elements.contactCode.value = code;
    elements.addChatError.textContent = '';

    if (!isCode(code)) {
      elements.addChatError.textContent = 'Enter exactly four digits.';
      return;
    }
    if (code === state.code) {
      elements.addChatError.textContent = 'You cannot add your own ID.';
      return;
    }

    elements.addChatSubmit.disabled = true;
    try {
      const profile = await getPeerProfile(code, true);
      state.online.set(code, Boolean(profile.online));
      ensureContact(code);
      closeModal(elements.addChatModal);
      elements.contactCode.value = '';
      renderContacts();
      await openChat(code);
    } catch (error) {
      elements.addChatError.textContent = error.message || 'Could not add that ID.';
    } finally {
      elements.addChatSubmit.disabled = false;
    }
  }

  function subscribeToPresence() {
    if (!state.socket || !state.socket.connected) return;
    const codes = state.contacts.map((contact) => contact.code).slice(0, 100);
    state.socket.emit('presence:subscribe', { codes }, (response) => {
      if (!response || !response.ok) return;
      for (const [code, online] of Object.entries(response.statuses || {})) {
        state.online.set(code, Boolean(online));
      }
      updateActivePeerStatus();
      renderContacts();
    });
  }

  function acknowledgeMessages(messageIds) {
    if (!state.socket || !state.socket.connected) return;
    const uniqueIds = [...new Set(messageIds.filter(Boolean))];
    for (let offset = 0; offset < uniqueIds.length; offset += 100) {
      state.socket.emit('message:received', { ids: uniqueIds.slice(offset, offset + 100) });
    }
  }

  function acknowledgeMessage(messageId) {
    acknowledgeMessages([messageId]);
  }

  async function handleIncomingMessage(envelope, options = {}) {
    const peerCode = envelope.from;
    if (!isCode(peerCode) || peerCode === state.code) return false;

    const existingMessages = state.messages.get(peerCode) || [];
    if (existingMessages.some((message) => message.id === envelope.id)) {
      if (!options.deferAck) acknowledgeMessage(envelope.id);
      return false;
    }

    const contact = ensureContact(peerCode);
    const decrypted = await decryptMessage(envelope);
    addOrMergeMessage(peerCode, decrypted);
    contact.lastActivity = Math.max(contact.lastActivity || 0, envelope.ts);

    const isVisibleConversation = state.activePeer === peerCode && !document.hidden;
    if (!isVisibleConversation) contact.unread += 1;
    saveContacts();
    renderContacts();
    if (!options.deferAck) acknowledgeMessage(envelope.id);

    if (state.activePeer === peerCode) {
      renderMessages();
    } else if (!options.suppressToast) {
      showToast(`New encrypted message from #${peerCode}`);
    }
    return true;
  }

  async function handleMessageSync(payload) {
    const messages = payload && Array.isArray(payload.messages) ? payload.messages : [];
    let newCount = 0;
    for (const message of messages.sort((left, right) => left.ts - right.ts)) {
      if (await handleIncomingMessage(message, { suppressToast: true, deferAck: true })) newCount += 1;
    }
    acknowledgeMessages(messages.map((message) => message.id));
    if (newCount > 0) {
      showToast(`${newCount} encrypted message${newCount === 1 ? '' : 's'} delivered.`);
    }
  }

  function handleMessageDelivered(payload) {
    const peerCode = payload && payload.by;
    if (!isCode(peerCode) || !payload.id) return;
    const messages = state.messages.get(peerCode) || [];
    const message = messages.find((item) => item.id === payload.id && item.from === state.code);
    if (!message) return;
    message.status = 'delivered';
    message.deliveredAt = payload.deliveredAt || Date.now();
    if (state.activePeer === peerCode) renderMessages();
    renderContacts();
  }

  function emitTyping(typing) {
    if (!state.socket || !state.socket.connected || !state.activePeer) return;
    if (state.lastTypingSent === typing) return;
    state.lastTypingSent = typing;
    state.socket.emit('chat:typing', { to: state.activePeer, typing });
  }

  function handleMessageInput() {
    elements.messageInput.style.height = 'auto';
    elements.messageInput.style.height = `${Math.min(elements.messageInput.scrollHeight, 128)}px`;

    emitTyping(true);
    window.clearTimeout(state.typingTimer);
    state.typingTimer = window.setTimeout(() => emitTyping(false), 1200);
  }

  async function sendMessage(event) {
    event.preventDefault();
    const text = elements.messageInput.value.trim();
    if (!text || !state.activePeer) return;
    if (!state.socket || !state.socket.connected) {
      showToast('You are offline. Reconnect before sending.', 'error');
      return;
    }

    const peerCode = state.activePeer;
    elements.messageInput.value = '';
    handleMessageInput();
    emitTyping(false);

    let envelope;
    try {
      envelope = await encryptMessage(peerCode, text);
    } catch (error) {
      showToast('Could not encrypt this message.', 'error');
      elements.messageInput.value = text;
      handleMessageInput();
      return;
    }

    const localMessage = {
      ...envelope,
      text,
      status: 'sending',
      decryptFailed: false
    };
    addOrMergeMessage(peerCode, localMessage);
    const contact = ensureContact(peerCode);
    contact.lastActivity = envelope.ts;
    saveContacts();
    renderMessages();
    renderContacts();

    state.socket.timeout(12000).emit(
      'message:send',
      {
        id: envelope.id,
        to: envelope.to,
        ts: envelope.ts,
        iv: envelope.iv,
        ciphertext: envelope.ciphertext,
        version: envelope.version
      },
      (timeoutError, response) => {
        const messages = state.messages.get(peerCode) || [];
        const message = messages.find((item) => item.id === envelope.id);
        if (!message) return;

        if (timeoutError || !response || !response.ok) {
          message.status = 'failed';
          showToast((response && response.error) || 'Message could not be delivered.', 'error');
        } else {
          if (message.status !== 'delivered') message.status = 'sent';
          message.receivedAt = response.receivedAt;
        }

        if (state.activePeer === peerCode) renderMessages();
        renderContacts();
      }
    );
  }

  async function showSafetyCode() {
    if (!state.activePeer) return;
    const peerCode = state.activePeer;
    openModal(elements.safetyModal);
    elements.safetyDescription.textContent = `Compare this code with #${peerCode}. Both devices should show the same value.`;
    elements.safetyCode.textContent = 'Calculating...';

    try {
      const profile = await getPeerProfile(peerCode, true);
      const entries = [
        { code: state.code, key: state.ownPublicJwk },
        { code: peerCode, key: profile.publicKey }
      ].sort((left, right) => left.code.localeCompare(right.code));
      const canonical = entries
        .map((entry) => `${entry.code}:${entry.key.crv}:${entry.key.x}:${entry.key.y}`)
        .join('|');
      const digest = bytesToHex(await sha256(textEncoder.encode(canonical))).toUpperCase();
      elements.safetyCode.textContent = digest.match(/.{1,4}/g).join(' ');
    } catch (error) {
      elements.safetyCode.textContent = error.message || 'Could not calculate the safety code.';
    }
  }

  function connectSocket() {
    if (state.socket) state.socket.disconnect();

    state.socket = window.io({
      auth: { code: state.code, token: state.token },
      reconnection: true,
      reconnectionDelayMax: 5000
    });

    state.socket.on('connect', () => {
      setConnectionState(true);
      subscribeToPresence();
    });

    state.socket.on('disconnect', () => {
      setConnectionState(false);
      for (const contact of state.contacts) state.online.set(contact.code, false);
      updateActivePeerStatus();
      renderContacts();
    });

    state.socket.on('connect_error', (error) => {
      setConnectionState(false);
      if (error && /already active/i.test(error.message || '')) {
        showToast('This ID is already open in another tab or device.', 'error', 6000);
      }
    });

    state.socket.on('presence:update', ({ code, online }) => {
      if (!isCode(code)) return;
      state.online.set(code, Boolean(online));
      updateActivePeerStatus();
      renderContacts();
    });

    state.socket.on('message:new', (message) => {
      handleIncomingMessage(message).catch(() => {
        showToast('An incoming message could not be processed.', 'error');
      });
    });

    state.socket.on('message:sync', (payload) => {
      handleMessageSync(payload).catch(() => {
        showToast('Pending messages could not be processed.', 'error');
      });
    });

    state.socket.on('message:delivered', handleMessageDelivered);

    state.socket.on('chat:typing', ({ from, typing }) => {
      if (from !== state.activePeer) return;
      window.clearTimeout(state.typingClearTimer);
      if (typing) {
        elements.peerStatus.textContent = 'Typing...';
        state.typingClearTimer = window.setTimeout(updateActivePeerStatus, 1800);
      } else {
        updateActivePeerStatus();
      }
    });

    state.socket.on('call:incoming', (payload) => {
      handleIncomingCall(payload).catch(() => {
        if (payload && isCode(payload.from) && payload.callId) {
          state.socket.emit('call:decline', { to: payload.from, callId: payload.callId });
          state.earlyIce.delete(earlyIceKey(payload.from, payload.callId));
        }
        showToast('An encrypted incoming call could not be verified.', 'error');
      });
    });
    state.socket.on('call:answer', (payload) => {
      handleCallAnswer(payload).catch(() => {
        showToast('The encrypted call answer could not be verified.', 'error');
        endCall(true);
      });
    });
    state.socket.on('call:ice', (payload) => {
      handleCallIce(payload).catch((error) => console.warn('Encrypted ICE signal rejected:', error));
    });
    state.socket.on('call:decline', handleCallDecline);
    state.socket.on('call:end', handleRemoteCallEnd);
  }

  async function enterApp(session, sessionInfo) {
    if (state.socket) state.socket.disconnect();
    state.code = session.code;
    state.token = session.token;
    state.activePeer = null;
    state.online = new Map();
    state.messages = new Map();
    state.loadedPeers = new Set();
    state.publicKeys = loadPinnedKeys(state.code);
    state.sharedKeys = new Map();
    state.callKeys = new Map();
    state.identity = await getOrCreateIdentity(state.code);
    state.ownPublicJwk = await crypto.subtle.exportKey('jwk', state.identity.publicKey);

    if (sessionInfo.hasPublicKey) {
      const profile = await apiRequest(`/api/users/${encodeURIComponent(state.code)}`, { session });
      if (!samePublicKey(profile.publicKey, state.ownPublicJwk)) {
        throw new Error('This browser does not have the matching encryption key. Restore the account backup for this ID.');
      }
    } else {
      await apiRequest('/api/profile/key', {
        method: 'PUT',
        session,
        body: { publicKey: state.ownPublicJwk }
      });
    }

    try {
      const config = await apiRequest('/api/config');
      if (Array.isArray(config.iceServers) && config.iceServers.length > 0) {
        state.iceServers = config.iceServers;
      }
    } catch (error) {
      console.warn('Using default ICE configuration:', error);
    }

    state.contacts = loadContacts();
    if (typeof window.io !== 'function') {
      throw new Error('The Firebase real-time adapter failed to load.');
    }
    connectSocket();
    elements.ownCode.textContent = `#${state.code}`;
    elements.authScreen.classList.add('hidden');
    elements.app.classList.remove('hidden');
    setConnectionState(false);
    renderContacts();
  }

  async function bootstrap() {
    bindEvents();
    const session = getStoredSession();
    if (!session) {
      elements.idCode.focus();
      return;
    }

    elements.createIdButton.disabled = true;
    setAuthError('Opening your private ID...');
    try {
      const sessionInfo = await apiRequest('/api/session', {
        method: 'POST',
        session
      });
      await enterApp(session, sessionInfo);
    } catch (error) {
      setAuthError(error.message || 'Could not open the saved ID.');
      elements.idCode.value = session.code;
      if (error instanceof ApiError && error.status === 401) {
        localStorage.removeItem(SESSION_KEY);
      }
    } finally {
      elements.createIdButton.disabled = false;
    }
  }

  async function registerId(event) {
    event.preventDefault();
    const code = sanitizeCode(elements.idCode.value);
    elements.idCode.value = code;
    setAuthError('');

    if (!isCode(code)) {
      setAuthError('Enter exactly four digits.');
      return;
    }

    elements.createIdButton.disabled = true;
    try {
      const session = await apiRequest('/api/register', {
        method: 'POST',
        auth: false,
        body: { code }
      });
      saveSession(session);
      await enterApp(session, { hasPublicKey: false });
      showToast(`ID #${code} is permanently reserved. Download an account backup from the header.`, 'info', 6500);
    } catch (error) {
      setAuthError(error.message || 'Could not create that ID.');
      if (error instanceof ApiError && error.status === 409) {
        elements.availabilityDot.classList.remove('available');
        elements.availabilityDot.classList.add('unavailable');
      }
    } finally {
      elements.createIdButton.disabled = false;
    }
  }

  async function checkAvailability() {
    const code = sanitizeCode(elements.idCode.value);
    elements.idCode.value = code;
    elements.availabilityDot.classList.remove('available', 'unavailable');
    setAuthError('');
    window.clearTimeout(state.availabilityTimer);

    if (code.length === 0) {
      elements.idHint.textContent = 'Exactly four digits. Leading zeroes are allowed.';
      return;
    }
    if (!isCode(code)) {
      elements.idHint.textContent = `${code.length}/4 digits entered`;
      return;
    }

    elements.idHint.textContent = 'Checking availability...';
    state.availabilityTimer = window.setTimeout(async () => {
      try {
        const result = await apiRequest(`/api/availability/${code}`, { auth: false });
        elements.availabilityDot.classList.toggle('available', result.available);
        elements.availabilityDot.classList.toggle('unavailable', !result.available);
        elements.idHint.textContent = result.available
          ? `#${code} is available.`
          : `#${code} has already been reserved.`;
      } catch (error) {
        elements.idHint.textContent = 'Availability could not be checked.';
      }
    }, 250);
  }

  async function downloadBackup() {
    try {
      const privateKey = await crypto.subtle.exportKey('jwk', state.identity.privateKey);
      const publicKey = await crypto.subtle.exportKey('jwk', state.identity.publicKey);
      const knownPublicKeys = {};
      for (const [code, key] of state.publicKeys) {
        if (isCode(code) && code !== state.code && isPublicJwk(key)) knownPublicKeys[code] = key;
      }
      const backup = {
        format: 'cipherchat-account-backup',
        version: 1,
        code: state.code,
        token: state.token,
        privateKey,
        publicKey,
        contacts: sanitizeContacts(state.contacts, state.code),
        knownPublicKeys,
        exportedAt: new Date().toISOString()
      };
      const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `cipherchat-backup-${state.code}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      showToast('Account backup downloaded. Keep it private; it can open your ID and messages.', 'info', 6000);
    } catch (error) {
      showToast('Could not create the account backup.', 'error');
    }
  }

  async function restoreBackup(file) {
    if (!file || state.restoring) return;
    state.restoring = true;
    elements.restoreButton.disabled = true;
    setAuthError('Checking account backup...');

    try {
      if (file.size > 256 * 1024) {
        throw new Error('The account backup is unexpectedly large.');
      }
      const backup = JSON.parse(await file.text());
      if (
        !backup ||
        backup.format !== 'cipherchat-account-backup' ||
        backup.version !== 1 ||
        !isCode(backup.code) ||
        typeof backup.token !== 'string' ||
        !backup.privateKey ||
        !backup.publicKey ||
        !isPublicJwk(backup.publicKey) ||
        typeof backup.privateKey.d !== 'string' ||
        !samePublicKey(backup.privateKey, backup.publicKey)
      ) {
        throw new Error('This is not a valid CipherChat account backup.');
      }

      const session = { code: backup.code, token: backup.token };
      const sessionInfo = await apiRequest('/api/session', { method: 'POST', session });
      const profile = await apiRequest(`/api/users/${encodeURIComponent(backup.code)}`, { session });
      if (!samePublicKey(profile.publicKey, backup.publicKey)) {
        throw new Error('The backup encryption key does not match this ID.');
      }
      const identity = await importIdentity(backup.code, backup.privateKey, backup.publicKey);
      const exportedPublic = await crypto.subtle.exportKey('jwk', identity.publicKey);
      if (!samePublicKey(backup.publicKey, exportedPublic)) {
        throw new Error('The backup contains an invalid public key.');
      }

      if (Array.isArray(backup.contacts)) {
        localStorage.setItem(
          contactsStorageKey(backup.code),
          JSON.stringify(sanitizeContacts(backup.contacts, backup.code))
        );
      }
      if (backup.knownPublicKeys && typeof backup.knownPublicKeys === 'object') {
        localStorage.setItem(
          publicKeysStorageKey(backup.code),
          JSON.stringify(sanitizePinnedKeys(backup.knownPublicKeys, backup.code))
        );
      }

      saveSession(session);
      await enterApp(session, sessionInfo);
      showToast(`Account #${backup.code}, contacts, and known keys were restored on this device.`);
    } catch (error) {
      setAuthError(error.message || 'Could not restore this backup.');
    } finally {
      state.restoring = false;
      elements.restoreButton.disabled = false;
      elements.restoreFile.value = '';
    }
  }

  async function copyOwnCode() {
    const value = state.code || '';
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      showToast(`Copied ID #${value}`);
    } catch (error) {
      const input = document.createElement('input');
      input.value = value;
      input.style.position = 'fixed';
      input.style.opacity = '0';
      document.body.appendChild(input);
      input.select();
      document.execCommand('copy');
      input.remove();
      showToast(`Copied ID #${value}`);
    }
  }

  async function acquireLocalMedia() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      throw new Error('Camera and microphone access require HTTPS or localhost.');
    }
    return navigator.mediaDevices.getUserMedia({
      audio: {
        echoCancellation: true,
        noiseSuppression: true,
        autoGainControl: true
      },
      video: {
        width: { ideal: 1280 },
        height: { ideal: 720 },
        facingMode: 'user'
      }
    });
  }

  function showCallScreen(peerCode, status) {
    elements.callPeerLabel.textContent = `#${peerCode}`;
    elements.callAvatar.textContent = avatarText(peerCode);
    elements.callStatusLabel.textContent = status;
    elements.remotePlaceholderText.textContent = status === 'Calling' ? 'Waiting for the other person...' : 'Connecting video...';
    elements.remotePlaceholder.classList.remove('hidden');
    elements.callScreen.classList.remove('hidden');
    elements.toggleMicButton.classList.remove('off');
    elements.toggleCameraButton.classList.remove('off');
    elements.toggleMicButton.querySelector('.icon-mic-on').classList.remove('hidden');
    elements.toggleMicButton.querySelector('.icon-mic-off').classList.add('hidden');
    elements.toggleCameraButton.querySelector('.icon-camera-on').classList.remove('hidden');
    elements.toggleCameraButton.querySelector('.icon-camera-off').classList.add('hidden');
  }

  async function sendEncryptedIce(candidate, peerCode, callId) {
    if (!state.socket || !state.socket.connected) return;
    if (peerCode !== state.callPeer || callId !== state.callId) return;
    const signal = await encryptCallSignal(peerCode, callId, 'ice', candidate);
    if (peerCode !== state.callPeer || callId !== state.callId) return;
    state.socket.emit('call:ice', { to: peerCode, callId, signal });
  }

  async function flushOutgoingIce() {
    const peerCode = state.callPeer;
    const callId = state.callId;
    const queued = state.outgoingIce.splice(0);
    for (const candidate of queued) {
      await sendEncryptedIce(candidate, peerCode, callId);
    }
  }

  function createPeerConnection(peerCode, callId) {
    const connection = new RTCPeerConnection({ iceServers: state.iceServers });
    state.peerConnection = connection;

    for (const track of state.localStream.getTracks()) {
      connection.addTrack(track, state.localStream);
    }

    connection.onicecandidate = (event) => {
      if (!event.candidate || !state.socket || !state.socket.connected) return;
      const candidate = event.candidate.toJSON ? event.candidate.toJSON() : event.candidate;
      if (!state.callSignalReady) {
        state.outgoingIce.push(candidate);
        return;
      }
      sendEncryptedIce(candidate, peerCode, callId).catch((error) => {
        console.warn('Could not encrypt ICE candidate:', error);
      });
    };

    connection.ontrack = (event) => {
      state.remoteStream = event.streams[0] || state.remoteStream || new MediaStream();
      if (!event.streams[0]) state.remoteStream.addTrack(event.track);
      elements.remoteVideo.srcObject = state.remoteStream;
      elements.remotePlaceholder.classList.add('hidden');
    };

    connection.onconnectionstatechange = () => {
      const connectionState = connection.connectionState;
      if (connectionState === 'connected') {
        window.clearTimeout(state.callTimer);
        window.clearTimeout(state.callDisconnectTimer);
        elements.callStatusLabel.textContent = 'Connected';
      } else if (connectionState === 'connecting') {
        elements.callStatusLabel.textContent = 'Connecting';
      } else if (connectionState === 'disconnected') {
        elements.callStatusLabel.textContent = 'Reconnecting';
        window.clearTimeout(state.callDisconnectTimer);
        state.callDisconnectTimer = window.setTimeout(() => {
          if (state.peerConnection && state.peerConnection.connectionState === 'disconnected') {
            showToast('The call connection was lost.', 'error');
            endCall(true);
          }
        }, 10000);
      } else if (connectionState === 'failed') {
        showToast('The video call could not connect. A TURN server may be required.', 'error', 6000);
        endCall(true);
      }
    };

    return connection;
  }

  async function addIceCandidate(candidate) {
    if (!state.peerConnection || !state.peerConnection.remoteDescription) {
      state.pendingIce.push(candidate);
      return;
    }
    try {
      await state.peerConnection.addIceCandidate(candidate);
    } catch (error) {
      console.warn('ICE candidate rejected:', error);
    }
  }

  async function flushPendingIce() {
    if (!state.peerConnection || !state.peerConnection.remoteDescription) return;
    const queued = state.pendingIce.splice(0);
    for (const candidate of queued) {
      try {
        await state.peerConnection.addIceCandidate(candidate);
      } catch (error) {
        console.warn('Queued ICE candidate rejected:', error);
      }
    }
  }

  async function startVideoCall() {
    if (!state.activePeer) return;
    if (!state.socket || !state.socket.connected) {
      showToast('Reconnect before starting a call.', 'error');
      return;
    }
    if (state.peerConnection || state.pendingCall) {
      showToast('A call is already active.', 'error');
      return;
    }

    const peerCode = state.activePeer;
    try {
      const profile = await getPeerProfile(peerCode, true);
      if (!profile.online) {
        showToast(`#${peerCode} is offline.`, 'error');
        return;
      }

      state.localStream = await acquireLocalMedia();
      state.callPeer = peerCode;
      state.callId = uuid();
      state.callRole = 'caller';
      state.pendingIce = [];
      state.callSignalReady = false;
      state.outgoingIce = [];
      elements.localVideo.srcObject = state.localStream;
      showCallScreen(peerCode, 'Calling');

      const connection = createPeerConnection(peerCode, state.callId);
      const offer = await connection.createOffer();
      await connection.setLocalDescription(offer);

      const offerSignal = await encryptCallSignal(peerCode, state.callId, 'offer', connection.localDescription);
      state.socket.timeout(12000).emit(
        'call:offer',
        {
          to: peerCode,
          callId: state.callId,
          signal: offerSignal
        },
        (timeoutError, response) => {
          if (timeoutError || !response || !response.ok) {
            showToast((response && response.error) || 'The call could not be started.', 'error');
            endCall(true);
          }
        }
      );
      state.callSignalReady = true;
      flushOutgoingIce().catch((error) => console.warn('Could not send queued ICE candidates:', error));

      state.callTimer = window.setTimeout(() => {
        showToast('The call was not answered.', 'error');
        endCall(true);
      }, 45000);
    } catch (error) {
      showToast(error.message || 'Camera or microphone access failed.', 'error', 6000);
      cleanupCall();
    }
  }

  async function handleIncomingCall(payload) {
    const { from, callId, signal } = payload || {};
    if (!isCode(from) || !callId || !signal) return;

    if (state.peerConnection || state.pendingCall) {
      state.socket.emit('call:decline', { to: from, callId });
      state.earlyIce.delete(earlyIceKey(from, callId));
      return;
    }

    const description = await decryptCallSignal(from, callId, 'offer', signal);
    if (!validSessionDescription(description, 'offer')) {
      throw new Error('Invalid decrypted call offer.');
    }

    ensureContact(from);
    state.pendingCall = { from, callId, description };
    state.pendingIce = state.earlyIce.get(earlyIceKey(from, callId)) || [];
    state.earlyIce.delete(earlyIceKey(from, callId));
    elements.incomingAvatar.textContent = avatarText(from);
    elements.incomingCallTitle.textContent = `#${from}`;
    openModal(elements.incomingCallModal);
  }

  async function acceptIncomingCall() {
    const incoming = state.pendingCall;
    if (!incoming) return;
    closeModal(elements.incomingCallModal);

    try {
      state.localStream = await acquireLocalMedia();
      state.callPeer = incoming.from;
      state.callId = incoming.callId;
      state.callRole = 'callee';
      state.callSignalReady = false;
      state.outgoingIce = [];
      elements.localVideo.srcObject = state.localStream;
      showCallScreen(incoming.from, 'Connecting');

      const connection = createPeerConnection(incoming.from, incoming.callId);
      await connection.setRemoteDescription(incoming.description);
      await flushPendingIce();
      const answer = await connection.createAnswer();
      await connection.setLocalDescription(answer);

      const answerSignal = await encryptCallSignal(
        incoming.from,
        incoming.callId,
        'answer',
        connection.localDescription
      );
      state.socket.emit(
        'call:answer',
        {
          to: incoming.from,
          callId: incoming.callId,
          signal: answerSignal
        },
        (response) => {
          if (!response || !response.ok) {
            showToast((response && response.error) || 'The caller is no longer available.', 'error');
            endCall(true);
          }
        }
      );
      state.callSignalReady = true;
      flushOutgoingIce().catch((error) => console.warn('Could not send queued ICE candidates:', error));
      state.pendingCall = null;
    } catch (error) {
      state.socket.emit('call:decline', { to: incoming.from, callId: incoming.callId });
      showToast(error.message || 'Camera or microphone access failed.', 'error', 6000);
      cleanupCall();
    }
  }

  function declineIncomingCall() {
    if (!state.pendingCall) return;
    state.socket.emit('call:decline', {
      to: state.pendingCall.from,
      callId: state.pendingCall.callId
    });
    state.earlyIce.delete(earlyIceKey(state.pendingCall.from, state.pendingCall.callId));
    state.pendingCall = null;
    state.pendingIce = [];
    closeModal(elements.incomingCallModal);
  }

  async function handleCallAnswer(payload) {
    if (
      !payload ||
      payload.callId !== state.callId ||
      payload.from !== state.callPeer ||
      !state.peerConnection
    ) {
      return;
    }

    try {
      const description = await decryptCallSignal(payload.from, payload.callId, 'answer', payload.signal);
      if (!validSessionDescription(description, 'answer')) throw new Error('Invalid decrypted call answer.');
      await state.peerConnection.setRemoteDescription(description);
      await flushPendingIce();
      elements.callStatusLabel.textContent = 'Connecting';
    } catch (error) {
      showToast('The call answer was invalid.', 'error');
      endCall(true);
    }
  }

  async function handleCallIce(payload) {
    if (!payload || !payload.signal || !isCode(payload.from) || !payload.callId) return;
    const candidate = await decryptCallSignal(payload.from, payload.callId, 'ice', payload.signal);
    if (!validIceCandidate(candidate)) throw new Error('Invalid decrypted ICE candidate.');

    if (payload.callId === state.callId && payload.from === state.callPeer) {
      await addIceCandidate(candidate);
      return;
    }
    if (
      state.pendingCall &&
      payload.callId === state.pendingCall.callId &&
      payload.from === state.pendingCall.from
    ) {
      state.pendingIce.push(candidate);
      return;
    }

    const queueKey = earlyIceKey(payload.from, payload.callId);
    if (!state.earlyIce.has(queueKey) && state.earlyIce.size >= 24) {
      const oldestKey = state.earlyIce.keys().next().value;
      if (oldestKey) state.earlyIce.delete(oldestKey);
    }
    const early = state.earlyIce.get(queueKey) || [];
    if (early.length < 120) {
      early.push(candidate);
      state.earlyIce.set(queueKey, early);
    }
  }

  function handleCallDecline(payload) {
    if (!payload || payload.callId !== state.callId || payload.from !== state.callPeer) return;
    showToast(`#${payload.from} declined the call.`);
    cleanupCall();
  }

  function handleRemoteCallEnd(payload) {
    const matchesActive = payload && payload.callId === state.callId && payload.from === state.callPeer;
    const matchesPending =
      payload &&
      state.pendingCall &&
      payload.callId === state.pendingCall.callId &&
      payload.from === state.pendingCall.from;
    if (!matchesActive && !matchesPending) return;
    showToast('Call ended.');
    cleanupCall();
  }

  function cleanupCall() {
    window.clearTimeout(state.callTimer);
    window.clearTimeout(state.callDisconnectTimer);
    state.callTimer = null;
    state.callDisconnectTimer = null;

    if (state.peerConnection) {
      state.peerConnection.onicecandidate = null;
      state.peerConnection.ontrack = null;
      state.peerConnection.onconnectionstatechange = null;
      state.peerConnection.close();
    }
    if (state.localStream) {
      for (const track of state.localStream.getTracks()) track.stop();
    }
    if (state.remoteStream) {
      for (const track of state.remoteStream.getTracks()) track.stop();
    }

    state.peerConnection = null;
    state.localStream = null;
    state.remoteStream = null;
    state.callPeer = null;
    state.callId = null;
    state.callRole = null;
    state.pendingCall = null;
    state.pendingIce = [];
    state.earlyIce.clear();
    state.callSignalReady = false;
    state.outgoingIce = [];
    elements.localVideo.srcObject = null;
    elements.remoteVideo.srcObject = null;
    elements.remotePlaceholder.classList.remove('hidden');
    elements.callScreen.classList.add('hidden');
    elements.incomingCallModal.classList.add('hidden');
  }

  function endCall(notify = true) {
    if (notify && state.socket && state.socket.connected && state.callPeer && state.callId) {
      state.socket.emit('call:end', { to: state.callPeer, callId: state.callId });
    }
    cleanupCall();
  }

  function toggleMicrophone() {
    if (!state.localStream) return;
    const track = state.localStream.getAudioTracks()[0];
    if (!track) return;
    track.enabled = !track.enabled;
    elements.toggleMicButton.classList.toggle('off', !track.enabled);
    elements.toggleMicButton.querySelector('.icon-mic-on').classList.toggle('hidden', !track.enabled);
    elements.toggleMicButton.querySelector('.icon-mic-off').classList.toggle('hidden', track.enabled);
    elements.toggleMicButton.setAttribute('aria-label', track.enabled ? 'Mute microphone' : 'Unmute microphone');
  }

  function toggleCamera() {
    if (!state.localStream) return;
    const track = state.localStream.getVideoTracks()[0];
    if (!track) return;
    track.enabled = !track.enabled;
    elements.toggleCameraButton.classList.toggle('off', !track.enabled);
    elements.toggleCameraButton.querySelector('.icon-camera-on').classList.toggle('hidden', !track.enabled);
    elements.toggleCameraButton.querySelector('.icon-camera-off').classList.toggle('hidden', track.enabled);
    elements.toggleCameraButton.setAttribute('aria-label', track.enabled ? 'Turn camera off' : 'Turn camera on');
  }

  function bindEvents() {
    elements.idForm.addEventListener('submit', registerId);
    elements.idCode.addEventListener('input', checkAvailability);
    elements.restoreButton.addEventListener('click', () => elements.restoreFile.click());
    elements.restoreFile.addEventListener('change', () => restoreBackup(elements.restoreFile.files[0]));
    elements.copyOwnId.addEventListener('click', copyOwnCode);
    elements.backupButton.addEventListener('click', downloadBackup);
    elements.addChatButton.addEventListener('click', () => {
      elements.addChatError.textContent = '';
      openModal(elements.addChatModal);
      requestAnimationFrame(() => elements.contactCode.focus());
    });
    elements.emptyAddChatButton.addEventListener('click', () => elements.addChatButton.click());
    elements.addChatForm.addEventListener('submit', addContactFromModal);
    elements.contactCode.addEventListener('input', () => {
      elements.contactCode.value = sanitizeCode(elements.contactCode.value);
      elements.addChatError.textContent = '';
    });
    elements.chatSearch.addEventListener('input', renderContacts);
    elements.composer.addEventListener('submit', sendMessage);
    elements.messageInput.addEventListener('input', handleMessageInput);
    elements.messageInput.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
        event.preventDefault();
        elements.composer.requestSubmit();
      }
    });
    elements.mobileBackButton.addEventListener('click', () => {
      elements.app.classList.remove('mobile-chat-open');
    });
    elements.safetyButton.addEventListener('click', showSafetyCode);
    elements.peerDetailsButton.addEventListener('click', showSafetyCode);
    elements.videoCallButton.addEventListener('click', startVideoCall);
    elements.acceptCallButton.addEventListener('click', acceptIncomingCall);
    elements.declineCallButton.addEventListener('click', declineIncomingCall);
    elements.endCallButton.addEventListener('click', () => endCall(true));
    elements.toggleMicButton.addEventListener('click', toggleMicrophone);
    elements.toggleCameraButton.addEventListener('click', toggleCamera);

    for (const closeButton of document.querySelectorAll('[data-close-modal]')) {
      closeButton.addEventListener('click', () => {
        const target = document.getElementById(closeButton.dataset.closeModal);
        if (target) closeModal(target);
      });
    }

    elements.addChatModal.addEventListener('click', (event) => {
      if (event.target === elements.addChatModal) closeModal(elements.addChatModal);
    });
    elements.safetyModal.addEventListener('click', (event) => {
      if (event.target === elements.safetyModal) closeModal(elements.safetyModal);
    });

    document.addEventListener('visibilitychange', () => {
      if (!document.hidden && state.activePeer) {
        const contact = getContact(state.activePeer);
        if (contact && contact.unread > 0) {
          contact.unread = 0;
          saveContacts();
          renderContacts();
        }
      }
    });

    document.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape') return;
      if (!elements.callScreen.classList.contains('hidden')) return;
      if (!elements.incomingCallModal.classList.contains('hidden')) {
        declineIncomingCall();
        return;
      }
      closeModal(elements.addChatModal);
      closeModal(elements.safetyModal);
    });

    window.addEventListener('beforeunload', () => {
      if (state.callPeer && state.callId && state.socket && state.socket.connected) {
        state.socket.emit('call:end', { to: state.callPeer, callId: state.callId });
      }
      if (state.localStream) {
        for (const track of state.localStream.getTracks()) track.stop();
      }
    });
  }

  bootstrap().catch((error) => {
    setAuthError(error.message || 'The application could not start.');
  });
})();
