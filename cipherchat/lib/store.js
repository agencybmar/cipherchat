'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function readJson(filePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return fallback;
    throw error;
  }
}

function atomicWriteJson(filePath, value) {
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tempPath, JSON.stringify(value, null, 2), { mode: 0o600 });
  fs.renameSync(tempPath, filePath);
}

function safeEqualHex(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  if (!/^[a-f0-9]+$/i.test(left) || !/^[a-f0-9]+$/i.test(right)) return false;
  const leftBuffer = Buffer.from(left, 'hex');
  const rightBuffer = Buffer.from(right, 'hex');
  if (leftBuffer.length !== rightBuffer.length) return false;
  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

class Store {
  constructor(dataDir) {
    this.dataDir = path.resolve(dataDir);
    this.usersFile = path.join(this.dataDir, 'users.json');
    this.messagesFile = path.join(this.dataDir, 'messages.json');

    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });

    this.users = readJson(this.usersFile, {});
    this.messages = readJson(this.messagesFile, []);
    this.messageIds = new Set(this.messages.map((message) => message.id));
  }

  hasUser(code) {
    return Object.prototype.hasOwnProperty.call(this.users, code);
  }

  createUser(code, tokenHash) {
    if (this.hasUser(code)) return false;

    this.users[code] = {
      tokenHash,
      publicKey: null,
      createdAt: Date.now(),
      keyUpdatedAt: null
    };
    atomicWriteJson(this.usersFile, this.users);
    return true;
  }

  authenticate(code, tokenHash) {
    const user = this.users[code];
    if (!user) return false;
    return safeEqualHex(user.tokenHash, tokenHash);
  }

  getUser(code) {
    const user = this.users[code];
    if (!user) return null;
    return {
      code,
      publicKey: user.publicKey,
      createdAt: user.createdAt,
      keyUpdatedAt: user.keyUpdatedAt
    };
  }

  setPublicKey(code, publicKey) {
    if (!this.hasUser(code)) return false;
    this.users[code].publicKey = publicKey;
    this.users[code].keyUpdatedAt = Date.now();
    atomicWriteJson(this.usersFile, this.users);
    return true;
  }

  addMessage(message) {
    if (this.messageIds.has(message.id)) return false;

    this.messages.push(message);
    this.messageIds.add(message.id);

    // This JSON store is intentionally simple. Keep a bounded history so a
    // forgotten deployment cannot grow forever.
    const maxStoredMessages = 100000;
    if (this.messages.length > maxStoredMessages) {
      const removeCount = this.messages.length - maxStoredMessages;
      const removed = this.messages.splice(0, removeCount);
      for (const oldMessage of removed) this.messageIds.delete(oldMessage.id);
    }

    atomicWriteJson(this.messagesFile, this.messages);
    return true;
  }

  getConversation(codeA, codeB, limit = 2000) {
    const conversation = this.messages.filter((message) => {
      return (
        (message.from === codeA && message.to === codeB) ||
        (message.from === codeB && message.to === codeA)
      );
    });

    return conversation.slice(-limit);
  }

  getUndelivered(recipientCode, limit = 2000) {
    return this.messages
      .filter((message) => message.to === recipientCode && !message.deliveredAt)
      .slice(0, limit);
  }

  markDelivered(messageId, recipientCode) {
    const message = this.messages.find((item) => item.id === messageId);
    if (!message || message.to !== recipientCode) return null;
    if (!message.deliveredAt) {
      message.deliveredAt = Date.now();
      atomicWriteJson(this.messagesFile, this.messages);
    }
    return message;
  }

  markDeliveredBatch(messageIds, recipientCode) {
    const requestedIds = new Set(messageIds);
    const newlyDelivered = [];
    const deliveredAt = Date.now();

    for (const message of this.messages) {
      if (!requestedIds.has(message.id) || message.to !== recipientCode || message.deliveredAt) continue;
      message.deliveredAt = deliveredAt;
      newlyDelivered.push(message);
    }

    if (newlyDelivered.length > 0) atomicWriteJson(this.messagesFile, this.messages);
    return newlyDelivered;
  }
}

module.exports = {
  Store,
  safeEqualHex
};
