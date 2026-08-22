'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { Store } = require('../lib/store');

test('reserves each four-digit code only once and authenticates its owner', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cipherchat-store-'));
  const store = new Store(directory);

  assert.equal(store.createUser('0042', 'aa'.repeat(32)), true);
  assert.equal(store.createUser('0042', 'bb'.repeat(32)), false);
  assert.equal(store.authenticate('0042', 'aa'.repeat(32)), true);
  assert.equal(store.authenticate('0042', 'bb'.repeat(32)), false);

  const reloadedStore = new Store(directory);
  assert.equal(reloadedStore.hasUser('0042'), true);
  assert.equal(reloadedStore.authenticate('0042', 'aa'.repeat(32)), true);
});

test('stores encrypted message envelopes and returns one conversation', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cipherchat-store-'));
  const store = new Store(directory);

  const message = {
    id: '6ed7b179-1f5d-44ad-8119-a6a165ea7654',
    from: '0001',
    to: '0002',
    ts: 1,
    receivedAt: 2,
    iv: 'aGVsbG8=',
    ciphertext: 'd29ybGQ=',
    version: 1
  };

  assert.equal(store.addMessage(message), true);
  assert.equal(store.addMessage(message), false);
  assert.deepEqual(store.getConversation('0001', '0002'), [message]);
  assert.deepEqual(store.getConversation('0001', '0003'), []);
});


test('tracks pending delivery without exposing message plaintext', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cipherchat-store-'));
  const store = new Store(directory);
  const message = {
    id: '7ed7b179-1f5d-44ad-8119-a6a165ea7654',
    from: '0001',
    to: '0002',
    ts: 1,
    receivedAt: 2,
    deliveredAt: null,
    iv: 'aGVsbG8=',
    ciphertext: 'd29ybGQ=',
    version: 1
  };

  store.addMessage(message);
  assert.equal(store.getUndelivered('0002').length, 1);
  const delivered = store.markDelivered(message.id, '0002');
  assert.ok(Number.isFinite(delivered.deliveredAt));
  assert.equal(store.getUndelivered('0002').length, 0);
  assert.equal(store.markDelivered(message.id, '0003'), null);
});


test('marks a batch of pending messages with one recipient boundary', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cipherchat-store-'));
  const store = new Store(directory);
  const makeMessage = (id, to) => ({
    id,
    from: '0001',
    to,
    ts: 1,
    receivedAt: 2,
    deliveredAt: null,
    iv: 'aGVsbG8=',
    ciphertext: 'd29ybGQ=',
    version: 1
  });

  store.addMessage(makeMessage('9ed7b179-1f5d-44ad-8119-a6a165ea7654', '0002'));
  store.addMessage(makeMessage('aed7b179-1f5d-44ad-8119-a6a165ea7654', '0002'));
  store.addMessage(makeMessage('bed7b179-1f5d-44ad-8119-a6a165ea7654', '0003'));

  const delivered = store.markDeliveredBatch([
    '9ed7b179-1f5d-44ad-8119-a6a165ea7654',
    'aed7b179-1f5d-44ad-8119-a6a165ea7654',
    'bed7b179-1f5d-44ad-8119-a6a165ea7654'
  ], '0002');

  assert.equal(delivered.length, 2);
  assert.equal(store.getUndelivered('0002').length, 0);
  assert.equal(store.getUndelivered('0003').length, 1);
});
