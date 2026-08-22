'use strict';

const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
const test = require('node:test');

const { subtle } = webcrypto;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

async function deriveConversationKey(ownPrivateKey, remotePublicKey, codeA, codeB, purpose = 'message') {
  const sharedBits = await subtle.deriveBits(
    { name: 'ECDH', public: remotePublicKey },
    ownPrivateKey,
    256
  );
  const material = await subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  const pair = [codeA, codeB].sort().join(':');
  const salt = await subtle.digest('SHA-256', encoder.encode(`cipherchat-salt-v1|${pair}`));
  return subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: encoder.encode(`cipherchat-${purpose === 'message' ? 'message' : 'call-signal'}-key-v1|${pair}`)
    },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function aad(message) {
  return encoder.encode(`${message.id}|${message.from}|${message.to}|${message.ts}|${message.version}`);
}

test('both participants derive a compatible key and reject tampering', async () => {
  const alice = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
  const bob = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );

  const aliceKey = await deriveConversationKey(alice.privateKey, bob.publicKey, '0001', '0002');
  const bobKey = await deriveConversationKey(bob.privateKey, alice.publicKey, '0002', '0001');
  const message = {
    id: '6ed7b179-1f5d-44ad-8119-a6a165ea7654',
    from: '0001',
    to: '0002',
    ts: 123456789,
    version: 1
  };
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad(message), tagLength: 128 },
    aliceKey,
    encoder.encode('Private hello')
  );
  const plaintext = await subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: aad(message), tagLength: 128 },
    bobKey,
    ciphertext
  );

  assert.equal(decoder.decode(plaintext), 'Private hello');

  const tampered = new Uint8Array(ciphertext);
  tampered[0] ^= 1;
  await assert.rejects(() => subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: aad(message), tagLength: 128 },
    bobKey,
    tampered
  ));
});


test('call setup signals use a separate authenticated conversation key', async () => {
  const alice = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
  const bob = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
  const aliceCallKey = await deriveConversationKey(
    alice.privateKey,
    bob.publicKey,
    '0001',
    '0002',
    'call'
  );
  const bobCallKey = await deriveConversationKey(
    bob.privateKey,
    alice.publicKey,
    '0002',
    '0001',
    'call'
  );
  const aliceMessageKey = await deriveConversationKey(
    alice.privateKey,
    bob.publicKey,
    '0001',
    '0002',
    'message'
  );
  const callId = '8ed7b179-1f5d-44ad-8119-a6a165ea7654';
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const additionalData = encoder.encode(
    `cipherchat-call-signal-v1|${callId}|0001|0002|offer`
  );
  const offer = { type: 'offer', sdp: 'private-session-description' };
  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData, tagLength: 128 },
    aliceCallKey,
    encoder.encode(JSON.stringify(offer))
  );
  const plaintext = await subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData, tagLength: 128 },
    bobCallKey,
    ciphertext
  );

  assert.deepEqual(JSON.parse(decoder.decode(plaintext)), offer);
  await assert.rejects(() => subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData, tagLength: 128 },
    aliceMessageKey,
    ciphertext
  ));
});
