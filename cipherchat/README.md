# CipherChat

CipherChat is a polished one-to-one messaging website with a WhatsApp-inspired layout, permanently unique four-digit IDs, encrypted message content, presence, encrypted history, and browser-to-browser video calls.

## Included

- Permanent four-digit account IDs from `0000` through `9999`
- Server-side duplicate prevention, including across restarts and simultaneous connection attempts
- Random 256-bit account tokens; only a peppered hash is stored by the server
- Add-chat flow using another person's ID
- Real-time one-to-one messaging with offline encrypted history
- Browser-side P-256 ECDH key agreement, HKDF-SHA-256, and AES-256-GCM
- First-seen contact-key pinning plus safety codes for manual key verification
- WebRTC video and audio calls with accept, decline, mute, camera, and hang-up controls
- Conversation-key encryption for SDP offers, answers, and ICE candidates
- Presence and typing indicators
- Responsive desktop and mobile layouts
- Account backup and restore for the login token, encryption identity, contact list, and known contact keys
- Security headers, API and socket rate controls, payload limits, and output-safe DOM rendering
- Docker and Docker Compose deployment files

## Run locally

Requirements: Node.js 20 or newer.

```bash
cp .env.example .env
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

Put the generated value in `.env` as `TOKEN_PEPPER`, then run:

```bash
npm install
npm start
```

Open `http://localhost:3000` in two different browser profiles. Choose a different four-digit ID in each profile, add the other ID, and start messaging.

For development with automatic server restarts:

```bash
npm run dev
```

Run the included checks:

```bash
npm run check
npm test
```

## Docker

Set a long random pepper in a local `.env` file:

```env
TOKEN_PEPPER=replace-this-with-a-long-random-secret
```

Then run:

```bash
docker compose up --build
```

The Compose file keeps account and encrypted-message data in a persistent volume.

## Production deployment requirements

### HTTPS

Deploy behind HTTPS. Browsers permit camera and microphone access on secure origins and on localhost. Your reverse proxy must also support WebSocket upgrades for Socket.IO.

Set this when there is exactly one trusted reverse proxy in front of the app:

```env
TRUST_PROXY=1
```

### Persistent storage

`DATA_DIR` must point to persistent storage. Losing that directory loses the account registry and encrypted message envelopes. Changing `TOKEN_PEPPER` makes existing account tokens fail authentication.

This starter uses atomic JSON files and is intentionally single-instance. For a larger deployment, move users and messages to a transactional database and move presence and Socket.IO coordination to Redis or another shared real-time store.

### TURN for reliable video calls

A public STUN endpoint is included by default for direct peer discovery. Set `STUN_URLS` to your own STUN service when you do not want to use the default third-party endpoint. Some mobile, enterprise, hotel, and carrier networks cannot establish a direct peer connection. Add a TURN service for reliable calling:

```env
STUN_URLS=stun:stun.your-domain.example:3478
TURN_URLS=turn:turn.example.com:3478?transport=udp,turns:turn.example.com:5349?transport=tcp
TURN_USERNAME=your-turn-user
TURN_CREDENTIAL=your-turn-password
```

TURN relays WebRTC packets when a direct path is unavailable. The media remains protected by WebRTC transport encryption, but the TURN operator still observes connection metadata. Static TURN credentials returned to registered clients can be copied, so a larger deployment should issue short-lived TURN credentials instead.

## Security model

### Messages

Each browser creates a persistent P-256 identity key pair. For each contact, both participants independently derive the same shared secret with ECDH. That secret is expanded through HKDF-SHA-256 into a conversation-specific AES-256-GCM key. Message text is encrypted in the browser before the encrypted envelope is sent to the server.

The server stores and relays:

- Sender and recipient IDs
- Message IDs and timestamps
- Public identity keys
- AES-GCM IVs and ciphertext
- Network and presence metadata needed to operate the service

The server does not receive message plaintext or private identity keys.

### Pinned keys and safety codes

The first valid public key seen for each contact is pinned in browser storage and included in account backups. A later key change is blocked instead of being accepted silently. A malicious or compromised server could still substitute a key during the very first contact, so both users should compare the safety code through a trusted channel when identity assurance matters. Matching codes confirm that both devices are using the same pair of identity keys.

### Calls

Calls use a direct two-party `RTCPeerConnection`. WebRTC protects audio and video with DTLS-SRTP. Before signaling, each browser also encrypts SDP offers, answers, and ICE candidates with a separate conversation-derived AES-256-GCM key. The signaling server relays those encrypted envelopes and does not receive readable session descriptions, network candidates, or decoded media. A configured TURN server may relay encrypted media packets when direct connectivity fails.

## Important limitations

This is a strong, functional starter, not a third-party-audited replacement for the Signal protocol.

- Static identity-key ECDH does not provide per-message forward secrecy or post-compromise security.
- Four digits provide only 10,000 total IDs. IDs are permanently reserved unless you add an administrative release policy.
- The downloaded account backup contains the account token, private encryption key, contact list, and known contact keys in readable JSON. Treat it like a master key and store it securely.
- The login token is stored in browser local storage; the private key is stored in IndexedDB. Strong content security policy and output-safe rendering reduce risk, but a successful same-origin compromise could still access browser credentials.
- The server can see communication metadata even though it cannot read message content or encrypted call signaling.
- There are no group chats, attachments, push notifications, multi-device key synchronization, message deletion, or moderation console in this version.
- The JSON persistence layer is suitable for a controlled starter deployment, not a large multi-process service.

Before handling sensitive or high-risk communications, commission an independent application, infrastructure, and cryptographic security review. For a mass-market product, replace the custom message-key design with a mature, audited protocol implementation that supports prekeys, key rotation, forward secrecy, and multi-device sessions.

## Project layout

```text
cipherchat/
  server.js                  Express, Socket.IO, authentication, signaling
  lib/store.js               Persistent ID and encrypted-message storage
  public/index.html          Application structure
  public/styles.css          Responsive messenger and call interface
  public/app.js              Browser keys, encryption, chat, presence, WebRTC
  test/                      Storage, crypto-protocol, and DOM contract tests
  Dockerfile
  docker-compose.yml
  .env.example
```
