# CipherChat on GitHub Pages + Firebase

This build is static and is intended to be hosted directly by GitHub Pages. Firebase supplies authentication, the real-time database, presence, encrypted-message relay, and WebRTC signaling. Message and call payloads are encrypted in the browser before Firebase receives them.

## 1. Create a Firebase project

1. Go to Firebase Console and create a project.
2. In **Build > Authentication > Sign-in method**, enable **Email/Password**. Do not enable Email Link instead; regular Email/Password must be enabled.
3. In **Build > Realtime Database**, create a database. Pick the region closest to your users. Start in locked mode.
4. In **Project settings > Your apps**, add a **Web app**.
5. In **Authentication > Settings > Authorized domains**, add your GitHub Pages host (for example `yourname.github.io`) if it is not already listed.
6. Firebase shows a `firebaseConfig` object. Copy its values into `firebase-config.js` in this repository.

The Firebase web config is not a password and is expected to be visible in a browser. Access control is provided by Authentication + Database Rules.

## 2. Install the database rules

Open **Realtime Database > Rules** in Firebase Console. Replace the existing rules with the contents of `firebase.rules.json`, then click **Publish**.

These rules make four-digit profiles readable only to signed-in CipherChat accounts and restrict user/session/presence writes to the account that owns that four-digit code. Conversation paths can only be read/written by the two participant accounts. Inbox and event queues are restricted to the intended receiver and authenticated sender.

## 3. Put these files at the root of your GitHub repository

The repository root should contain at least:

- `index.html`
- `styles.css`
- `app.js`
- `firebase-config.js`
- `firebase-backend.js`
- `.nojekyll`

`firebase.rules.json` and this setup guide can stay in the repository too.

## 4. Turn on GitHub Pages

In GitHub: **Settings > Pages > Build and deployment > Deploy from a branch**. Choose your main branch and `/ (root)`, then Save.

GitHub will show the final HTTPS URL. Camera/microphone access requires HTTPS, which GitHub Pages provides.

## 5. Test

Open the Pages URL in two separate browsers/devices. Pick a different four-digit ID in each. Add the other code and send a message. For a call, both users must be online.

## Important production notes

- Four-digit IDs provide only 10,000 total possible accounts. This is suitable for a small/private service, not an open large-scale messenger.
- This build uses browser-side P-256 ECDH + AES-GCM for content encryption, but it is not the audited Signal protocol and does not provide Signal's full forward-secrecy/post-compromise guarantees.
- Firebase still sees metadata such as account identifiers, timestamps, presence, sender/recipient relationships, IP/network metadata, and encrypted payload sizes.
- WebRTC media is encrypted in transit by WebRTC (DTLS-SRTP), and call signaling is additionally encrypted by the app. Firebase cannot decrypt the SDP/ICE signaling payloads.
- The default Google STUN server is enough for many calls but not all network combinations. Reliable production calling requires a TURN service; add TURN credentials to the `iceServers` response in `firebase-backend.js` or use a TURN credential service.
- The free Firebase Spark plan has quotas. If usage grows, you may need a paid plan.
