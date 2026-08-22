# CipherChat - Google Account setup

This is the Google-account build of CipherChat for GitHub Pages + Firebase.

## Already done

- GitHub Pages hosts the website.
- Firebase Authentication should have Google enabled.
- Firebase Realtime Database should already exist.

## 1. Publish the NEW database rules

In Firebase Console open:

Realtime Database > Rules

Delete the old rules and paste the entire contents of `firebase.rules.json` from this package. Click **Publish**.

These rules link every four-digit CipherChat ID to the Firebase `auth.uid` of the Google account that claimed it.

## 2. Register your website as a Firebase Web App

Firebase Console > Project settings (gear) > General > Your apps > Add app > Web (`</>`).

Give it a nickname such as `CipherChat Web`. You do NOT need Firebase Hosting because GitHub Pages is your host.

After registering, Firebase shows a configuration object containing values such as `apiKey`, `authDomain`, `projectId`, and `appId`.

Copy those values into `firebase-config.js`.

IMPORTANT: for `databaseURL`, use the exact URL shown at the top of your Realtime Database Data tab. It looks similar to:

`https://YOUR-PROJECT-default-rtdb.REGION.firebasedatabase.app`

## 3. Authorized domain

Firebase Console > Authentication > Settings > Authorized domains.

Add your GitHub Pages host, for example:

`yourusername.github.io`

Do not include `https://` or the repository path.

## 4. Upload to GitHub

Replace the files in your GitHub Pages repository with the files from this folder and commit them to the branch used by Pages.

The important files are:

- `index.html`
- `styles.css`
- `app.js`
- `firebase-backend.js`
- `firebase-config.js`
- `.nojekyll`

`firebase.rules.json` is for the Firebase Rules screen; GitHub can contain a copy too.

## 5. Test

1. Open your GitHub Pages URL.
2. Click **Continue with Google**.
3. Select your Google account.
4. Choose a free four-digit CipherChat ID.
5. Open the site in a different Google account/browser and choose another ID.
6. Add the second ID and send a message.
7. Test a video call with both accounts online.

## Account and encryption behavior

- The four-digit ID is permanently linked to the Google account that claimed it.
- Contacts are synchronized through Firebase so the account can recover its chat list after signing back in.
- Encrypted messages stay in Firebase as ciphertext.
- The private end-to-end encryption key stays on the device. Download the **encryption backup** if you want to decrypt old chats on a different device/browser.
- A Google login alone intentionally does not give Firebase a copy of the private encryption key. This preserves the end-to-end encryption design.
- WebRTC media uses the browser's DTLS-SRTP encryption. A TURN service is still recommended later for reliable calls on restrictive/mobile networks.
