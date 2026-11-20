// Free passkey backend for MART Drive, deployed as a Vercel Serverless Function.
// File location in your repo: api/passkey/[action].js
// Routes: POST /api/passkey/register-options, /register-verify, /login-options, /login-verify
// Needs: package.json dependencies: firebase-admin, @simplewebauthn/server
// Needs env var on Vercel: FIREBASE_SERVICE_ACCOUNT = full JSON of a service account key
// (Firebase Console → Project settings → Service accounts → Generate new private key)

const admin = require('firebase-admin');
const {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse
} = require('@simplewebauthn/server');

if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)) });
}
const db = admin.firestore();

// Passkeys are bound to this domain.
const RP = { name: 'MART Drive', id: 'mart-drive.vercel.app', origin: 'https://mart-drive.vercel.app' };

const bearer = req => (req.headers.authorization || '').replace('Bearer ', '');
const uidFromToken = async req => (await admin.auth().verifyIdToken(bearer(req))).uid;
const normEmail = e => String(e || '').trim().toLowerCase();

async function getChallenge(key) {
  const snap = await db.collection('challenges').doc(key).get();
  if (!snap.exists) throw new Error('Challenge expired. Try again.');
  await db.collection('challenges').doc(key).delete(); // one-time use, prevents replay
  return snap.data().c;
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  const action = req.query.action;

  try {
    // ---- Add a passkey (logged-in user only) ----
    if (action === 'register-options') {
      const uid = await uidFromToken(req);
      const user = await admin.auth().getUser(uid);
      const existing = await db.collection('passkeys').where('uid', '==', uid).get();
      const options = await generateRegistrationOptions({
        rpName: RP.name, rpID: RP.id,
        userName: user.email, userID: Buffer.from(uid),
        excludeCredentials: existing.docs.map(d => ({ id: d.id, transports: d.data().transports })),
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' }
      });
      await db.collection('challenges').doc(uid).set({ c: options.challenge });
      return res.json({ options });
    }

    if (action === 'register-verify') {
      const uid = await uidFromToken(req);
      const ch = await getChallenge(uid);
      const v = await verifyRegistrationResponse({
        response: req.body.response, expectedChallenge: ch,
        expectedOrigin: RP.origin, expectedRPID: RP.id
      });
      if (!v.verified) return res.status(400).json({ error: 'Passkey could not be verified' });
      const c = v.registrationInfo.credential;
      await db.collection('passkeys').doc(c.id).set({
        uid, publicKey: Buffer.from(c.publicKey).toString('base64'),
        counter: c.counter, transports: c.transports || []
      });
      return res.json({ ok: true });
    }

    // ---- Log in with email + passkey ----
    if (action === 'login-options') {
      const email = normEmail(req.body.email);
      const user = await admin.auth().getUserByEmail(email).catch(() => null);
      const creds = user
        ? (await db.collection('passkeys').where('uid', '==', user.uid).get()).docs.map(d => ({ id: d.id, transports: d.data().transports }))
        : [];
      const options = await generateAuthenticationOptions({ rpID: RP.id, allowCredentials: creds, userVerification: 'required' });
      await db.collection('challenges').doc('login_' + email).set({ c: options.challenge });
      return res.json({ options });
    }

    if (action === 'login-verify') {
      const email = normEmail(req.body.email);
      const ch = await getChallenge('login_' + email);
      const pk = await db.collection('passkeys').doc(req.body.response.id).get();
      if (!pk.exists) return res.status(400).json({ error: 'Passkey not found' });
      const d = pk.data();
      const v = await verifyAuthenticationResponse({
        response: req.body.response, expectedChallenge: ch,
        expectedOrigin: RP.origin, expectedRPID: RP.id,
        credential: { id: req.body.response.id, publicKey: Buffer.from(d.publicKey, 'base64'), counter: d.counter, transports: d.transports }
      });
      if (!v.verified) return res.status(400).json({ error: 'Passkey could not be verified' });
      const user = await admin.auth().getUser(d.uid);
      if (normEmail(user.email) !== email) return res.status(400).json({ error: 'This passkey does not belong to that email' });
      await pk.ref.update({ counter: v.authenticationInfo.newCounter });
      return res.json({ token: await admin.auth().createCustomToken(d.uid) });
    }

    return res.status(404).json({ error: 'Unknown action' });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
};
