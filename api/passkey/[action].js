// MART Drive passkey API (Vercel Serverless Function)
// File: api/passkey/[action].js
// Routes: POST /api/passkey/register-options | register-verify | login-options | login-verify
// Health check: GET /api/passkey/status
// Env var: FIREBASE_SERVICE_ACCOUNT = full service account JSON (Secret)

const RP = { name: 'MART Drive', id: 'mart-drive.vercel.app', origin: 'https://mart-drive.vercel.app' };

// Loaded lazily so any setup problem returns a readable JSON error instead of a crash.
let deps = null;
function load() {
  if (deps) return deps;
  const admin = require('firebase-admin');
  const sw = require('@simplewebauthn/server');
  if (!admin.apps.length) {
    const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (!raw) throw new Error('FIREBASE_SERVICE_ACCOUNT env var is missing in Vercel');
    let sa;
    try { sa = JSON.parse(raw); }
    catch (e) { throw new Error('FIREBASE_SERVICE_ACCOUNT is not valid JSON: ' + e.message); }
    admin.initializeApp({ credential: admin.credential.cert(sa) });
  }
  deps = { admin, db: admin.firestore(), sw };
  return deps;
}

const bearer = req => (req.headers.authorization || '').replace('Bearer ', '');
const normEmail = e => String(e || '').trim().toLowerCase();

async function getChallenge(db, key) {
  const ref = db.collection('challenges').doc(key);
  const snap = await ref.get();
  if (!snap.exists) throw new Error('Challenge expired. Try again.');
  await ref.delete();
  return snap.data().c;
}

module.exports = async function handler(req, res) {
  const action = req.query.action;

  if (req.method === 'GET' && action === 'status') {
    try { load(); return res.status(200).json({ ok: true, message: 'ready' }); }
    catch (e) { return res.status(500).json({ ok: false, message: e.message }); }
  }

  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  let d;
  try { d = load(); }
  catch (e) { return res.status(500).json({ error: 'Server setup error: ' + e.message }); }
  const { admin, db, sw } = d;

  try {
    if (action === 'register-options') {
      const uid = (await admin.auth().verifyIdToken(bearer(req))).uid;
      const user = await admin.auth().getUser(uid);
      const existing = await db.collection('passkeys').where('uid', '==', uid).get();
      const options = await sw.generateRegistrationOptions({
        rpName: RP.name, rpID: RP.id,
        userName: user.email, userID: Buffer.from(uid),
        excludeCredentials: existing.docs.map(x => ({ id: x.id, transports: x.data().transports })),
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' }
      });
      await db.collection('challenges').doc(uid).set({ c: options.challenge });
      return res.json({ options });
    }

    if (action === 'register-verify') {
      const uid = (await admin.auth().verifyIdToken(bearer(req))).uid;
      const ch = await getChallenge(db, uid);
      const v = await sw.verifyRegistrationResponse({
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

    if (action === 'login-options') {
      const email = normEmail(req.body.email);
      const user = await admin.auth().getUserByEmail(email).catch(() => null);
      const creds = user
        ? (await db.collection('passkeys').where('uid', '==', user.uid).get()).docs.map(x => ({ id: x.id, transports: x.data().transports }))
        : [];
      const options = await sw.generateAuthenticationOptions({ rpID: RP.id, allowCredentials: creds, userVerification: 'required' });
      await db.collection('challenges').doc('login_' + email).set({ c: options.challenge });
      return res.json({ options });
    }

    if (action === 'login-verify') {
      const email = normEmail(req.body.email);
      const ch = await getChallenge(db, 'login_' + email);
      const pk = await db.collection('passkeys').doc(req.body.response.id).get();
      if (!pk.exists) return res.status(400).json({ error: 'Passkey not found' });
      const x = pk.data();
      const v = await sw.verifyAuthenticationResponse({
        response: req.body.response, expectedChallenge: ch,
        expectedOrigin: RP.origin, expectedRPID: RP.id,
        credential: { id: req.body.response.id, publicKey: Buffer.from(x.publicKey, 'base64'), counter: x.counter, transports: x.transports }
      });
      if (!v.verified) return res.status(400).json({ error: 'Passkey could not be verified' });
      const user = await admin.auth().getUser(x.uid);
      if (normEmail(user.email) !== email) return res.status(400).json({ error: 'This passkey does not belong to that email' });
      await pk.ref.update({ counter: v.authenticationInfo.newCounter });
      return res.json({ token: await admin.auth().createCustomToken(x.uid) });
    }

    return res.status(404).json({ error: 'Unknown action' });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
};
