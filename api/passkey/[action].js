// api/passkey/[action].js  —  Vercel Serverless Function (Hobby plan, free)
// Passkey (WebAuthn) backend for MART Drive. Replaces the old passkey-server.js.
// Firebase Spark plan is enough: Admin SDK is used only to verify ID tokens,
// store passkeys in Firestore and mint custom tokens.
//
// Env: FIREBASE_SERVICE_ACCOUNT = full service-account JSON text
//      PASSKEY_ALLOWED_ORIGINS  = optional, comma-separated extra origins
//
// Endpoints (base: https://mart-drive.vercel.app/api/passkey):
//   GET  /health                                   -> { ok, configured }
//   POST /register-options  [Bearer ID token]      -> { challengeId, options }
//   POST /register-verify   [Bearer ID token]      { challengeId, response, name? } -> { ok, passkey }
//   POST /login-options                            -> { challengeId, options }
//   POST /login-verify                             { challengeId, response } -> { ok, token, uid }
//   GET  /list              [Bearer ID token]      -> { passkeys: [...] }
//   POST /delete            [Bearer ID token]      { id } -> { ok }

const { initializeApp, getApps, cert } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore, FieldValue, Timestamp } = require("firebase-admin/firestore");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");
const { isoBase64URL, isoUint8Array } = require("@simplewebauthn/server/helpers");

const RP_NAME = "MART Drive";
const DEFAULT_ORIGINS = ["https://mart-drive.vercel.app", "https://mart-drive.web.app", "https://mart-drive.firebaseapp.com"];
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const MAX_PASSKEYS_PER_USER = 10;
const PASSKEYS = "passkeys";
const CHALLENGES = "passkeyChallenges";

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// Accepts the key file as raw JSON or as base64-encoded JSON.
function parseServiceAccount(raw) {
  const text = raw.trim();
  let sa;
  for (const candidate of [text, Buffer.from(text, "base64").toString("utf8")]) {
    try {
      sa = JSON.parse(candidate);
      break;
    } catch {}
  }
  if (!sa || sa.type !== "service_account" || !sa.private_key || !sa.client_email) {
    throw new HttpError(500, "FIREBASE_SERVICE_ACCOUNT must contain the Firebase service account JSON key file");
  }
  sa.private_key = sa.private_key.replace(/\\n/g, "\n");
  return sa;
}

function admin() {
  if (!getApps().length) {
    const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
    if (!raw) throw new HttpError(500, "FIREBASE_SERVICE_ACCOUNT is not set");
    const sa = parseServiceAccount(raw);
    initializeApp({ credential: cert(sa), projectId: sa.project_id });
  }
  return { auth: getAuth(), db: getFirestore() };
}

function allowedOrigins() {
  const extra = String(process.env.PASSKEY_ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim().replace(/\/+$/, ""))
    .filter(Boolean);
  return new Set([...DEFAULT_ORIGINS, ...extra]);
}

function isAllowedOrigin(origin) {
  if (!origin) return false;
  if (allowedOrigins().has(origin)) return true;
  try {
    const u = new URL(origin);
    return u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1");
  } catch {
    return false;
  }
}

function resolveOrigin(req) {
  const origin = String(req.headers.origin || "").replace(/\/+$/, "");
  if (!isAllowedOrigin(origin)) throw new HttpError(403, "Origin not allowed: " + (origin || "(none)"));
  return { origin, rpID: new URL(origin).hostname };
}

function setCors(req, res) {
  const origin = String(req.headers.origin || "").replace(/\/+$/, "");
  if (isAllowedOrigin(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Max-Age", "600");
  }
}

function send(res, status, data) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify(data));
}

function readBody(req) {
  const b = req.body;
  if (!b) return {};
  if (typeof b === "string") {
    try {
      return JSON.parse(b);
    } catch {
      throw new HttpError(400, "Invalid JSON body");
    }
  }
  return b;
}

async function requireUser(req, auth) {
  const m = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || ""));
  if (!m) throw new HttpError(401, "Missing Firebase ID token");
  try {
    return await auth.verifyIdToken(m[1], true);
  } catch {
    throw new HttpError(401, "Invalid or expired Firebase ID token");
  }
}

async function saveChallenge(db, data) {
  const ref = db.collection(CHALLENGES).doc();
  await ref.set({ ...data, expiresAt: Timestamp.fromMillis(Date.now() + CHALLENGE_TTL_MS) });
  return ref.id;
}

async function takeChallenge(db, id, type) {
  if (typeof id !== "string" || !/^[A-Za-z0-9]{10,40}$/.test(id)) throw new HttpError(400, "Invalid challengeId");
  const ref = db.collection(CHALLENGES).doc(id);
  const data = await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    if (!snap.exists) return null;
    tx.delete(ref);
    return snap.data();
  });
  if (!data || data.type !== type) throw new HttpError(400, "Challenge not found or already used");
  if (data.expiresAt.toMillis() < Date.now()) throw new HttpError(400, "Challenge expired, try again");
  return data;
}

function publicPasskey(id, d) {
  return {
    id,
    name: d.name || "Passkey",
    deviceType: d.deviceType || null,
    backedUp: !!d.backedUp,
    createdAt: d.createdAt ? d.createdAt.toMillis() : null,
    lastUsedAt: d.lastUsedAt ? d.lastUsedAt.toMillis() : null,
  };
}

async function userPasskeys(db, uid) {
  const snap = await db.collection(PASSKEYS).where("uid", "==", uid).get();
  return snap.docs;
}

const actions = {
  async health() {
    return { ok: true, configured: !!process.env.FIREBASE_SERVICE_ACCOUNT };
  },

  async "register-options"(req) {
    const { rpID } = resolveOrigin(req);
    const { auth, db } = admin();
    const user = await requireUser(req, auth);
    const existing = await userPasskeys(db, user.uid);
    if (existing.length >= MAX_PASSKEYS_PER_USER) throw new HttpError(400, "Passkey limit reached");

    const userName = user.email || user.uid;
    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID,
      userName,
      userDisplayName: user.name || userName,
      userID: isoUint8Array.fromUTF8String(user.uid),
      attestationType: "none",
      excludeCredentials: existing.map((d) => ({ id: d.id, transports: d.get("transports") || undefined })),
      authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
    });
    const challengeId = await saveChallenge(db, { type: "register", uid: user.uid, challenge: options.challenge, rpID });
    return { challengeId, options };
  },

  async "register-verify"(req) {
    const { origin, rpID } = resolveOrigin(req);
    const { auth, db } = admin();
    const user = await requireUser(req, auth);
    const body = readBody(req);
    if (!body.response || typeof body.response !== "object") throw new HttpError(400, "Missing response");
    const ch = await takeChallenge(db, body.challengeId, "register");
    if (ch.uid !== user.uid || ch.rpID !== rpID) throw new HttpError(400, "Challenge does not match this user");

    let v;
    try {
      v = await verifyRegistrationResponse({
        response: body.response,
        expectedChallenge: ch.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: false,
      });
    } catch (e) {
      throw new HttpError(400, "Registration failed: " + e.message);
    }
    if (!v.verified) throw new HttpError(400, "Registration could not be verified");

    const { credential, credentialDeviceType, credentialBackedUp } = v.registrationInfo;
    const ref = db.collection(PASSKEYS).doc(credential.id);
    const dup = await ref.get();
    if (dup.exists) throw new HttpError(409, "This passkey is already registered");

    const name = String(body.name || "").trim().slice(0, 60) || "Passkey";
    const doc = {
      uid: user.uid,
      email: user.email || null,
      name,
      rpID,
      publicKey: isoBase64URL.fromBuffer(credential.publicKey),
      counter: credential.counter,
      transports: credential.transports || [],
      deviceType: credentialDeviceType,
      backedUp: credentialBackedUp,
      createdAt: FieldValue.serverTimestamp(),
      lastUsedAt: null,
    };
    await ref.set(doc);
    return { ok: true, passkey: { id: credential.id, name, deviceType: credentialDeviceType, backedUp: credentialBackedUp } };
  },

  async "login-options"(req) {
    const { rpID } = resolveOrigin(req);
    const { db } = admin();
    const options = await generateAuthenticationOptions({ rpID, userVerification: "preferred" });
    const challengeId = await saveChallenge(db, { type: "login", challenge: options.challenge, rpID });
    return { challengeId, options };
  },

  async "login-verify"(req) {
    const { origin, rpID } = resolveOrigin(req);
    const { auth, db } = admin();
    const body = readBody(req);
    const response = body.response;
    if (!response || typeof response !== "object" || typeof response.id !== "string") throw new HttpError(400, "Missing response");
    const ch = await takeChallenge(db, body.challengeId, "login");
    if (ch.rpID !== rpID) throw new HttpError(400, "Challenge does not match this site");

    const ref = db.collection(PASSKEYS).doc(response.id);
    const snap = await ref.get();
    if (!snap.exists) throw new HttpError(404, "Passkey not recognised. Sign in with Google and add it again.");
    const pk = snap.data();

    let v;
    try {
      v = await verifyAuthenticationResponse({
        response,
        expectedChallenge: ch.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        credential: {
          id: snap.id,
          publicKey: isoBase64URL.toBuffer(pk.publicKey),
          counter: pk.counter || 0,
          transports: pk.transports || undefined,
        },
        requireUserVerification: false,
      });
    } catch (e) {
      throw new HttpError(401, "Passkey sign-in failed: " + e.message);
    }
    if (!v.verified) throw new HttpError(401, "Passkey could not be verified");

    const userHandle = response.response && response.response.userHandle;
    if (userHandle && isoUint8Array.toUTF8String(isoBase64URL.toBuffer(userHandle)) !== pk.uid) {
      throw new HttpError(401, "Passkey does not belong to this account");
    }

    try {
      const u = await auth.getUser(pk.uid);
      if (u.disabled) throw new HttpError(403, "Account is disabled");
    } catch (e) {
      if (e instanceof HttpError) throw e;
      throw new HttpError(404, "Account no longer exists");
    }

    await ref.update({ counter: v.authenticationInfo.newCounter, lastUsedAt: FieldValue.serverTimestamp() });
    const token = await auth.createCustomToken(pk.uid, { passkey: true });
    return { ok: true, token, uid: pk.uid };
  },

  async list(req) {
    const { auth, db } = admin();
    const user = await requireUser(req, auth);
    const docs = await userPasskeys(db, user.uid);
    return { passkeys: docs.map((d) => publicPasskey(d.id, d.data())).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0)) };
  },

  async delete(req) {
    const { auth, db } = admin();
    const user = await requireUser(req, auth);
    const { id } = readBody(req);
    if (typeof id !== "string" || !id || id.length > 512) throw new HttpError(400, "Missing passkey id");
    const ref = db.collection(PASSKEYS).doc(id);
    const snap = await ref.get();
    if (!snap.exists || snap.get("uid") !== user.uid) throw new HttpError(404, "Passkey not found");
    await ref.delete();
    return { ok: true };
  },
};

const GET_ACTIONS = new Set(["health", "list"]);

module.exports = async (req, res) => {
  setCors(req, res);
  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    return res.end();
  }

  const raw = req.query && req.query.action;
  const action = String(Array.isArray(raw) ? raw[0] : raw || "");
  const handler = Object.prototype.hasOwnProperty.call(actions, action) ? actions[action] : null;
  if (!handler) return send(res, 404, { error: "Unknown action" });

  const method = GET_ACTIONS.has(action) ? "GET" : "POST";
  if (req.method !== method) {
    res.setHeader("Allow", method + ", OPTIONS");
    return send(res, 405, { error: "Use " + method });
  }

  try {
    send(res, 200, await handler(req));
  } catch (e) {
    const status = e instanceof HttpError ? e.status : 500;
    if (status >= 500) console.error("[passkey]", action, e);
    send(res, status, { error: status >= 500 && !(e instanceof HttpError) ? "Server error" : e.message });
  }
};
