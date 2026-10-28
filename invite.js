// api/invite.js  —  Vercel Serverless Function
// /?join=CODE লিংকের জন্য organization এর লগো ও নাম সহ link preview (Open Graph) তৈরি করে।
// Firestore এর invites/{CODE} ডকুমেন্ট থেকে orgName, teamName, logoUrl পড়ে।

const PROJECT_ID = "mart-drive";
const API_KEY = "AIzaSyDUcT6hVqLHy3pYzwg1oktI7amTpF9Qj4c";
const SITE_NAME = "MART Drive";
const DEFAULT_IMAGE = "https://i.ibb.co/mrBbnLCS/file-0000000080fc81f88ca15c13f4410789.png";

const esc = (s) =>
  String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function getInvite(code) {
  if (!code) return null;
  try {
    const url =
      "https://firestore.googleapis.com/v1/projects/" + PROJECT_ID +
      "/databases/(default)/documents/invites/" + encodeURIComponent(code) +
      "?key=" + API_KEY;
    const r = await fetch(url);
    if (!r.ok) return null;
    const f = (await r.json()).fields || {};
    const v = (k) => (f[k] && f[k].stringValue) || "";
    return { orgName: v("orgName"), teamName: v("teamName"), logoUrl: v("logoUrl") };
  } catch (e) {
    return null;
  }
}

module.exports = async (req, res) => {
  const proto = String(req.headers["x-forwarded-proto"] || "https").split(",")[0];
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  const origin = proto + "://" + host;
  const raw = req.query && req.query.join;
  const code = String(Array.isArray(raw) ? raw[0] : raw || "").replace(/[^A-Za-z0-9_-]/g, "").slice(0, 64);

  let html;
  try {
    const r = await fetch(origin + "/index.html");
    if (!r.ok) throw new Error("index.html " + r.status);
    html = await r.text();
  } catch (e) {
    // fallback: preview ছাড়াই অ্যাপ খুলবে, join কাজ করবে
    res.statusCode = 302;
    res.setHeader("Location", "/index.html" + (code ? "?join=" + code : ""));
    return res.end();
  }

  const inv = await getInvite(code);
  let cache = "public, s-maxage=60";

  if (inv && inv.orgName) {
    const image = /^https?:\/\//i.test(inv.logoUrl) ? inv.logoUrl : DEFAULT_IMAGE;
    const title = "Join " + inv.orgName + " on " + SITE_NAME;
    const desc =
      "You've been invited to join " + inv.orgName +
      (inv.teamName ? " (Team: " + inv.teamName + ")" : "") +
      ". Open the link to send your join request.";
    const url = origin + "/?join=" + code;

    const tags = [
      ["property", "og:type", "website"],
      ["property", "og:title", title],
      ["property", "og:description", desc],
      ["property", "og:url", url],
      ["property", "og:site_name", SITE_NAME],
      ["property", "og:image", image],
      ["property", "og:image:secure_url", image],
      ["property", "og:image:alt", inv.orgName + " logo"],
      ["name", "twitter:card", "summary"],
      ["name", "twitter:title", title],
      ["name", "twitter:description", desc],
      ["name", "twitter:image", image],
    ]
      .map((t) => '<meta ' + t[0] + '="' + t[1] + '" content="' + esc(t[2]) + '">')
      .join("\n");

    html = html
      .replace(/<meta\s+(?:property|name)=["'](?:og:|twitter:)[^>]*>\s*/gi, "")
      .replace(/<meta\s+name=["']description["'][^>]*>\s*/i, "")
      .replace(/<title>[\s\S]*?<\/title>/i, "<title>" + esc(title) + "</title>")
      .replace(/<\/head>/i, () => '<meta name="description" content="' + esc(desc) + '">\n' + tags + "\n</head>");
    cache = "public, s-maxage=300, stale-while-revalidate=3600";
  }

  res.statusCode = 200;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", cache);
  res.end(html);
};
