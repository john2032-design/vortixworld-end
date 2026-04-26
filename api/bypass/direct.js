export const config = {
  runtime: "nodejs"
};

import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET;
const BT_API_KEY = process.env.BT_API_KEY;

const ALLOWED_TARGET_HOSTS = new Set([
  "linkvertise.com",
  "mboost.me",
  "cuty.io",
  "rekonise.com",
  "ouo.io",
  "work.ink",
  "hydrogen.lat",
  "auth.platorelay.com",
  "fast-links.org",
  "rapid-links.com",
  "rapid-links.net",
  "lockr.so",
  "link-unlocker.com",
  "pandadevelopment.net",
  "new.pandadevelopment.net",
  "cuttlinks.com",
  "cuttlinks.com",
  "trigonevo.com"
]);

const usedTokens = new Map();

function verifyAccess(req) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";

  if (!token) return null;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.typ !== "access") return null;
    return { token, sessionId: decoded.sub };
  } catch {
    return null;
  }
}

function parseBody(req) {
  try {
    if (typeof req.body === "string") return JSON.parse(req.body);
    return req.body || {};
  } catch {
    return null;
  }
}

function validateUrl(raw) {
  let parsed;

  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, error: "INVALID_URL" };
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return { ok: false, error: "INVALID_URL" };
  }

  const host = parsed.hostname.toLowerCase();
  const matchesAllowed = [...ALLOWED_TARGET_HOSTS].some(
    allowed => host === allowed || host.endsWith(`.${allowed}`)
  );

  if (!matchesAllowed) {
    return { ok: false, error: "HOST_NOT_ALLOWED" };
  }

  return { ok: true, url: parsed.toString() };
}

async function validateApiKey(apiKey) {
  if (!apiKey) return false;
  try {
    const res = await fetch(`https://apikey-nine.vercel.app/api/key/info/${apiKey}`);
    const data = await res.json();
    console.log("[validateApiKey] Key:", apiKey.slice(0, 8) + "...", "Response:", data);
    return data.valid === true;
  } catch (err) {
    console.error("[validateApiKey] Fetch error:", err);
    return false;
  }
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-VW-API-Key");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({
      status: "error",
      message: "Method not allowed"
    });
  }

  if (!JWT_SECRET || !BT_API_KEY) {
    return res.status(500).json({
      status: "error",
      message: "Server misconfigured"
    });
  }

  const auth = verifyAccess(req);
  if (!auth) {
    return res.status(401).json({
      status: "error",
      message: "Unauthorized"
    });
  }

  const { token, sessionId } = auth;

  if (usedTokens.has(token)) {
    return res.status(401).json({
      status: "error",
      message: "Token already used"
    });
  }

  const apiKey = req.headers["x-vw-api-key"] || req.headers["X-VW-API-Key"] || "";
  console.log("[bypass/direct] Received API key:", apiKey ? apiKey.slice(0, 8) + "..." : "MISSING");

  const isKeyValid = await validateApiKey(apiKey);
  if (!isKeyValid) {
    return res.status(401).json({
      status: "error",
      message: "Invalid API key"
    });
  }

  const body = parseBody(req);
  if (!body) {
    return res.status(400).json({
      status: "error",
      message: "Invalid JSON body"
    });
  }

  const { url } = body;

  if (!url || typeof url !== "string") {
    return res.status(400).json({
      status: "error",
      message: "Missing url parameter"
    });
  }

  const check = validateUrl(url);
  if (!check.ok) {
    return res.status(400).json({
      status: "error",
      message: check.error
    });
  }

  try {
    const upstream = await fetch(
      `https://lootlinkcom.vercel.app/api/bypass?url=${encodeURIComponent(check.url)}`
    );

    const text = await upstream.text();

    usedTokens.set(token, Date.now());
    setTimeout(() => usedTokens.delete(token), 15 * 60 * 1000);

    res.status(upstream.status);
    res.setHeader("Content-Type", "application/json");
    return res.send(text);
  } catch (err) {
    usedTokens.set(token, Date.now());
    setTimeout(() => usedTokens.delete(token), 15 * 60 * 1000);

    console.error("PROXY ERROR:", err);

    return res.status(500).json({
      status: "error",
      message: "Proxy failed"
    });
  }
}