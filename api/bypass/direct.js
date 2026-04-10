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
  "new.pandadevelopment.net"
]);

function verifyAccess(req) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";

  if (!token) return null;

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.typ !== "access") return null;
    return decoded.sub;
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

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
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

  const session = verifyAccess(req);
  if (!session) {
    return res.status(401).json({
      status: "error",
      message: "Unauthorized"
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

    res.status(upstream.status);
    res.setHeader("Content-Type", "application/json");
    return res.send(text);
  } catch (err) {
    console.error("PROXY ERROR:", err);

    return res.status(500).json({
      status: "error",
      message: "Proxy failed"
    });
  }
}