export const config = { runtime: "nodejs" };

import jwt from "jsonwebtoken";
import { randomUUID } from "crypto";
import { createPool } from "@vercel/postgres";

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;
const connectionString = process.env.APIKey_POSTGRES_URL;

const pool = createPool({ connectionString });

function signAccess(sessionId) {
  return jwt.sign({ sub: sessionId, typ: "access" }, JWT_SECRET, { expiresIn: "15m" });
}

function signRefresh(sessionId) {
  return jwt.sign({ sub: sessionId, typ: "refresh" }, REFRESH_SECRET, { expiresIn: "1m" });
}

async function validateApiKey(key) {
  const now = Math.floor(Date.now() / 1000);
  const result = await pool.sql`
    SELECT key, active, expires_at FROM api_keys WHERE key = ${key}
  `;
  if (result.rowCount === 0) return { valid: false, reason: "invalid_key" };
  const row = result.rows[0];
  if (!row.active) return { valid: false, reason: "inactive" };
  if (row.expires_at < now) return { valid: false, reason: "expired" };
  return { valid: true };
}

async function createSession(sessionId, apiKey) {
  const now = Math.floor(Date.now() / 1000);
  await pool.sql`
    INSERT INTO sessions (session_id, api_key, created_at, consumed)
    VALUES (${sessionId}, ${apiKey}, ${now}, 0)
  `;
}

export default async function handler(req, res) {
  try {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Cache-Control", "no-store");

    if (req.method === "OPTIONS") return res.status(200).end();
    if (req.method !== "POST") return res.status(405).json({ status: "error", message: "Method not allowed" });
    if (!JWT_SECRET || !REFRESH_SECRET || !connectionString) {
      return res.status(500).json({ status: "error", message: "Server misconfigured" });
    }

    let body;
    try {
      body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
    } catch {
      return res.status(400).json({ status: "error", message: "Invalid JSON" });
    }

    const { key } = body;
    if (!key || typeof key !== "string") {
      return res.status(400).json({ status: "error", message: "API key required" });
    }

    const validation = await validateApiKey(key);
    if (!validation.valid) {
      return res.status(401).json({ status: "error", message: validation.reason });
    }

    const sessionId = randomUUID();
    await createSession(sessionId, key);

    const accessToken = signAccess(sessionId);
    const refreshToken = signRefresh(sessionId);

    res.setHeader("Set-Cookie", [
      `refresh_token=${refreshToken}; HttpOnly; Path=/api/auth/refresh; Max-Age=60; SameSite=None; Secure`
    ]);

    return res.status(200).json({
      status: "success",
      accessToken,
      expiresIn: 900
    });
  } catch (err) {
    console.error("ANON ERROR:", err);
    return res.status(500).json({ status: "error", message: "Anon failed" });
  }
}