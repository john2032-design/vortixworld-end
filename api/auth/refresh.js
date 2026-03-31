export const config = {
  runtime: "nodejs"
};

import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;

function signAccess(sessionId) {
  return jwt.sign(
    { sub: sessionId, typ: "access" },
    JWT_SECRET,
    { expiresIn: "15m" }
  );
}

function getCookieValue(cookieHeader, name) {
  if (!cookieHeader) return null;

  const parts = cookieHeader.split(";").map(v => v.trim());
  for (const part of parts) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (key === name) return value;
  }

  return null;
}

function verifyRefresh(token) {
  try {
    const decoded = jwt.verify(token, REFRESH_SECRET);
    if (decoded.typ !== "refresh") return null;
    return decoded.sub;
  } catch {
    return null;
  }
}

export default async function handler(req, res) {
  try {
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

    if (!JWT_SECRET || !REFRESH_SECRET) {
      return res.status(500).json({
        status: "error",
        message: "Server misconfigured"
      });
    }

    const token = getCookieValue(req.headers.cookie || "", "refresh_token");

    if (!token) {
      return res.status(401).json({
        status: "error",
        message: "Missing refresh token"
      });
    }

    const sessionId = verifyRefresh(token);

    if (!sessionId) {
      return res.status(401).json({
        status: "error",
        message: "Invalid refresh token"
      });
    }

    const accessToken = signAccess(sessionId);

    return res.status(200).json({
      status: "success",
      accessToken,
      expiresIn: 900
    });
  } catch (err) {
    console.error("REFRESH ERROR:", err);

    return res.status(500).json({
      status: "error",
      message: "Refresh failed"
    });
  }
}