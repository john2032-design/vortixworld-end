export const config = {
  runtime: "nodejs"
};

import jwt from "jsonwebtoken";
import { randomUUID } from "crypto";

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;

function signAccess(sessionId) {
  return jwt.sign(
    { sub: sessionId, typ: "access" },
    JWT_SECRET,
    { expiresIn: "15m" }
  );
}

function signRefresh(sessionId) {
  return jwt.sign(
    { sub: sessionId, typ: "refresh" },
    REFRESH_SECRET,
    { expiresIn: "14d" }
  );
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

    const sessionId = randomUUID();
    const accessToken = signAccess(sessionId);
    const refreshToken = signRefresh(sessionId);

    res.setHeader("Set-Cookie", [
      `refresh_token=${refreshToken}; HttpOnly; Path=/api/auth/refresh; Max-Age=1209600; SameSite=None; Secure`
    ]);

    return res.status(200).json({
      status: "success",
      accessToken,
      expiresIn: 900
    });
  } catch (err) {
    console.error("ANON ERROR:", err);

    return res.status(500).json({
      status: "error",
      message: "Anon failed"
    });
  }
}