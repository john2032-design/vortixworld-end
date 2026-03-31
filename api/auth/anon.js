export const config = {
  runtime: "nodejs"
};

import { newSessionId, signAccessToken, signRefreshToken } from "../../lib/auth.js";

function sendJson(res, statusCode, body) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  return res.status(statusCode).json(body);
}

export default function handler(req, res) {
  if (req.method === "OPTIONS") {
    return sendJson(res, 200, { status: "success" });
  }

  if (req.method !== "POST") {
    return sendJson(res, 405, {
      status: "error",
      message: "Method not allowed"
    });
  }

  try {
    const sessionId = newSessionId();
    const accessToken = signAccessToken(sessionId);
    const refreshToken = signRefreshToken(sessionId);

    return sendJson(res, 200, {
      status: "success",
      accessToken,
      refreshToken,
      expiresIn: 900,
      refreshExpiresIn: 1209600
    });
  } catch (err) {
    console.error("anon error:", err);
    return sendJson(res, 500, {
      status: "error",
      message: "Anon failed"
    });
  }
}