export const config = {
  runtime: "nodejs"
};

import { signAccessToken, verifyRefreshToken } from "../../lib/auth.js";

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
    const { refreshToken } = req.body || {};

    if (!refreshToken || typeof refreshToken !== "string") {
      return sendJson(res, 400, {
        status: "error",
        message: "Missing refresh token"
      });
    }

    const sessionId = verifyRefreshToken(refreshToken);
    if (!sessionId) {
      return sendJson(res, 401, {
        status: "error",
        message: "Invalid refresh token"
      });
    }

    return sendJson(res, 200, {
      status: "success",
      accessToken: signAccessToken(sessionId),
      expiresIn: 900
    });
  } catch (err) {
    console.error("refresh error:", err);
    return sendJson(res, 500, {
      status: "error",
      message: "Refresh failed"
    });
  }
}