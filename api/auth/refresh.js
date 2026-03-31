export const config = {
  runtime: "nodejs"
};

import { verifyRefresh, signAccess } from "../../lib/auth.js";

export default async function handler(req, res) {
  try {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");

    if (req.method === "OPTIONS") {
      return res.status(200).end();
    }

    const cookie = req.headers.cookie || "";
    const match = cookie.match(/refresh_token=([^;]+)/);
    const token = match ? match[1] : null;

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