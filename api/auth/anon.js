export const config = {
  runtime: "nodejs"
};

import { signAccess, signRefresh, newSession } from "../../lib/auth.js";

export default async function handler(req, res) {
  try {
    const sessionId = newSession();

    const accessToken = signAccess(sessionId);
    const refreshToken = signRefresh(sessionId);

    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");

    if (req.method === "OPTIONS") {
      return res.status(200).end();
    }

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