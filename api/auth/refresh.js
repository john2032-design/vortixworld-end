import { verifyRefresh, signAccess } from "../../lib/auth.js";

export default async function handler(req, res) {
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

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  res.status(200).json({
    status: "success",
    accessToken,
    expiresIn: 900
  });
}
