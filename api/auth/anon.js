import { signAccess, signRefresh, newSession } from "../../lib/auth.js";

export default async function handler(req, res) {
  const sessionId = newSession();

  const accessToken = signAccess(sessionId);
  const refreshToken = signRefresh(sessionId);

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  res.setHeader("Set-Cookie", [
    `refresh_token=${refreshToken}; HttpOnly; Path=/api/auth/refresh; Max-Age=1209600; SameSite=None; Secure`
  ]);

  res.status(200).json({
    status: "success",
    accessToken,
    expiresIn: 900
  });
}
