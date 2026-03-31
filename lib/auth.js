import jwt from "jsonwebtoken";
import { randomUUID } from "crypto";

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;

export function signAccess(sessionId) {
  return jwt.sign(
    { sub: sessionId, typ: "access" },
    JWT_SECRET,
    { expiresIn: "15m" }
  );
}

export function signRefresh(sessionId) {
  return jwt.sign(
    { sub: sessionId, typ: "refresh" },
    REFRESH_SECRET,
    { expiresIn: "14d" }
  );
}

export function verifyAccess(req) {
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

export function verifyRefresh(token) {
  try {
    const decoded = jwt.verify(token, REFRESH_SECRET);
    if (decoded.typ !== "refresh") return null;
    return decoded.sub;
  } catch {
    return null;
  }
}

export function newSession() {
  return randomUUID();
}