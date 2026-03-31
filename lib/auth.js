import jwt from "jsonwebtoken";
import crypto from "crypto";

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;

if (!JWT_SECRET || !REFRESH_SECRET) {
  throw new Error("Missing JWT_SECRET or REFRESH_SECRET");
}

export function newSessionId() {
  return crypto.randomUUID();
}

export function signAccessToken(sessionId) {
  return jwt.sign(
    { sub: sessionId, typ: "access" },
    JWT_SECRET,
    { expiresIn: "15m" }
  );
}

export function signRefreshToken(sessionId) {
  return jwt.sign(
    { sub: sessionId, typ: "refresh" },
    REFRESH_SECRET,
    { expiresIn: "14d" }
  );
}

export function verifyAccessToken(token) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.typ !== "access") return null;
    return decoded.sub;
  } catch {
    return null;
  }
}

export function verifyRefreshToken(token) {
  try {
    const decoded = jwt.verify(token, REFRESH_SECRET);
    if (decoded.typ !== "refresh") return null;
    return decoded.sub;
  } catch {
    return null;
  }
}