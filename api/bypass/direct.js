export const config = {
  runtime: "nodejs"
};

import { verifyAccessToken } from "../../lib/auth.js";
import { validateTargetUrl } from "../../lib/validate.js";

function sendJson(res, statusCode, body) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  return res.status(statusCode).json(body);
}

export default async function handler(req, res) {
  if (req.method === "OPTIONS") {
    return sendJson(res, 200, { status: "success" });
  }

  if (req.method !== "POST") {
    return sendJson(res, 405, {
      status: "error",
      message: "Method not allowed"
    });
  }

  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const sessionId = token ? verifyAccessToken(token) : null;

  if (!sessionId) {
    return sendJson(res, 401, {
      status: "error",
      message: "Unauthorized"
    });
  }

  const { url } = req.body || {};

  if (!url || typeof url !== "string") {
    return sendJson(res, 400, {
      status: "error",
      message: "Missing url"
    });
  }

  const check = validateTargetUrl(url);
  if (!check.ok) {
    return sendJson(res, 400, {
      status: "error",
      message: check.error
    });
  }

  try {
    const upstream = await fetch(
      `https://lootlinkcom.vercel.app/api/bypass?url=${encodeURIComponent(check.url)}`
    );

    const raw = await upstream.text();

    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      return sendJson(res, 502, {
        status: "error",
        result: "Upstream returned non-JSON",
        raw
      });
    }

    return sendJson(res, upstream.status, data);
  } catch (err) {
    console.error("proxy error:", err);
    return sendJson(res, 500, {
      status: "error",
      message: "Proxy failed"
    });
  }
}