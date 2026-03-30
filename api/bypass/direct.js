export const config = {
  runtime: "nodejs"
};

import { verifyAccess } from "../../lib/auth.js";
import { validateUrl } from "../../lib/validate.js";

const BT_API_KEY = process.env.BT_API_KEY;

export default async function handler(req, res) {
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

  const session = verifyAccess(req);
  if (!session) {
    return res.status(401).json({
      status: "error",
      message: "Unauthorized"
    });
  }

  const { url, refresh = false } = req.body || {};

  if (typeof url !== "string" || !url.trim()) {
    return res.status(400).json({
      status: "error",
      message: "Missing URL"
    });
  }

  const check = validateUrl(url);
  if (!check.ok) {
    return res.status(400).json({
      status: "error",
      message: check.error
    });
  }

  if (!BT_API_KEY) {
    console.error("BT_API_KEY is missing in environment");
    return res.status(500).json({
      status: "error",
      message: "Server misconfigured"
    });
  }

  try {
    const upstream = await fetch("https://api.bypass.tools/api/v1/bypass/direct", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": BT_API_KEY
      },
      body: JSON.stringify({
        url: check.url,
        refresh
      })
    });

    const text = await upstream.text();

    console.log("bypass.tools status:", upstream.status);
    console.log("bypass.tools body:", text);

    res.status(upstream.status);
    res.setHeader("Content-Type", "application/json");
    return res.send(text);
  } catch (err) {
    console.error("Proxy failed:", err);
    return res.status(500).json({
      status: "error",
      message: err?.message || "Proxy failed"
    });
  }
}