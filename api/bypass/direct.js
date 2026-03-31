export const config = {
  runtime: "nodejs"
};

import { verifyAccess } from "../../lib/auth.js";
import { validateUrl } from "../../lib/validate.js";

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");

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

  let body = {};

  try {
    body = typeof req.body === "string"
      ? JSON.parse(req.body)
      : req.body || {};
  } catch {
    return res.status(400).json({
      status: "error",
      message: "Invalid JSON body"
    });
  }

  const { url } = body;

  if (!url) {
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

  try {
    const upstream = await fetch(
      `https://lootlinkcom.vercel.app/api/bypass?url=${encodeURIComponent(check.url)}`
    );

    const text = await upstream.text();

    return res.status(200).send(text);
  } catch (err) {
    console.error("Proxy failed:", err);

    return res.status(500).json({
      status: "error",
      message: "Proxy failed"
    });
  }
}