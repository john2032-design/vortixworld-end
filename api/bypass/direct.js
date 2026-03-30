import { verifyAccess } from "../../lib/auth.js";
import { validateUrl } from "../../lib/validate.js";

const BT_API_KEY = process.env.BT_API_KEY;

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const session = verifyAccess(req);
  if (!session) {
    return res.status(401).json({
      status: "error",
      message: "Unauthorized"
    });
  }

  const { url, refresh = false } = req.body || {};

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

    const data = await upstream.json();

    return res.status(upstream.status).json(data);
  } catch {
    return res.status(500).json({
      status: "error",
      message: "Proxy failed"
    });
  }
}
