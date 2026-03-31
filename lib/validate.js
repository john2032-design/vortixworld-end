const ALLOWED_TARGET_HOSTS = new Set([
  "linkvertise.com",
  "lockr.so",
  "link-unlocker.com",
  "mboost.me",
  "rekonise.com",
  "ouo.io",
  "cuty.io"
]);

export function validateTargetUrl(raw) {
  let parsed;

  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, error: "INVALID_URL" };
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return { ok: false, error: "INVALID_URL" };
  }

  if (parsed.username || parsed.password) {
    return { ok: false, error: "INVALID_URL" };
  }

  const host = parsed.hostname.toLowerCase().replace(/^www\./, "");

  if (!ALLOWED_TARGET_HOSTS.has(host)) {
    return { ok: false, error: "HOST_NOT_ALLOWED" };
  }

  return { ok: true, url: parsed.toString() };
}