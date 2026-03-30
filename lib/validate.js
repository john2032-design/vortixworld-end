const ALLOWED_TARGET_HOSTS = new Set([
  "linkvertise.com",
  "loot-link.com",
  "lootlabs.com",
  "lootlab.com",
  "tpi.li",
  "lootdest.com"
]);

export function validateUrl(raw) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, error: "INVALID_URL" };
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return { ok: false, error: "INVALID_URL" };
  }

  const host = parsed.hostname.toLowerCase();

  if (!ALLOWED_TARGET_HOSTS.has(host)) {
    return { ok: false, error: "HOST_NOT_ALLOWED" };
  }

  return { ok: true, url: parsed.toString() };
}
