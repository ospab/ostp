// ── What a server says about itself, its operator and the user's key ──
// The connected core reports it inside the tunnel (never in the subscription
// document, which anyone with the URL can fetch). The app keeps the last copy
// with the subscription, so the information window also works offline.

const str = (v, max) => (typeof v === 'string' && v.trim() ? v.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '').trim().slice(0, max) : null);
const num = v => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? Math.floor(v) : null);
const bool = v => (typeof v === 'boolean' ? v : null);
const isObj = v => v && typeof v === 'object' && !Array.isArray(v);

// Whatever the core sent → only known fields of the right type; null when nothing is usable.
export function normalizeServerInfo(raw) {
  let v = raw;
  if (typeof v === 'string') {
    if (!v.trim()) return null;
    try { v = JSON.parse(v); } catch { return null; }
  }
  if (!isObj(v)) return null;
  const out = {};
  if (isObj(v.operator)) {
    const o = {
      name: str(v.operator.name, 120), location: str(v.operator.location, 120),
      contact: str(v.operator.contact, 200), about: str(v.operator.about, 8000),
    };
    if (Object.values(o).some(x => x != null)) out.operator = o;
  }
  if (isObj(v.server)) {
    const s = {
      version: str(v.server.version, 64),
      carriers: Array.isArray(v.server.carriers) ? v.server.carriers.map(c => str(c, 16)).filter(Boolean).slice(0, 8) : [],
      log_privacy: ['strict', 'normal', 'debug'].includes(v.server.log_privacy) ? v.server.log_privacy : null,
      ipv6: bool(v.server.ipv6), dns_filtering: bool(v.server.dns_filtering),
    };
    if (s.version || s.carriers.length || s.log_privacy || s.ipv6 != null || s.dns_filtering != null) out.server = s;
  }
  if (isObj(v.key)) {
    const k = {
      used_bytes: num(v.key.used_bytes), limit_bytes: num(v.key.limit_bytes),
      expires_at: num(v.key.expires_at), max_devices: num(v.key.max_devices),
    };
    if (Object.values(k).some(x => x != null)) out.key = k;
  }
  return Object.keys(out).length ? out : null;
}

const DAY_MS = 86400000;

// The day a key ends, as the server counts it (UTC), e.g. "2026-12-31".
export const expiryDate = sec => new Date(sec * 1000).toISOString().slice(0, 10);

// { expired, daysLeft, date } for a subscription, or null when no expiry is known.
// `keyExpired` is set when the server closed a session because the key expired.
export function subscriptionExpiry(sub, now = Date.now()) {
  const at = sub?.serverInfo?.key?.expires_at ?? null;
  if (at == null) return sub?.keyExpired ? { expired: true, daysLeft: 0, date: null } : null;
  const left = at * 1000 - now;
  const expired = left <= 0 || !!sub.keyExpired;
  return { expired, daysLeft: expired ? 0 : Math.ceil(left / DAY_MS), date: expiryDate(at) };
}

// "until 2026-12-31", "until 2026-12-31, 3 days left", "expired".
export function expiryLabel(e) {
  if (!e) return '';
  if (e.expired) return 'expired';
  const left = e.daysLeft < 7 ? `, ${e.daysLeft} ${e.daysLeft === 1 ? 'day' : 'days'} left` : '';
  return `until ${e.date}${left}`;
}

// A key closed by the server for being past its date, from the reason the core reports.
export const isKeyExpiredReason = text => /\b(key|access)\b[^.]*\bexpired\b|\bexpired\b[^.]*\bkey\b|KeyExpired/i.test(String(text || ''));

export const LOG_PRIVACY_TEXT = {
  strict: 'No destinations in the logs; your address is replaced by a daily tag.',
  normal: 'No destinations in the logs; your address is cut to its network.',
  debug: 'The server logs destinations: the sites and addresses you connect to.',
};
