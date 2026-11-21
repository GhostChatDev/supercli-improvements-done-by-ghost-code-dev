import { createHash } from 'node:crypto';

// Stable JSON: object keys sorted at every level, so the same action always hashes the same.
export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}

// SHA-256 of the exact action: tool name plus the full arguments (for a commit: paths and contents).
export function actionHash(name, args) {
  return createHash('sha256').update(canonical({ name, args })).digest('hex');
}

const MASK = '[REDACTED]';
const PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\b(authorization)\s*[:=]\s*[^\r\n"',]+/gi,
  /\bbearer\s+[A-Za-z0-9._~+/=-]+/gi,
  /\b(DATABASE_URL|[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)\s*[:=]\s*[^\s"',]+/g,
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s@/]+@[^\s"']+/gi,
  /\b(?:sk|pk|rk)[-_](?:live|test|ant|proj)?[-_]?[A-Za-z0-9_-]{12,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
];

// Replace anything that looks like a secret. Keeps the variable name so the summary stays readable.
export function redactText(text) {
  let out = String(text ?? '');
  for (const re of PATTERNS) {
    out = out.replace(re, (match, name) => {
      if (name && /^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) return `${name}=${MASK}`;
      return MASK;
    });
  }
  return out;
}

export function countSecrets(text) {
  const s = String(text ?? '');
  return PATTERNS.reduce((n, re) => n + (s.match(re)?.length ?? 0), 0);
}

const SECRET_KEY = /(secret|token|password|api[_-]?key|authorization|database_url|private[_-]?key|cookie)/i;

// Deep redaction of a value (used for anything stored, logged or shown).
export function redactValue(value, key = '') {
  if (SECRET_KEY.test(key) && value !== null && typeof value !== 'object') return MASK;
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map((v) => redactValue(v));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redactValue(v, k)]));
  }
  return value;
}

// Human summary for the approval card and hand-over note. Never contains raw secrets.
export function summarize(name, args = {}) {
  const files = Array.isArray(args.files)
    ? args.files.map((f) => ({
        path: redactText(f.path),
        bytes: Buffer.byteLength(String(f.content ?? '')),
        preview: redactText(String(f.content ?? '').slice(0, 400)),
      }))
    : [];
  const rest = { ...args };
  delete rest.files;
  return {
    title: redactText(`${name}${args.message ? `: ${args.message}` : ''}`),
    files,
    details: redactText(canonical(redactValue(rest))),
  };
}
