import { createHash } from 'node:crypto';

// Stable JSON: object keys sorted at every level, so the same action always hashes the same.
export function canonical(value) {
  if (value === null || typeof value === 'number' || typeof value === 'boolean' || typeof value === 'string') {
    if (typeof value === 'number' && !Number.isFinite(value)) throw new TypeError('Non-finite numbers cannot be hashed');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (typeof value === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  throw new TypeError(`Cannot hash a value of type ${typeof value}`);
}

export function actionHash(tool, args) {
  return createHash('sha256').update(canonical({ tool, args: args ?? null })).digest('hex');
}

const SECRET_KEY = /(secret|token|password|passwd|authorization|api[_-]?key|private[_-]?key|database_url|cookie)/i;

const TEXT_RULES = [
  [/\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s"'`]+/gi, '$1://[REDACTED]'],
  [/\b(authorization)\s*[:=]\s*[^\r\n"'`]+/gi, '$1: [REDACTED]'],
  [/\bbearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [REDACTED]'],
  [/\b([A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|APIKEY|DATABASE_URL|PRIVATE_KEY)[A-Za-z0-9_]*)\s*[=:]\s*[^\s"'`]+/gi, '$1=[REDACTED]'],
  [/\b(sk|pk|rk)-[A-Za-z0-9_-]{8,}/g, '[REDACTED_KEY]'],
  [/\b(ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{10,}/g, '[REDACTED_KEY]'],
  [/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED_KEY]'],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, '[REDACTED_JWT]'],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]'],
];

export function redactText(text) {
  let out = String(text);
  for (const [pattern, replacement] of TEXT_RULES) out = out.replace(pattern, replacement);
  return out;
}

// Deep copy with secret-looking keys and values replaced. Never mutates the input.
export function redact(value, keyName = '') {
  if (keyName && SECRET_KEY.test(keyName) && value !== null && typeof value !== 'object') return '[REDACTED]';
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map((v) => redact(v));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = redact(v, k);
    return out;
  }
  return value;
}

// Counts strings that still look like secrets; used by the "secrets found" counter.
export function countSecrets(text) {
  const s = String(text);
  let n = 0;
  for (const [pattern] of TEXT_RULES) {
    const matches = s.match(new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g')) || [];
    n += matches.filter((m) => !m.includes('[REDACTED')).length;
  }
  return n;
}

const PREVIEW_CHARS = 400;

// What the person sees: files and a redacted diff preview for commits, a redacted payload otherwise.
export function summarize(tool, args) {
  const safe = redact(args ?? {});
  if (safe && Array.isArray(safe.files)) {
    return {
      kind: 'files',
      title: `${tool}: ${safe.files.length} file(s)`,
      files: safe.files.map((f) => {
        const content = typeof f.content === 'string' ? f.content : '';
        return {
          path: redactText(f.path ?? '(no path)'),
          bytes: Buffer.byteLength(typeof args.files.find((o) => o.path === f.path)?.content === 'string' ? args.files.find((o) => o.path === f.path).content : ''),
          preview: content.length > PREVIEW_CHARS ? `${content.slice(0, PREVIEW_CHARS)}\n…` : content,
        };
      }),
      message: safe.message ? redactText(safe.message) : undefined,
    };
  }
  const text = JSON.stringify(safe, null, 2);
  return { kind: 'action', title: tool, details: text.length > PREVIEW_CHARS * 2 ? `${text.slice(0, PREVIEW_CHARS * 2)}\n…` : text };
}
