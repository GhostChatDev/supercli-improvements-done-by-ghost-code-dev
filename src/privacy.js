import { createHash } from 'node:crypto';

// Accept JSON only; reject ambiguous values instead of hashing them incorrectly.
export function canonical(value) {
  const seen = new Set();
  function visit(item) {
    if (item === null || typeof item === 'boolean' || typeof item === 'string') return JSON.stringify(item);
    if (typeof item === 'number' && Number.isFinite(item)) return JSON.stringify(item);
    if (typeof item !== 'object' || seen.has(item)) throw new TypeError('Action must be acyclic JSON');
    seen.add(item);
    let result;
    if (Array.isArray(item)) {
      if (Object.keys(item).length !== item.length) throw new TypeError('Sparse arrays are not supported');
      result = '[' + item.map(visit).join(',') + ']';
    } else {
      if (Object.getPrototypeOf(item) !== Object.prototype) throw new TypeError('Action must be plain JSON');
      result = '{' + Object.keys(item).sort().map(key => JSON.stringify(key) + ':' + visit(item[key])).join(',') + '}';
    }
    seen.delete(item);
    return result;
  }
  return visit(value);
}

export function actionHash(name, args) {
  return createHash('sha256').update(canonical({ name, args })).digest('hex');
}

// Stronger than pattern matching: untrusted arguments, file names and diff text
// never enter storage, logs or HTML. Hosts show sensitive diffs in their existing
// authenticated workspace, using this hash to bind that view to the decision.
export function safeSummary(name, args) {
  const count = Array.isArray(args?.files) ? args.files.length : null;
  return `${name}: protected action${count === null ? '' : ` affecting ${count} file(s)`}. Payload hidden for privacy.`;
}

export function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}
