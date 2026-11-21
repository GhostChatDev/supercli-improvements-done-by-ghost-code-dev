import { INTERACTION_KINDS } from './agent-guard.js';
import { redactText } from './privacy.js';

const esc = (s) => redactText(String(s ?? '')).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function approvalCard(a) {
  const files = (a.summary.files ?? [])
    .map((f) => `<li><code>${esc(f.path)}</code> (${f.bytes} bytes)<pre>${esc(f.preview)}</pre></li>`)
    .join('');
  const expires = new Date(a.expiresAt).toISOString();
  return `<section class="approval-card" data-kind="approval" data-hash="${esc(a.hash)}">
  <h3>Approve <strong>${esc(a.tool)}</strong>?</h3>
  <p class="summary">${esc(a.summary.title)}</p>
  ${files ? `<ul class="files">${files}</ul>` : ''}
  ${a.summary.details && a.summary.details !== '{}' ? `<pre class="details">${esc(a.summary.details)}</pre>` : ''}
  <p class="expiry">Expires <time datetime="${expires}">${expires}</time></p>
  <button type="button" data-decision="approve" data-approval="${esc(a.id)}" data-hash="${esc(a.hash)}">Approve</button>
  <button type="button" data-decision="deny" data-approval="${esc(a.id)}">Deny</button>
</section>`;
}

export const RENDERERS = Object.freeze({ approval: approvalCard });

export function renderInteraction(interaction) {
  const r = RENDERERS[interaction?.kind];
  if (!r) throw new Error(`no renderer for interaction kind "${interaction?.kind}"`);
  if (interaction.status === 'expired') return `<section data-kind="${esc(interaction.kind)}"><p>Expired, nothing was changed</p></section>`;
  return r(interaction);
}

// Every kind the backend can create must have a screen.
export const missingRenderers = (kinds = INTERACTION_KINDS) => kinds.filter((k) => !RENDERERS[k]);
