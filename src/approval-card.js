import { INTERACTION_KINDS } from './agent-guard.js';
import { redactText } from './privacy.js';

const esc = (s) => redactText(String(s ?? '')).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function summaryHtml(summary) {
  if (summary?.kind === 'files') {
    const files = summary.files.map((f) =>
      `<li><code>${esc(f.path)}</code> (${Number(f.bytes) || 0} bytes)<pre>${esc(f.preview)}</pre></li>`).join('');
    const msg = summary.message ? `<p class="message">${esc(summary.message)}</p>` : '';
    return `${msg}<ul class="files">${files}</ul>`;
  }
  return `<pre class="details">${esc(summary?.details)}</pre>`;
}

// Approve carries the exact hash shown, so a decision never applies to a different action.
function approvalCard(a) {
  const expires = new Date(a.expiresAt).toISOString();
  const open = a.status === 'pending';
  const state = a.status === 'expired' ? '<p class="state">Expired, nothing was changed</p>' : `<p class="state">${esc(a.status)}</p>`;
  const buttons = open
    ? `<button data-decision="approve" data-id="${esc(a.id)}" data-hash="${esc(a.hash)}">Approve</button>` +
      `<button data-decision="deny" data-id="${esc(a.id)}" data-hash="${esc(a.hash)}">Deny</button>`
    : '';
  return `<section class="approval-card" data-kind="approval">` +
    `<h3>Approve <code>${esc(a.tool)}</code>?</h3>` +
    `<p class="title">${esc(a.summary?.title)}</p>${summaryHtml(a.summary)}` +
    `<p class="expires">Expires <time datetime="${expires}">${expires}</time></p>${state}${buttons}</section>`;
}

export const RENDERERS = Object.freeze({ approval: approvalCard });

export function renderInteraction(interaction) {
  const render = RENDERERS[interaction?.kind];
  if (!render) throw new Error(`No renderer for interaction kind "${interaction?.kind}"`);
  return render(interaction);
}

export const missingRenderers = () => INTERACTION_KINDS.filter((k) => typeof RENDERERS[k] !== 'function');
