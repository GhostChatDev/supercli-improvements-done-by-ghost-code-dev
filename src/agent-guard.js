/*
 * NOTICE: Patterns adapted from Nova (supercli) by Yash Dewasthale, MIT License.
 * Copyright (c) 2026 Yash Dewasthale. https://github.com/yashdev9274/supercli
 * Their copyright notice and MIT permission notice stay with any copy of their software.
 * This work reimplements the ideas. It does not copy their source files.
 */
import { randomUUID } from 'node:crypto';
import { actionHash, redactText, summarize, countSecrets } from './privacy.js';

export const DAY_MS = 24 * 60 * 60 * 1000;
export const INTERACTION_KINDS = Object.freeze(['approval']);
export const MESSAGES = Object.freeze({
  denied: 'denied by user',
  replan: 'Choose another route; do not repeat this action.',
  skipped: 'skipped, waiting for you',
  changed: 'needs new approval',
  expired: 'Expired, nothing was changed',
  notFound: 'not found',
  unknownOutcome: 'Outcome unknown; check it before retrying',
});

// In-memory store. A real deployment swaps in a database with the same methods.
export class MemoryStore {
  constructor() { this.approvals = new Map(); this.receipts = new Map(); }
  async putApproval(a) { this.approvals.set(a.id, structuredClone(a)); }
  async getApproval(id) { const a = this.approvals.get(id); return a ? structuredClone(a) : null; }
  async listApprovals() { return [...this.approvals.values()].map((a) => structuredClone(a)); }
  async putReceipt(key, r) { this.receipts.set(key, structuredClone(r)); }
  async getReceipt(key) { const r = this.receipts.get(key); return r ? structuredClone(r) : null; }
}

function requireOwner(ctx) {
  if (!ctx || typeof ctx.userId !== 'string' || !ctx.userId || typeof ctx.sessionId !== 'string' || !ctx.sessionId) {
    throw new Error('userId and sessionId are required');
  }
}

const isOwner = (a, ctx) => a && a.userId === ctx.userId && a.sessionId === ctx.sessionId;
const publicView = ({ id, kind, tool, hash, summary, status, createdAt, expiresAt }) =>
  ({ id, kind, tool, hash, summary, status, createdAt, expiresAt });

export function createGuard({ store = new MemoryStore(), now = () => Date.now(), ttlMs = DAY_MS, log = () => {} } = {}) {
  const tools = new Map();
  const skipped = new Map(); // roundId -> [{ tool, summary }]
  const counters = { tasks: 0, firstTryPasses: 0, executions: 0, duplicateExecutions: 0, backgroundWaits: 0, secretsFound: 0 };
  const executedKeys = new Set();

  function safeLog(line) {
    const clean = redactText(line);
    counters.secretsFound += countSecrets(clean);
    log(clean);
  }

  function registerTool({ name, access, run, verify }) {
    if (!name || typeof run !== 'function') throw new Error('A tool needs a name and a run function');
    // Anything not explicitly "read" is a write and must be approved.
    tools.set(name, { name, access: access === 'read' ? 'read' : 'write', run, verify });
  }

  const accessOf = (name) => tools.get(name)?.access ?? 'write';

  async function createApproval(ctx, tool, args, hash) {
    const t = now();
    const approval = {
      id: randomUUID(), kind: 'approval', userId: ctx.userId, sessionId: ctx.sessionId, roundId: ctx.roundId,
      tool, hash, summary: summarize(tool, args), status: 'pending', createdAt: t, expiresAt: t + ttlMs,
    };
    await store.putApproval(approval);
    safeLog(`approval requested: ${approval.summary.title} (${hash.slice(0, 12)})`);
    return publicView(approval);
  }

  async function loadOwned(ctx, id) {
    requireOwner(ctx);
    const a = await store.getApproval(id);
    if (!isOwner(a, ctx)) return null; // another person's record looks exactly like a missing one
    if (a.status === 'pending' && now() >= a.expiresAt) { a.status = 'expired'; await store.putApproval(a); }
    return a;
  }

  async function getApproval(ctx, id) { const a = await loadOwned(ctx, id); return a ? publicView(a) : null; }

  async function listPending(ctx) {
    requireOwner(ctx);
    const out = [];
    for (const a of await store.listApprovals()) {
      if (!isOwner(a, ctx) || a.status !== 'pending') continue;
      const fresh = await loadOwned(ctx, a.id);
      if (fresh.status === 'pending') out.push(publicView(fresh));
    }
    return out;
  }

  // The person's tap. The decision counts only for the hash shown on the card.
  async function decide(ctx, id, decision, hash) {
    const a = await loadOwned(ctx, id);
    if (!a) return { ok: false, error: MESSAGES.notFound };
    if (a.status === 'expired') return { ok: false, error: MESSAGES.expired };
    if (a.status !== 'pending') return { ok: false, error: `already ${a.status}` };
    if (hash !== a.hash) return { ok: false, error: MESSAGES.changed };
    if (decision !== 'approve' && decision !== 'deny') return { ok: false, error: 'decision must be approve or deny' };
    a.status = decision === 'approve' ? 'approved' : 'denied';
    a.decidedAt = now();
    await store.putApproval(a);
    if (a.status === 'denied') {
      await store.putReceipt(`${a.roundId}:${a.hash}`, { status: 'denied', tool: a.tool, at: a.decidedAt });
    }
    safeLog(`approval ${a.status}: ${a.summary.title}`);
    return { ok: true, approval: publicView(a) };
  }

  const deniedResult = (tool) => ({ ok: false, denied: true, status: 'denied', taskFailed: false, charge: 0, tool, message: MESSAGES.denied, next: MESSAGES.replan });

  async function execute(ctx, tool, args, hash, key) {
    if (executedKeys.has(key)) counters.duplicateExecutions += 1;
    executedKeys.add(key);
    counters.executions += 1;
    await store.putReceipt(key, { status: 'unknown', tool: tool.name, at: now() });
    try {
      const result = await tool.run(args, ctx);
      await store.putReceipt(key, { status: 'completed', tool: tool.name, at: now(), result: result ?? null });
      safeLog(`ran ${tool.name} (${hash.slice(0, 12)})`);
      return { ok: true, status: 'completed', result: result ?? null, charge: Number(result?.cost) || 0 };
    } catch (err) {
      // The side effect may or may not have happened: the receipt stays "unknown" and is never blindly redone.
      safeLog(`outcome unknown for ${tool.name}: ${err?.message ?? err}`);
      return { ok: false, status: 'unknown', error: MESSAGES.unknownOutcome };
    }
  }

  // The single choke point every agent tool call goes through.
  async function callTool(ctx, name, args = {}, { approvalId, unattended = false } = {}) {
    requireOwner(ctx);
    if (!ctx.roundId) throw new Error('roundId is required');
    const tool = tools.get(name);
    if (!tool) return { ok: false, status: 'error', error: `unknown tool ${name}` };
    if (tool.access === 'read') return { ok: true, status: 'completed', result: await tool.run(args, ctx), charge: 0 };

    const hash = actionHash(name, args);
    const key = `${ctx.roundId}:${hash}`;
    const receipt = await store.getReceipt(key);
    if (receipt?.status === 'completed') return { ok: true, status: 'completed', replayed: true, result: receipt.result, charge: 0 };
    if (receipt?.status === 'denied') return deniedResult(name);
    if (receipt?.status === 'unknown') {
      const found = tool.verify ? await tool.verify(args, ctx) : undefined;
      if (found && found.exists) {
        await store.putReceipt(key, { status: 'completed', tool: name, at: now(), result: found.result ?? null });
        return { ok: true, status: 'completed', replayed: true, result: found.result ?? null, charge: 0 };
      }
      if (!found || found.exists !== false) return { ok: false, status: 'unknown', error: MESSAGES.unknownOutcome };
      // Verified absent: safe to run once more (falls through, still needs a valid approval).
    }

    if (unattended) {
      const list = skipped.get(ctx.roundId) ?? [];
      const summary = summarize(name, args);
      if (!list.some((s) => s.hash === hash)) list.push({ tool: name, hash, summary });
      skipped.set(ctx.roundId, list);
      safeLog(`${MESSAGES.skipped}: ${summary.title}`);
      return { ok: false, skipped: true, status: 'skipped', taskFailed: false, charge: 0, message: MESSAGES.skipped };
    }

    if (!approvalId) {
      const approval = await createApproval(ctx, name, args, hash);
      return { ok: false, needsApproval: true, status: 'waiting', charge: 0, approval };
    }
    const a = await loadOwned(ctx, approvalId);
    if (!a) return { ok: false, status: 'error', error: MESSAGES.notFound };
    if (a.status === 'expired') return { ok: false, status: 'expired', charge: 0, error: MESSAGES.expired };
    if (a.tool !== name || a.hash !== hash) {
      const approval = await createApproval(ctx, name, args, hash);
      return { ok: false, needsApproval: true, status: 'waiting', charge: 0, error: MESSAGES.changed, approval };
    }
    if (a.status === 'denied') return deniedResult(name);
    if (a.status === 'pending') return { ok: false, needsApproval: true, status: 'waiting', charge: 0, approval: publicView(a) };
    if (a.status !== 'approved') return { ok: false, status: 'error', error: `approval is ${a.status}` };
    a.status = 'used';
    await store.putApproval(a);
    return execute(ctx, tool, args, hash, key);
  }

  function handoverNote(roundId) {
    const list = skipped.get(roundId) ?? [];
    if (!list.length) return '';
    return ['Skipped, waiting for you:', ...list.map((s) => `- ${s.summary.title} (${MESSAGES.skipped})`)].join('\n');
  }

  function recordTask({ firstTryPass }) { counters.tasks += 1; if (firstTryPass) counters.firstTryPasses += 1; }

  function metrics() {
    const per100 = (n) => (counters.tasks ? (n * 100) / counters.tasks : 0);
    return {
      ...counters,
      firstTryPassRate: counters.tasks ? counters.firstTryPasses / counters.tasks : null,
      duplicatesPer100Tasks: per100(counters.duplicateExecutions),
    };
  }

  return { registerTool, accessOf, callTool, decide, getApproval, listPending, handoverNote, recordTask, metrics, kinds: INTERACTION_KINDS };
}
