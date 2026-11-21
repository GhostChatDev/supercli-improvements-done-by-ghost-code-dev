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
  async putReceipt(r) { this.receipts.set(r.key, structuredClone(r)); }
  async getReceipt(key) { const r = this.receipts.get(key); return r ? structuredClone(r) : null; }
}

// What the browser and the hand-over note may see: no raw arguments, only hash + redacted summary.
const publicView = (a) => ({
  id: a.id, kind: a.kind, tool: a.tool, hash: a.hash, summary: a.summary,
  status: a.status, createdAt: a.createdAt, expiresAt: a.expiresAt,
});

export function createGuard({ store = new MemoryStore(), now = () => Date.now(), log = () => {} } = {}) {
  const tools = new Map();
  const skipped = new Map(); // sessionKey -> [summary]
  const counters = { tasks: 0, firstTryPasses: 0, duplicateActions: 0, backgroundStuck: 0, secretsFound: 0 };

  const sessionKey = (ctx) => `${ctx.userId}:${ctx.sessionId}`;
  const receiptKey = (ctx, hash) => `${sessionKey(ctx)}:${hash}`;
  function safeLog(line) {
    counters.secretsFound += countSecrets(line);
    log(redactText(line));
  }

  function registerTool(def) {
    if (!def?.name || typeof def.run !== 'function') throw new Error('tool needs a name and run()');
    tools.set(def.name, { ...def, access: def.access === 'read' ? 'read' : 'write' });
  }
  // Unknown or unclassified tools are writes: they always ask first.
  const accessOf = (name) => (tools.get(name)?.access === 'read' ? 'read' : 'write');

  async function loadOwned(ctx, id) {
    const a = id ? await store.getApproval(id) : null;
    if (!a || a.userId !== ctx.userId || a.sessionId !== ctx.sessionId) return null;
    if (a.status === 'pending' && now() >= a.expiresAt) {
      a.status = 'expired';
      await store.putApproval(a);
    }
    return a;
  }

  async function requestApproval(ctx, name, hash, args) {
    const a = {
      id: randomUUID(), kind: 'approval', tool: name, hash, summary: summarize(name, args),
      status: 'pending', userId: ctx.userId, sessionId: ctx.sessionId, roundId: ctx.roundId,
      createdAt: now(), expiresAt: now() + DAY_MS,
    };
    await store.putApproval(a); // raw args are never stored
    safeLog(`approval requested: ${a.summary.title}`);
    return { ok: false, status: 'needs_approval', approval: publicView(a) };
  }

  async function getApproval(ctx, id) {
    const a = await loadOwned(ctx, id);
    return a ? publicView(a) : null;
  }

  async function decide(ctx, id, decision, hash) {
    const a = await loadOwned(ctx, id);
    if (!a) return { ok: false, status: 'not_found', message: MESSAGES.notFound };
    if (a.status === 'expired') return { ok: false, status: 'expired', message: MESSAGES.expired };
    if (a.status !== 'pending') return { ok: false, status: a.status, message: `already ${a.status}` };
    if (decision === 'approve' && hash !== a.hash) return { ok: false, status: 'needs_new_approval', message: MESSAGES.changed };
    a.status = decision === 'approve' ? 'approved' : 'denied';
    a.decidedAt = now();
    await store.putApproval(a);
    safeLog(`approval ${a.status}: ${a.summary.title}`);
    return { ok: true, approval: publicView(a) };
  }

  const deniedResult = (tool) => ({ ok: false, denied: true, status: 'denied', taskFailed: false, charge: 0, tool, message: MESSAGES.denied, next: MESSAGES.replan });

  // Run a protected action once. Receipt: unknown -> completed. After a crash, unknown is verified, not redone.
  async function runOnce(ctx, tool, args, hash) {
    const key = receiptKey(ctx, hash);
    const prior = await store.getReceipt(key);
    if (prior?.status === 'completed') return { ok: true, status: 'completed', replayed: true, result: prior.result, charge: 0 };
    if (prior?.status === 'unknown') {
      const check = tool.verify ? await tool.verify(args) : null;
      if (check?.exists) {
        await store.putReceipt({ ...prior, status: 'completed', result: check.result, roundId: ctx.roundId });
        safeLog(`recovered ${tool.name} from an earlier round; not run again`);
        return { ok: true, status: 'completed', replayed: true, recovered: true, result: check.result, charge: 0 };
      }
      if (!check) return { ok: false, status: 'unknown', message: MESSAGES.unknownOutcome };
    }
    await store.putReceipt({ key, hash, tool: tool.name, status: 'unknown', roundId: ctx.roundId, at: now() });
    const result = await tool.run(args);
    const charge = typeof tool.cost === 'function' ? tool.cost(result) : 0;
    await store.putReceipt({ key, hash, tool: tool.name, status: 'completed', result, charge, roundId: ctx.roundId, at: now() });
    return { ok: true, status: 'completed', result, charge };
  }

  async function callTool(ctx, name, args = {}, { approvalId } = {}) {
    const tool = tools.get(name);
    if (accessOf(name) === 'read') return { ok: true, status: 'completed', result: await tool.run(args), charge: 0 };
    const hash = actionHash(name, args);

    const prior = await store.getReceipt(receiptKey(ctx, hash));
    if (prior?.status === 'denied') return deniedResult(name); // no loop on a denied action
    if (prior?.status === 'completed') { counters.duplicateActions += 0; return runOnce(ctx, tool, args, hash); }

    if (ctx.unattended && !approvalId) {
      const list = skipped.get(sessionKey(ctx)) ?? [];
      list.push({ tool: name, summary: summarize(name, args), message: MESSAGES.skipped });
      skipped.set(sessionKey(ctx), list);
      safeLog(`${MESSAGES.skipped}: ${name}`);
      return { ok: false, skipped: true, status: 'skipped', taskFailed: false, charge: 0, message: MESSAGES.skipped };
    }
    if (!approvalId) return requestApproval(ctx, name, hash, args);

    const a = await loadOwned(ctx, approvalId);
    if (!a) return { ok: false, status: 'not_found', message: MESSAGES.notFound };
    if (a.status === 'expired') return { ok: false, status: 'expired', message: MESSAGES.expired, charge: 0 };
    if (a.status === 'denied') {
      await store.putReceipt({ key: receiptKey(ctx, hash), hash, tool: name, status: 'denied', roundId: ctx.roundId, at: now() });
      return deniedResult(name);
    }
    if (a.hash !== hash || a.tool !== name) {
      const fresh = await requestApproval(ctx, name, hash, args);
      return { ...fresh, status: 'needs_new_approval', message: MESSAGES.changed };
    }
    if (a.status !== 'approved') return { ok: false, status: 'needs_approval', approval: publicView(a) };
    if (!tool) return { ok: false, status: 'not_found', message: `no tool ${name}` };
    return runOnce(ctx, tool, args, hash);
  }

  function handoverNote(ctx) {
    const list = skipped.get(sessionKey(ctx)) ?? [];
    if (!list.length) return 'Nothing was skipped.';
    return list.map((s) => `- ${s.summary.title} (${s.message})`).join('\n');
  }

  function recordTask({ passedFirstTry }) { counters.tasks += 1; if (passedFirstTry) counters.firstTryPasses += 1; }
  function metrics() {
    const per100 = (n) => (counters.tasks ? (n * 100) / counters.tasks : 0);
    return {
      ...counters,
      firstTryPassRate: counters.tasks ? counters.firstTryPasses / counters.tasks : null, // measured, never claimed
      duplicatesPer100Tasks: per100(counters.duplicateActions),
    };
  }

  return { registerTool, accessOf, callTool, decide, getApproval, handoverNote, recordTask, metrics };
}
