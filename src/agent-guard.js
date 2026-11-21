import { mkdirSync, readFileSync, writeFileSync, renameSync, rmSync, openSync, fsyncSync, closeSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { actionHash, canonical, safeSummary } from './privacy.js';

/* NOTICE
Patterns adapted from Nova (supercli) by Yash Dewasthale, MIT License.
Copyright (c) 2026 Yash Dewasthale.
https://github.com/yashdev9274/supercli
Their copyright notice and MIT permission notice stay with any copy of their software.
This work reimplements the ideas. It does not copy their source files.
*/
export const interactionKinds = Object.freeze(['approval']);
const ttl = 24 * 60 * 60 * 1000;
const empty = () => ({ approvals: {}, receipts: {}, batches: {} });
const identifier = value => typeof value === 'string' && value.length > 0 && value.length <= 200;

// Atomic local journal. Each transaction owns an exclusive lock. A stale lock
// fails closed; an operator must establish no writer remains before removing it.
export class FileJournal {
  constructor(path) { this.path = path; mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); }
  transaction(fn) {
    const lock = this.path + '.lock';
    const fd = openSync(lock, 'wx', 0o600);
    let temp;
    try {
      let state;
      try { state = JSON.parse(readFileSync(this.path, 'utf8')); }
      catch (error) { if (error.code !== 'ENOENT') throw error; state = empty(); }
      const result = fn(state);
      temp = this.path + '.' + randomUUID();
      writeFileSync(temp, JSON.stringify(state), { mode: 0o600, flag: 'wx' });
      const data = openSync(temp, 'r');
      try { fsyncSync(data); } finally { closeSync(data); }
      renameSync(temp, this.path);
      const directory = openSync(dirname(this.path), 'r');
      try { fsyncSync(directory); } finally { closeSync(directory); }
      return result;
    } finally {
      if (temp) rmSync(temp, { force: true });
      closeSync(fd); rmSync(lock, { force: true });
    }
  }
}

export class AgentGuard {
  constructor({ journal, tools, clock = Date.now }) {
    this.journal = journal; this.clock = clock;
    this.tools = new Map(Object.entries(tools).map(([name, tool]) => {
      if (!/^[a-z][a-z0-9_.-]{0,63}$/.test(name) || typeof tool.run !== 'function') throw new Error('Invalid tool registration');
      return [name, Object.freeze({ ...tool })];
    }));
  }
  scope(context) {
    for (const field of ['userId', 'sessionId', 'roundId', 'batchId']) {
      if (!identifier(context[field])) throw new Error('Authenticated context required');
    }
    return actionHash('scope', { user: context.userId, session: context.sessionId });
  }
  batch(state, context) {
    const key = actionHash('batch', { scope: this.scope(context), batch: context.batchId });
    return state.batches[key] ??= { tasks: {}, duplicateExecutions: 0, duplicateCharges: 0, backgroundWaits: 0, secretFindings: 0, replayed: 0 };
  }
  get(context, id) {
    const scope = this.scope(context);
    return this.journal.transaction(state => {
      const item = state.approvals[id];
      if (!item || item.scope !== scope) return null;
      if (this.clock() >= item.expiresAt) item.status = 'expired';
      return structuredClone(item);
    });
  }
  decide(context, id, hash, approve) {
    const scope = this.scope(context);
    if (typeof approve !== 'boolean') throw new TypeError('Boolean decision required');
    return this.journal.transaction(state => {
      const item = state.approvals[id];
      if (!item || item.scope !== scope) return { status: 'not_found' };
      if (this.clock() >= item.expiresAt) {
        item.status = 'expired';
        return { status: 'expired', message: 'Expired, nothing was changed' };
      }
      if (item.hash !== hash) return { status: 'needs_new_approval', message: 'needs new approval' };
      if (item.status !== 'pending') return { status: item.status };
      item.status = approve ? 'approved' : 'denied';
      if (!approve) state.receipts[item.key] = { status: 'denied' };
      return { status: item.status };
    });
  }
  async call(context, name, args, approvalId) {
    const scope = this.scope(context);
    const tool = this.tools.get(name);
    if (!tool) throw new Error('Tool not registered');
    // Freeze a JSON snapshot before any asynchronous execution or mutation.
    const payload = JSON.parse(canonical(args));
    const hash = actionHash(name, payload);
    const key = actionHash('receipt', { scope, round: context.roundId, hash });
    const summary = safeSummary(name, payload);
    if (tool.access === 'read') {
      return { status: 'completed', result: await tool.run(payload, { idempotencyKey: key }) };
    }
    const gate = this.journal.transaction(state => {
      const receipt = state.receipts[key];
      const batch = this.batch(state, context);
      if (receipt) {
        if (receipt.status === 'completed') batch.replayed++;
        return { status: receipt.status, replayed: true };
      }
      if (approvalId) {
        const approval = state.approvals[approvalId];
        if (!approval || approval.scope !== scope) return { status: 'not_found' };
        if (approval.hash !== hash || approval.key !== key) return { status: 'needs_new_approval', message: 'needs new approval' };
        if (this.clock() >= approval.expiresAt) {
          approval.status = 'expired';
          return { status: 'expired', message: 'Expired, nothing was changed' };
        }
        if (approval.status === 'denied') return { status: 'denied', message: 'denied by user', stepCharge: 0 };
        if (approval.status === 'approved') {
          state.receipts[key] = { status: 'unknown' };
          approval.status = 'consumed';
          return { status: 'execute' };
        }
      }
      if (context.unattended) return { status: 'skipped', message: `skipped, waiting for you: ${summary}`, stepCharge: 0 };
      const existing = Object.values(state.approvals).find(item => item.key === key && item.status === 'pending' && item.expiresAt > this.clock());
      const item = existing ?? { id: randomUUID(), kind: 'approval', scope, key, hash, name, summary, expiresAt: this.clock() + ttl, status: 'pending' };
      state.approvals[item.id] = item;
      return { status: 'approval_required', approval: structuredClone(item), stepCharge: 0 };
    });
    if (gate.status === 'denied') return { ...gate, message: 'denied by user', next: 'Choose a different action or explain a safe alternative.', stepCharge: 0 };
    if (gate.status === 'unknown') {
      if (!tool.reconcile) return { status: 'unknown', message: 'Check external outcome; not retried' };
      // Reconciliation must be read-only and search the external system by key.
      try {
        if (await tool.reconcile({ idempotencyKey: key }) === true) {
          this.journal.transaction(state => { state.receipts[key] = { status: 'completed' }; });
          return { status: 'completed', replayed: true };
        }
      } catch { /* Do not leak provider errors or assume execution failed. */ }
      return { status: 'unknown', message: 'Check external outcome; not retried' };
    }
    if (gate.status !== 'execute') return gate;
    try {
      await tool.run(payload, { idempotencyKey: key });
      this.journal.transaction(state => { state.receipts[key] = { status: 'completed' }; });
      return { status: 'completed' };
    } catch {
      return { status: 'unknown', message: 'External outcome uncertain; not retried' };
    }
  }
  recordTask(context, { taskId, firstTryPassed, duplicateExecutions = 0, duplicateCharges = 0, backgroundWaits = 0, secretFindings = 0 }) {
    this.scope(context);
    if (!identifier(taskId) || typeof firstTryPassed !== 'boolean') throw new TypeError('Invalid measurement');
    const counts = { duplicateExecutions, duplicateCharges, backgroundWaits, secretFindings };
    if (Object.values(counts).some(value => !Number.isSafeInteger(value) || value < 0)) throw new TypeError('Invalid count');
    return this.journal.transaction(state => {
      const batch = this.batch(state, context);
      const key = actionHash('task', { taskId });
      if (batch.tasks[key]) return;
      batch.tasks[key] = { firstTryPassed };
      for (const [name, value] of Object.entries(counts)) batch[name] += value;
    });
  }
  metrics(context) {
    this.scope(context);
    return this.journal.transaction(state => {
      const batch = this.batch(state, context);
      const tasks = Object.values(batch.tasks);
      return { tasks: tasks.length, firstTryPasses: tasks.filter(item => item.firstTryPassed).length,
        firstTryPassRate: tasks.length ? tasks.filter(item => item.firstTryPassed).length / tasks.length : null,
        duplicateExecutions: batch.duplicateExecutions, duplicateCharges: batch.duplicateCharges,
        duplicatesPer100Tasks: tasks.length ? 100 * (batch.duplicateExecutions + batch.duplicateCharges) / tasks.length : null,
        backgroundWaits: batch.backgroundWaits, secretFindings: batch.secretFindings, replayed: batch.replayed };
    });
  }
}
