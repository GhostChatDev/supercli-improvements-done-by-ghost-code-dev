import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGuard, MemoryStore, DAY_MS, INTERACTION_KINDS, MESSAGES } from '../src/agent-guard.js';
import { renderInteraction, missingRenderers } from '../src/approval-card.js';
import { actionHash, canonical } from '../src/privacy.js';

const alex = { userId: 'user-alex', sessionId: 'session-1', roundId: 'round-1' };
const sam = { userId: 'user-sam', sessionId: 'session-9', roundId: 'round-9' };

function setup() {
  let clock = 1_000_000;
  const logs = [];
  const store = new MemoryStore();
  const repo = []; // fake outside world: commits that exist
  const guard = createGuard({ store, now: () => clock, log: (l) => logs.push(l) });
  let runs = 0;
  guard.registerTool({
    name: 'commit', access: 'write',
    run: async (args) => { runs += 1; repo.push({ sha: `sha-${repo.length + 1}`, message: args.message }); return { sha: repo.at(-1).sha }; },
    verify: async (args) => { const c = repo.find((r) => r.message === args.message); return c ? { exists: true, result: { sha: c.sha } } : { exists: false }; },
  });
  guard.registerTool({ name: 'read_file', access: 'read', run: async () => 'contents' });
  return { guard, store, logs, repo, runs: () => runs, tick: (ms) => { clock += ms; } };
}

const commitArgs = (content = 'hello') => ({ message: 'feat: add file', files: [{ path: 'a.txt', content }] });

async function approveAndRun(guard, ctx, args) {
  const first = await guard.callTool(ctx, 'commit', args);
  await guard.decide(ctx, first.approval.id, 'approve', first.approval.hash);
  return { first, result: await guard.callTool(ctx, 'commit', args, { approvalId: first.approval.id }) };
}

test('canonical hashing ignores key order', () => {
  assert.equal(canonical({ b: 1, a: { d: 2, c: 3 } }), canonical({ a: { c: 3, d: 2 }, b: 1 }));
  assert.equal(actionHash('t', { b: 1, a: 2 }), actionHash('t', { a: 2, b: 1 }));
});

test('1. a connector tool with no class asks for approval and does not run first', async () => {
  const { guard } = setup();
  let ran = false;
  guard.registerTool({ name: 'mcp_unknown', run: async () => { ran = true; } });
  assert.equal(guard.accessOf('mcp_unknown'), 'write');
  const r = await guard.callTool(alex, 'mcp_unknown', { x: 1 });