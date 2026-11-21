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
  assert.equal(r.status, 'needs_approval');
  assert.equal(ran, false);
  assert.equal((await guard.callTool(alex, 'read_file', {})).result, 'contents');
});

test('2. denying a commit is a normal answer: not failed, nothing committed, no charge, no loop', async () => {
  const { guard, repo } = setup();
  const first = await guard.callTool(alex, 'commit', commitArgs());
  await guard.decide(alex, first.approval.id, 'deny');
  const r = await guard.callTool(alex, 'commit', commitArgs(), { approvalId: first.approval.id });
  assert.equal(r.denied, true);
  assert.equal(r.taskFailed, false);
  assert.notEqual(r.status, 'failed');
  assert.equal(r.charge, 0);
  assert.equal(r.message, MESSAGES.denied);
  assert.match(r.next, /another route/);
  assert.equal(repo.length, 0);
  const again = await guard.callTool(alex, 'commit', commitArgs());
  assert.equal(again.denied, true); // same denied action is not asked or run again
});

test('3. an unattended round skips the protected action, finishes and names it in the note', async () => {
  const { guard, repo } = setup();
  const bg = { ...alex, unattended: true };
  const r = await guard.callTool(bg, 'commit', commitArgs());
  assert.equal(r.status, 'skipped');
  assert.equal(r.taskFailed, false);
  assert.equal(repo.length, 0);
  assert.match(guard.handoverNote(bg), /commit: feat: add file \(skipped, waiting for you\)/);
  assert.equal(guard.metrics().backgroundStuck, 0);
});

test('4A. changing one byte after approval is refused with "needs new approval"', async () => {
  const { guard, repo } = setup();
  const first = await guard.callTool(alex, 'commit', commitArgs('hello'));
  await guard.decide(alex, first.approval.id, 'approve', first.approval.hash);
  const r = await guard.callTool(alex, 'commit', commitArgs('hellp'), { approvalId: first.approval.id });
  assert.equal(r.status, 'needs_new_approval');
  assert.equal(r.message, 'needs new approval');
  assert.equal(repo.length, 0);
  const wrongHash = await guard.callTool(alex, 'commit', commitArgs('x'));
  assert.equal((await guard.decide(alex, wrongHash.approval.id, 'approve', first.approval.hash)).message, 'needs new approval');
});

test('4B. an approval past 24 hours is rejected and nothing changes', async () => {
  const { guard, repo, tick } = setup();
  const first = await guard.callTool(alex, 'commit', commitArgs());
  tick(DAY_MS + 1);
  const d = await guard.decide(alex, first.approval.id, 'approve', first.approval.hash);
  assert.equal(d.status, 'expired');
  assert.equal(d.message, 'Expired, nothing was changed');
  const r = await guard.callTool(alex, 'commit', commitArgs(), { approvalId: first.approval.id });
  assert.equal(r.status, 'expired');
  assert.equal(repo.length, 0);
});

test('5. a crash after the commit succeeds does not commit twice in the next round', async () => {
  const { guard, store, repo, runs } = setup();
  const first = await guard.callTool(alex, 'commit', commitArgs());
  await guard.decide(alex, first.approval.id, 'approve', first.approval.hash);
  const real = store.putReceipt.bind(store);
  store.putReceipt = async (rec) => { if (rec.status === 'completed') throw new Error('process died'); return real(rec); };
  await assert.rejects(guard.callTool(alex, 'commit', commitArgs(), { approvalId: first.approval.id }), /process died/);
  assert.equal(repo.length, 1);
  store.putReceipt = real;
  const next = { ...alex, roundId: 'round-2' };
  const r = await guard.callTool(next, 'commit', commitArgs(), { approvalId: first.approval.id });
  assert.equal(r.recovered, true);
  assert.equal(r.result.sha, 'sha-1');
  const again = await guard.callTool(next, 'commit', commitArgs(), { approvalId: first.approval.id });
  assert.equal(again.replayed, true);
  assert.equal(repo.length, 1);
  assert.equal(runs(), 1);
});

test('5b. a completed action is not run again', async () => {
  const { guard, repo } = setup();
  const { first } = await approveAndRun(guard, alex, commitArgs());
  const r = await guard.callTool(alex, 'commit', commitArgs(), { approvalId: first.approval.id });
  assert.equal(r.replayed, true);
  assert.equal(repo.length, 1);
});

test('6. every interaction kind has a renderer and the approval card shows what is needed', async () => {
  assert.deepEqual(missingRenderers(INTERACTION_KINDS), []);
  assert.deepEqual(missingRenderers(['approval', 'mystery']), ['mystery']);
  assert.throws(() => renderInteraction({ kind: 'mystery' }), /no renderer/);
  const { guard } = setup();
  const { approval } = await guard.callTool(alex, 'commit', commitArgs());
  const html = renderInteraction(approval);
  assert.match(html, /commit: feat: add file/);
  assert.match(html, /a\.txt/);
  assert.match(html, /Expires <time/);
  assert.match(html, />Approve</);
  assert.match(html, />Deny</);
  assert.match(html, new RegExp(`data-hash="${approval.hash}"`));
});

test('ownership: another person cannot read or decide an approval', async () => {
  const { guard } = setup();
  const { approval } = await guard.callTool(alex, 'commit', commitArgs());
  assert.equal(await guard.getApproval(sam, approval.id), null);
  assert.equal(await guard.getApproval({ ...alex, sessionId: 'other' }, approval.id), null);
  assert.equal((await guard.decide(sam, approval.id, 'approve', approval.hash)).status, 'not_found');
  assert.equal((await guard.callTool(sam, 'commit', commitArgs(), { approvalId: approval.id })).status, 'not_found');
});

test('privacy: secrets are absent from the stored approval, the card and the log line', async () => {
  const { guard, store, logs } = setup();
  const secretText = 'DATABASE_URL=postgres://user:password@localhost/db\nAuthorization: Bearer test-secret-not-real';
  const args = { message: 'deploy Authorization: Bearer test-secret-not-real', files: [{ path: '.env', content: secretText }] };
  const { approval } = await guard.callTool(alex, 'commit', args);
  const stored = JSON.stringify([...store.approvals.values()]);
  const card = renderInteraction(approval);
  const logText = logs.join('\n');
  for (const where of [stored, card, logText, guard.handoverNote(alex)]) {
    assert.ok(!where.includes('password@localhost'), 'database password leaked');
    assert.ok(!where.includes('postgres://user:password'), 'database URL leaked');
    assert.ok(!where.includes('test-secret-not-real'), 'bearer token leaked');
  }
  assert.match(card, /DATABASE_URL=\[REDACTED\]/);
  assert.match(stored, /\[REDACTED\]/);
});

test('metrics are counted, not claimed', () => {
  const { guard } = setup();
  assert.equal(guard.metrics().firstTryPassRate, null);
  guard.recordTask({ passedFirstTry: true });
  guard.recordTask({ passedFirstTry: false });
  const m = guard.metrics();
  assert.equal(m.firstTryPassRate, 0.5);
  assert.equal(m.duplicatesPer100Tasks, 0);
  assert.equal(m.secretsFound, 0);
});
