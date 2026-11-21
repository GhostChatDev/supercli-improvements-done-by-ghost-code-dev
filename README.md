# supercli-improvements-done-by-ghost-code-dev
supercli credits to https://github.com/yashdev9274/supercli.. great tech..

# Ghost Code build prompt — approval, replay, and privacy

Paste this whole file into a new Ghost Code session. Select Ghost Code's own repository first. Do not select the public Nova / supercli fork.

---

You are Ghost Code. Build the approval and safety improvements below in Ghost Code's own source. Work until the tests you add pass. Do not stop after a plan.

## What this is

These are product rules for Ghost Code, learned by reading Nova (supercli), not by copying it.

Credit, keep this text in the commit message and in a short NOTICE comment beside the new approval code:

Patterns adapted from Nova (supercli) by Yash Dewasthale, MIT License.
Copyright (c) 2026 Yash Dewasthale.
https://github.com/yashdev9274/supercli
Their copyright notice and MIT permission notice stay with any copy of their software.
This work reimplements the ideas. It does not copy their source files.

Their code is not ours. Our new Ghost Code code is ours. Putting our name on a fork does not erase their copyright.

## Stop rules

1. If the selected repository is Nova, supercli, or supercli-fork, stop. Say: "Wrong repo. Open Ghost Code's own repository." Do not edit that fork.
2. Do not weaken sign-in, session checks, or row ownership to make a test pass. A change to existing sign-in or access code is never applied automatically: stop and tell the user.
3. Do not put secrets in code, tests, logs, commits, prompts, or sample data. No API keys, database URLs, auth secrets, tokens, or private chat text. Tests use obvious fakes such as "test-secret-not-real".
4. Do not claim a 90–98% success rate. There is no measurement for that yet. Add the counters in "How to measure" and leave the rate unclaimed.
5. Do not publish these notes as a public fact about Nova. The Nova UI gap below was found by reading code, not by running their app.
6. Encryption of Ghost Code messages stays as it is. Do not disable it, log plaintext secrets, or add a debug bypass.
7. Never show one person's pending approval to another person. The server checks user and session on every read and every decision.

## Read before you edit

Search the Ghost Code repository for the real tool-call, commit, publish, and approval code. Map each item below onto files you actually opened. If a file you expected is missing, say so and implement the rule at the real choke point (the function that runs a tool, the function that commits, the function that charges). Do not invent paths.

Do not copy Nova source into this repo. The Nova paths below are study notes only.

## Build these, smallest first

### 1. Unknown tools are writes

Nova note (do not copy): `packages/agent-runtime/tool-policy.ts` classifies a tool as read, write, or unknown. The name is checked first. `requiresApproval` is used only when the name is ambiguous. Unknown tools are allowed in agent mode and blocked in chat and plan mode. That is the gap to avoid, not a rule to copy.

Ghost Code rule: every tool, including MCP connector tools, has an access class: `read` or `write`. Search, read, and fetch are `read` and may run. Commit, publish, send, delete, and pay are `write` and need a tap. A tool with no class is `write` and must ask before it runs. Do not let an unclassified tool run just because the mode is agent.

Test: register a connector tool with no class. Calling it asks for approval and does not run first.

### 2. Denial is a normal answer

Nova note: a denied call returns `{ success: false, denied: true }` and the run is marked ready to resume. It does not throw.

Ghost Code rule: if the user denies, the agent receives "denied by user", replans, and the task is not failed. A denied step is not charged. Do not retry the same denied action in a loop.

Test: deny a commit. Status is not failed. No commit is created. The agent states another route. The charge for that step is zero.

### 3. Unattended work does not wait

Nova note: `apps/web/modules/nova/harness/durable.ts` returns denied immediately when a run is unattended, with the error "Human interaction is unavailable in unattended runs".

Ghost Code rule: a background round (tab closed, next round started by itself) never blocks on a tap. A protected action is skipped, listed in the hand-over note as "skipped, waiting for you", and the round continues with safe work. Nothing protected lands.

Test: start a background round that needs approval. The round finishes. The protected action did not run. The note names it.

### 4. Approval is tied to the exact action, and it expires

Nova note: `apps/web/modules/nova/harness/durable.ts` hashes `{ name, args }` with SHA-256 after sorting object keys (`stableHash`). `durable-store.ts` saves that hash as `normalizedArgsHash`. `expiresAt` is 24 hours ahead and is written on the activity payload inside `wait`, not as its own column. A decision whose hash does not match is not found. An expired interaction throws "Interaction expired; start a new turn".

Ghost Code rule: when the user is asked to approve a commit, publish, send, or pay, store a SHA-256 of the exact action (sorted keys, then the payload). For a commit, the payload is the file paths and the file contents. Show the user a redacted summary, not the raw payload. Approval of hash A does not apply to hash B. If anything changes after approval, refuse with "needs new approval" and ask again. Unanswered approvals expire after 24 hours and must not land later. Expired means "Expired, nothing was changed".

Test A: approve a commit, change one byte, then commit. Refused with "needs new approval".
Test B: create an approval, set the clock past 24 hours, then approve. Rejected. Nothing changed.

### 5. Do not run a finished action twice

Nova note: a tool call that already completed returns its saved result. Uncertain executions are not blindly retried.

Ghost Code rule: every commit, publish, and paid call gets a receipt keyed by round id plus the argument hash. Status is `completed`, `denied`, or `unknown`. After a crash, a `completed` receipt is reused and not run again. An `unknown` receipt is checked against the outside world (does that commit SHA already exist?) and is not simply redone. This is to stop double commits and double charges.

Test: simulate a crash after the commit call succeeds but before the round records success. The next round finds the commit and does not create a second one.

### 6. Every wait has a screen

Nova note, from reading only, not from running their app: the backend can wait on an approval, while the timeline card returns nothing unless the interaction kind is "question". Do not copy this gap. Do not state it as a verified bug in their product.

Ghost Code rule: every interaction kind the backend can create has a renderer. An approval card shows: tool name, redacted summary of what will change (files and a diff, or the send/pay action), expiry time, Approve, and Deny. Approve sends the decision for that hash only. Deny sends denied.

Test: list every interaction kind the backend can persist. Fail the test if any kind has no renderer. Render an approval fixture and assert the summary, expiry, Approve, and Deny are present.

## Privacy on every item above

Before an argument is stored, logged, or shown, redact anything that looks like a secret: API keys, tokens, `*_SECRET`, `DATABASE_URL`, `Authorization` headers, and bearer values. Store the hash plus the redacted summary, never the raw secret. Hand-over notes use the redacted summary only. Approvals are loaded by user id and session id. A request for another user's approval returns not found, not the record.

Test: an argument containing `DATABASE_URL=postgres://user:password@localhost/db` and `Authorization: Bearer test-secret-not-real` is stored and shown with those values replaced. The raw strings are absent from the approval record, the card, and the log line.

## How to measure

Add counters, do not invent a percent. Track, per task batch:

- first-try pass rate (build and tests pass on the first commit)
- duplicate commits or charges per 100 tasks (target 0)
- background rounds stuck waiting (target 0)
- secrets found in logs, commits, or approval cards (target 0)

Do not write "90-98%" anywhere in the product, the README, or the tests.

## Done means

Unknown tool asks before it runs; deny does not fail the task or charge; unattended run skips the protected action and finishes; changed file after approval is refused; expired approval is refused; crash after commit does not commit twice; every interaction kind has a screen; secret strings in the privacy test are absent from stored approval, card, and log; sign-in and ownership checks are unchanged; Nova copyright credit is in the commit message; no secrets and no private chat text are in the diff.

## How to work

Read the real files first. Implement in the order 1, 2, 3, 4, 5, 6. Add the test with each item. Commit to the ghost-code branch only, in small commits, and do not touch main. If a check fails, fix the cause. Do not delete or weaken tests. If you cannot find the choke point for an item, say "no matches" for that item and leave it unbuilt rather than guessing a file.
