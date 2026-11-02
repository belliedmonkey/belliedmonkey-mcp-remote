#!/usr/bin/env node
/**
 * BEL-151 GAP-2 self-test · real sensitive-tool handler with mock MCP server.
 *
 * Bundles src/tools.ts against a stub for `agents/mcp/server` (auth context)
 * and captures the registered tool callbacks. Uses an in-memory KV + the real
 * device-sessions/confirm handler, so the B path, same-call wait, A gate and
 * negative cases are exercised end-to-end without cloud credentials.
 *
 * Usage: node scripts/tool-selftest.mjs
 *        SELFTEST_OUT=/path/to/verify node scripts/tool-selftest.mjs
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..');
const build = resolve(repo, '.test-build');
mkdirSync(build, { recursive: true });

const stubAgents = resolve(build, 'stub-agents.mjs');
writeFileSync(
  stubAgents,
  `export function getMcpAuthContext() {\n  return { props: { userId: globalThis.__MCP_TEST_SUB || 'sub-a' } };\n}\n`,
);

const esbuild = resolve(repo, 'node_modules/.bin/esbuild');
const buildOne = (entry, out, extra = []) =>
  execFileSync(
    esbuild,
    [entry, '--bundle', '--format=esm', '--platform=node', `--outfile=${resolve(build, out)}`, ...extra],
    { cwd: repo, stdio: 'pipe' },
  );

buildOne('src/pending-confirm.ts', 'pending-confirm.mjs');
buildOne('src/device-sessions.ts', 'device-sessions.mjs');
buildOne('src/client-caps.ts', 'client-caps.mjs');
buildOne('src/tools.ts', 'tools.mjs', [`--alias:agents/mcp/server=${stubAgents}`]);

const P = await import(pathToFileURL(resolve(build, 'pending-confirm.mjs')).href);
const D = await import(pathToFileURL(resolve(build, 'device-sessions.mjs')).href);
const C = await import(pathToFileURL(resolve(build, 'client-caps.mjs')).href);
const T = await import(pathToFileURL(resolve(build, 'tools.mjs')).href);

class MockKV {
  constructor() {
    this.map = new Map();
  }
  async get(k) {
    const e = this.map.get(k);
    if (!e) return null;
    if (e.exp && e.exp <= Date.now()) {
      this.map.delete(k);
      return null;
    }
    return e.v;
  }
  async put(k, v, opts = {}) {
    this.map.set(k, {
      v: String(v),
      exp: opts.expirationTtl ? Date.now() + opts.expirationTtl * 1000 : 0,
    });
  }
  async delete(k) {
    this.map.delete(k);
  }
}

const results = [];
function check(name, cond, detail) {
  const row = { name, ok: !!cond, detail };
  results.push(row);
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail === undefined ? '' : '  ' + JSON.stringify(detail)}`);
}

const kv = new MockKV();
const env = {
  OAUTH_KV: kv,
  MCP_RESOURCE_URL: 'https://mcp.example/mcp/v1',
  ISSUER: 'https://mcp.example',
  OAUTH_PROVIDER: {
    async unwrapToken(token) {
      const userId = token === 'tok-a' ? 'sub-a' : token === 'tok-b' ? 'sub-b' : null;
      return userId ? { userId, grant: { props: { userId } } } : null;
    },
  },
};

async function post(path, token, body) {
  const res = await D.handleDeviceSessions(
    new Request(`https://mcp.example${path}`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
    env,
  );
  return { status: res.status, json: await res.json().catch(() => null) };
}

const reg = await post('/api/mcp/device-sessions/register', 'tok-a', {
  device_id: 'dev-a',
  platform: 'mac',
  confirm: true,
});
const cred = reg.json.device_cred;
check('bridge_up_registered', reg.status === 200 && !!cred, { status: reg.status });

const tools = new Map();
T.registerTools(
  {
    registerTool(name, opts, cb) {
      tools.set(name, { opts, cb });
    },
  },
  'mcp.example',
  env,
);
const live = tools.get('start_live_subtitles');
check('seven_tools_registered', tools.size === 7, { names: [...tools.keys()] });

const ctx = (elicit) => ({ mcpReq: elicit ? { elicitInput: elicit } : {} });

// ---------- probe: no elicitation declared -----------------------------------
await C.captureInitialize(
  new Request('https://mcp.example/mcp/v1', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'probe', version: '1' } },
    }),
  }),
  env,
  'sub-a',
);

// ---------- B: honest need_confirm + pending_id + action deeplink ------------
const first = await live.cb({ video_lang: 'en', my_lang: 'zh', source: 'mcp' }, ctx());
const firstText = JSON.parse(first.content[0].text);
const firstPending = firstText.fix?.pending_id;
check(
  'B_need_confirm_with_pending_and_deeplink',
  firstText.code === 'need_confirm' &&
    typeof firstPending === 'string' &&
    firstText.fix.action_deeplink?.includes(`pending_id=${firstPending}`) &&
    firstText.fix.open_setup?.includes(`pending_id=${firstPending}`) &&
    !firstText.fix.open_setup?.includes('step=mic') &&
    firstText.fix.client_elicit === 'no' &&
    firstText.fix.micStarted === undefined &&
    firstText.fix.openedSubtitles === undefined,
  firstText,
);

const allow = await post('/api/mcp/device-sessions/confirm', 'tok-a', {
  pending_id: firstPending,
  decision: 'allow',
  device_id: 'dev-a',
  device_cred: cred,
});
check(
  'B_confirm_allow_resume_semantics',
  allow.status === 200 &&
    allow.json.status === 'allowed' &&
    allow.json.resumed.openedSubtitles === true &&
    allow.json.resumed.micStarted === false,
  { status: allow.status, resumed: allow.json?.resumed },
);

const replay = await live.cb({ pending_id: firstPending, video_lang: 'en', my_lang: 'zh' }, ctx());
const replayText = JSON.parse(replay.content[0].text);
check(
  'B_same_pending_replay_ok_no_mic',
  replayText.code === 'ok' &&
    replayText.fix.openedSubtitles === true &&
    replayText.fix.micStarted === false &&
    replayText.fix.pending_id === firstPending,
  replayText,
);

// ---------- B: deny → cancelled ---------------------------------------------
const second = await live.cb({ source: 'mcp' }, ctx());
const secondText = JSON.parse(second.content[0].text);
await post('/api/mcp/device-sessions/confirm', 'tok-a', {
  pending_id: secondText.fix.pending_id,
  decision: 'deny',
  device_id: 'dev-a',
  device_cred: cred,
});
const denied = await live.cb({ pending_id: secondText.fix.pending_id }, ctx());
const deniedText = JSON.parse(denied.content[0].text);
check(
  'B_deny_cancelled_no_fake_success',
  deniedText.code === 'cancelled' &&
    deniedText.fix.openedSubtitles === false &&
    deniedText.fix.micStarted === false,
  deniedText,
);

// ---------- B: same-call resume via bounded wait -----------------------------
const beforeWait = JSON.parse(await kv.get('pending_confirm_idx:sub-a'));
const waiting = live.cb({ video_lang: 'ja', wait_sec: 8 }, ctx());
await new Promise((r) => setTimeout(r, 700));
// Find the pending created by the waiting call: diff the index.
const afterWait = JSON.parse(await kv.get('pending_confirm_idx:sub-a'));
const newIds = afterWait.filter((id) => !beforeWait.includes(id));
const newest = await P.getPending(env, 'sub-a', newIds[newIds.length - 1]);
const waitConfirm = await post('/api/mcp/device-sessions/confirm', 'tok-a', {
  pending_id: newest.pending_id,
  decision: 'allow',
  device_id: 'dev-a',
  device_cred: cred,
});
const waited = JSON.parse((await waiting).content[0].text);
check(
  'B_same_call_wait_resumes',
  waitConfirm.status === 200 &&
    waited.code === 'ok' &&
    waited.fix.openedSubtitles === true &&
    waited.fix.micStarted === false &&
    waited.fix.pending_id === newest.pending_id,
  { waited, confirm: waitConfirm.status },
);

// ---------- A gate: no caps → no elicit; caps + accept → confirm only --------
let elicited = 0;
await C.captureInitialize(
  new Request('https://mcp.example/mcp/v1', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-03-26',
        capabilities: { elicitation: {} },
        clientInfo: { name: 'probe-elicit', version: '1' },
      },
    }),
  }),
  env,
  'sub-a',
);
const aAccept = await live.cb({ source: 'mcp' }, ctx(async () => {
  elicited += 1;
  return { action: 'accept', content: { confirm: true } };
}));
const aAcceptText = JSON.parse(aAccept.content[0].text);
check(
  'A_accept_is_confirmation_only',
  elicited === 1 &&
    aAcceptText.code === 'ok' &&
    aAcceptText.fix.openedSubtitles === false &&
    aAcceptText.fix.micStarted === false &&
    aAcceptText.fix.elicit === 'accept',
  aAcceptText,
);

const aDecline = await live.cb({ source: 'mcp' }, ctx(async () => {
  elicited += 1;
  return { action: 'decline' };
}));
const aDeclineText = JSON.parse(aDecline.content[0].text);
check(
  'A_decline_cancelled',
  aDeclineText.code === 'cancelled' && aDeclineText.fix.openedSubtitles === false,
  aDeclineText,
);

const aFail = await live.cb({ source: 'mcp' }, ctx(async () => {
  elicited += 1;
  throw new Error('client channnel unavailable');
}));
const aFailText = JSON.parse(aFail.content[0].text);
check(
  'A_failure_falls_back_to_B_need_confirm',
  aFailText.code === 'need_confirm' && typeof aFailText.fix.pending_id === 'string',
  aFailText,
);

// Reset probe so later B calls are not A-gated.
await C.captureInitialize(
  new Request('https://mcp.example/mcp/v1', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'probe', version: '1' } },
    }),
  }),
  env,
  'sub-a',
);

// ---------- expired pending does not fake success ----------------------------
const old = Date.now() - 121000;
const stale = await P.createPending(env, {
  oauth_sub: 'sub-a',
  device_id: 'dev-a',
  action: 'start_live_subtitles',
  args: { video_lang: 'de' },
  now: old,
});
const afterExpiry = await live.cb({ pending_id: stale.pending_id, video_lang: 'de' }, ctx());
const afterExpiryText = JSON.parse(afterExpiry.content[0].text);
const staleState = await P.getPending(env, 'sub-a', stale.pending_id);
check(
  'expired_replay_new_pending_no_success',
  staleState?.status === 'expired' &&
    afterExpiryText.code === 'need_confirm' &&
    afterExpiryText.fix.pending_id !== stale.pending_id &&
    !afterExpiryText.fix.openedSubtitles,
  { state: staleState?.status, receipt: afterExpiryText.code },
);

// ---------- revoke → pending revoked + bridge DOWN need_app ------------------
const revoke = await post('/api/mcp/device-sessions/revoke', 'tok-a', {
  device_id: 'dev-a',
  device_cred: cred,
});
const down = await live.cb({ source: 'mcp' }, ctx());
const downText = JSON.parse(down.content[0].text);
check(
  'revoke_then_bridge_down_need_app',
  revoke.status === 200 &&
    revoke.json.pending_revoked >= 1 &&
    downText.code === 'need_app' &&
    downText.fix.gap === 'need_app',
  { revoke: revoke.json, receipt: downText.code },
);

const pass = results.every((r) => r.ok);
const outDir = process.env.SELFTEST_OUT;
if (outDir) {
  mkdirSync(outDir, { recursive: true });
  writeFileSync(
    resolve(outDir, 'selftest-tools.json'),
    JSON.stringify({ at: new Date().toISOString(), pass, results }, null, 2),
  );
}
console.log(pass ? '\\nTOOL_SELFTEST_PASS' : '\\nTOOL_SELFTEST_FAIL');
process.exit(pass ? 0 : 1);
