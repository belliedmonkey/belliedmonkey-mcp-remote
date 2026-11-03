#!/usr/bin/env node
/**
 * BEL-151 GAP-2 self-test · pending_confirm store + /confirm endpoint.
 *
 * Uses the real src modules bundled by esbuild, with an in-memory KV and a
 * mock OAuth token unwrapper. No cloud credentials and no side effects.
 *
 * Usage: node scripts/confirm-selftest.mjs
 *        SELFTEST_OUT=/path/to/verify node scripts/confirm-selftest.mjs
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..');
const build = resolve(repo, '.test-build');
mkdirSync(build, { recursive: true });

const esbuild = resolve(repo, 'node_modules/.bin/esbuild');
for (const [entry, out] of [
  ['src/pending-confirm.ts', 'pending-confirm.mjs'],
  ['src/device-sessions.ts', 'device-sessions.mjs'],
  ['src/client-caps.ts', 'client-caps.mjs'],
]) {
  execFileSync(
    esbuild,
    [entry, '--bundle', '--format=esm', '--platform=node', `--outfile=${resolve(build, out)}`],
    { cwd: repo, stdio: 'pipe' },
  );
}

const P = await import(pathToFileURL(resolve(build, 'pending-confirm.mjs')).href);
const D = await import(pathToFileURL(resolve(build, 'device-sessions.mjs')).href);
const C = await import(pathToFileURL(resolve(build, 'client-caps.mjs')).href);

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

function makeEnv() {
  const kv = new MockKV();
  const users = {
    'tok-a': 'sub-a',
    'tok-b': 'sub-b',
  };
  const env = {
    OAUTH_KV: kv,
    MCP_RESOURCE_URL: 'https://mcp.example/mcp/v1',
    ISSUER: 'https://mcp.example',
    OAUTH_PROVIDER: {
      async unwrapToken(token) {
        const userId = users[token];
        if (!userId) return null;
        return { userId, grant: { props: { userId } } };
      },
    },
  };
  return env;
}

async function post(env, path, token, body) {
  const res = await D.handleDeviceSessions(
    new Request(`https://mcp.example${path}`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
    }),
    env,
  );
  let json = null;
  try {
    json = await res.json();
  } catch {
    json = null;
  }
  return { status: res.status, json };
}

const env = makeEnv();

// ---------- register two devices (same account) + one cross-account device ----
const regA = await post(env, '/api/mcp/device-sessions/register', 'tok-a', {
  device_id: 'dev-a',
  platform: 'mac',
  confirm: true,
});
const regB = await post(env, '/api/mcp/device-sessions/register', 'tok-a', {
  device_id: 'dev-b',
  platform: 'mac',
  confirm: true,
});
const regC = await post(env, '/api/mcp/device-sessions/register', 'tok-b', {
  device_id: 'dev-c',
  platform: 'mac',
  confirm: true,
});
check('register_devices', regA.status === 200 && regB.status === 200 && regC.status === 200, {
  a: regA.status,
  b: regB.status,
  c: regC.status,
});

const credA = regA.json.device_cred;
const credB = regB.json.device_cred;
const credC = regC.json.device_cred;

// ---------- pending shape + args hash ----------------------------------------
const args = { video_lang: 'en', my_lang: 'zh', pending_id: 'ignored', wait_sec: 5 };
const p1 = await P.createPending(env, {
  oauth_sub: 'sub-a',
  device_id: 'dev-a',
  action: 'start_live_subtitles',
  args,
});
const raw1 = await env.OAUTH_KV.get(`pending_confirm:sub-a:${p1.pending_id}`);
check(
  'pending_shape_ttl120',
  p1.status === 'pending' &&
    p1.expires_at - p1.created_at === 120000 &&
    typeof p1.args_hash === 'string' &&
    p1.args_hash.length === 64,
  { ttl_ms: p1.expires_at - p1.created_at, hash_len: p1.args_hash.length },
);
check(
  'args_hash_no_plaintext_and_stable',
  p1.args_hash === (await P.argsHash(args)) &&
    p1.args_hash === (await P.argsHash({ my_lang: 'zh', video_lang: 'en' })) &&
    !raw1.includes('video_lang') &&
    !raw1.includes('"en"') &&
    !raw1.includes('"zh"'),
  { stored_has_lang: raw1.includes('video_lang') },
);

// ---------- allow → resumed openedSubtitles, micStarted:false -----------------
const allow = await post(env, '/api/mcp/device-sessions/confirm', 'tok-a', {
  pending_id: p1.pending_id,
  decision: 'allow',
  device_id: 'dev-a',
  device_cred: credA,
});
check(
  'confirm_allow_resume',
  allow.status === 200 &&
    allow.json.status === 'allowed' &&
    allow.json.resumed.openedSubtitles === true &&
    allow.json.resumed.micStarted === false &&
    allow.json.resumed.receipt.code === 'ok' &&
    allow.json.resumed.receipt.fix.micStarted === false,
  allow.json,
);

const allowAgain = await post(env, '/api/mcp/device-sessions/confirm', 'tok-a', {
  pending_id: p1.pending_id,
  decision: 'allow',
  device_id: 'dev-a',
  device_cred: credA,
});
check(
  'confirm_allow_idempotent',
  allowAgain.status === 200 &&
    allowAgain.json.status === 'allowed' &&
    allowAgain.json.resumed.receipt.receipt_id === allow.json.resumed.receipt.receipt_id,
  { status: allowAgain.status },
);

const conflict = await post(env, '/api/mcp/device-sessions/confirm', 'tok-a', {
  pending_id: p1.pending_id,
  decision: 'deny',
  device_id: 'dev-a',
  device_cred: credA,
});
check('confirm_conflicting_decision_409', conflict.status === 409 && conflict.json.error === 'already_decided', {
  status: conflict.status,
});

// ---------- deny → cancelled, no openedSubtitles -----------------------------
const p2 = await P.createPending(env, {
  oauth_sub: 'sub-a',
  device_id: 'dev-a',
  action: 'start_live_subtitles',
  args: {},
});
const deny = await post(env, '/api/mcp/device-sessions/confirm', 'tok-a', {
  pending_id: p2.pending_id,
  decision: 'deny',
  device_id: 'dev-a',
  device_cred: credA,
});
check(
  'confirm_deny_cancelled_no_success',
  deny.status === 200 &&
    deny.json.status === 'denied' &&
    deny.json.resumed.code === 'cancelled' &&
    deny.json.resumed.openedSubtitles === false &&
    deny.json.resumed.micStarted === false,
  deny.json,
);

// ---------- wrong credential / wrong device / cross account ------------------
const p3 = await P.createPending(env, {
  oauth_sub: 'sub-a',
  device_id: 'dev-a',
  action: 'start_live_subtitles',
  args: {},
});
const badCred = await post(env, '/api/mcp/device-sessions/confirm', 'tok-a', {
  pending_id: p3.pending_id,
  decision: 'allow',
  device_id: 'dev-a',
  device_cred: 'dc_deadbeef',
});
check('confirm_bad_cred_401', badCred.status === 401 && badCred.json.error === 'unauthorized', {
  status: badCred.status,
});

const crossDevice = await post(env, '/api/mcp/device-sessions/confirm', 'tok-a', {
  pending_id: p3.pending_id,
  decision: 'allow',
  device_id: 'dev-b',
  device_cred: credB,
});
check('confirm_cross_device_403', crossDevice.status === 403 && crossDevice.json.error === 'cross_device', {
  status: crossDevice.status,
});

const crossAccount = await post(env, '/api/mcp/device-sessions/confirm', 'tok-b', {
  pending_id: p3.pending_id,
  decision: 'allow',
  device_id: 'dev-c',
  device_cred: credC,
});
check('confirm_cross_account_403', crossAccount.status === 403 && crossAccount.json.error === 'cross_account', {
  status: crossAccount.status,
});

const unknown = await post(env, '/api/mcp/device-sessions/confirm', 'tok-a', {
  pending_id: '00000000-0000-4000-8000-000000000000',
  decision: 'allow',
  device_id: 'dev-a',
  device_cred: credA,
});
check('confirm_unknown_404', unknown.status === 404 && unknown.json.error === 'pending_not_found', {
  status: unknown.status,
});

// ---------- revoke invalidates pending --------------------------------------
const p4 = await P.createPending(env, {
  oauth_sub: 'sub-a',
  device_id: 'dev-a',
  action: 'start_live_subtitles',
  args: {},
});
const revoke = await post(env, '/api/mcp/device-sessions/revoke', 'tok-a', {
  device_id: 'dev-a',
  device_cred: credA,
});
const afterRevoke = await post(env, '/api/mcp/device-sessions/confirm', 'tok-a', {
  pending_id: p4.pending_id,
  decision: 'allow',
  device_id: 'dev-a',
  device_cred: credA,
});
const p4state = await P.getPending(env, 'sub-a', p4.pending_id);
check(
  'revoke_invalidates_pending',
  revoke.status === 200 &&
    revoke.json.pending_revoked >= 1 &&
    p4state?.status === 'revoked' &&
    (afterRevoke.status === 410
      ? afterRevoke.json.error === 'pending_revoked'
      : afterRevoke.status === 401 && afterRevoke.json.message === 'session_expired') &&
    !JSON.stringify(afterRevoke.json).includes('openedSubtitles'),
  { revoke: revoke.json, pending: p4state?.status, confirm: afterRevoke.json },
);

// ---------- expiry has no fake success --------------------------------------
const old = Date.now() - 121000;
const p5 = await P.createPending(env, {
  oauth_sub: 'sub-a',
  device_id: 'dev-b',
  action: 'start_live_subtitles',
  args: {},
  now: old,
});
const expired = await post(env, '/api/mcp/device-sessions/confirm', 'tok-a', {
  pending_id: p5.pending_id,
  decision: 'allow',
  device_id: 'dev-b',
  device_cred: credB,
});
check(
  'expired_410_no_fake_success',
  expired.status === 410 &&
    expired.json.error === 'pending_expired' &&
    expired.json.status === 'expired' &&
    !JSON.stringify(expired.json).includes('openedSubtitles'),
  { status: expired.status, json: expired.json },
);

// ---------- bridge DOWN revokes remaining pending ---------------------------
const p6 = await P.createPending(env, {
  oauth_sub: 'sub-a',
  device_id: 'dev-b',
  action: 'start_live_subtitles',
  args: {},
});
const revokedByDown = await P.revokeAllPending(env, 'sub-a');
const p6after = await P.getPending(env, 'sub-a', p6.pending_id);
check(
  'bridge_down_revokes_pending',
  revokedByDown >= 1 && p6after?.status === 'revoked',
  { count: revokedByDown, status: p6after?.status },
);

// ---------- GC ---------------------------------------------------------------
const gc = await P.gcPending(env, 'sub-a');
const p7 = await P.createPending(env, {
  oauth_sub: 'sub-a',
  device_id: 'dev-b',
  action: 'start_live_subtitles',
  args: {},
  now: Date.now() - 3 * 24 * 3600 * 1000,
});
const gc2 = await P.gcPending(env, 'sub-a');
const p7after = await P.getPending(env, 'sub-a', p7.pending_id);
check(
  'gc_marks_expired_and_drops_old',
  gc2.expired >= 1 && (p7after === null || p7after.status === 'expired'),
  { first: gc, second: gc2, p7: p7after?.status ?? 'dropped' },
);

// ---------- ACCEPT-PROBE capture / gate -------------------------------------
const capsNo = await C.captureInitialize(
  new Request('https://mcp.example/mcp/v1', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-03-26',
        capabilities: { roots: { listChanged: true } },
        clientInfo: { name: 'probe-no-elicit', version: '0.0.1' },
      },
    }),
  }),
  env,
  'sub-a',
);
const capsYes = await C.captureInitialize(
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
        clientInfo: { name: 'probe-with-elicit', version: '0.0.1' },
      },
    }),
  }),
  env,
  'sub-b',
);
const gotNo = await C.getClientCaps(env, 'sub-a');
const gotYes = await C.getClientCaps(env, 'sub-b');
check(
  'probe_records_client_caps',
  capsNo?.has_elicitation === false &&
    capsYes?.has_elicitation === true &&
    gotNo?.has_elicitation === false &&
    gotYes?.has_elicitation === true &&
    gotYes?.client_name === 'probe-with-elicit',
  { no: gotNo?.has_elicitation, yes: gotYes?.has_elicitation },
);
check(
  'probe_gate_truth_table',
  C.hasElicitationCapability(undefined) === false &&
    C.hasElicitationCapability({}) === false &&
    C.hasElicitationCapability({ elicitation: false }) === false &&
    C.hasElicitationCapability({ elicitation: {} }) === true &&
    C.hasElicitationCapability({ elicitation: { form: {} } }) === true &&
    C.hasElicitationCapability({ elicitation: { url: {} } }) === true,
  {},
);

const pass = results.every((r) => r.ok);
const outDir = process.env.SELFTEST_OUT;
if (outDir) {
  mkdirSync(outDir, { recursive: true });
  writeFileSync(
    resolve(outDir, 'selftest-confirm.json'),
    JSON.stringify({ at: new Date().toISOString(), pass, results }, null, 2),
  );
}
console.log(pass ? '\\nSELFTEST_PASS' : '\\nSELFTEST_FAIL');
process.exit(pass ? 0 : 1);
