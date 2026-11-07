#!/usr/bin/env node
/**
 * BEL-213 preview self-test: OAuth five-state storage on preview D1.
 *
 * Runs only against the preview Worker / preview D1 / preview KV:
 *   PREVIEW_ORIGIN  https://belliedmonkey-mcp-remote-preview.belliedmonkey.workers.dev
 *   SELFTEST_ORIGIN https://belliedmonkey-mcp-remote-preview-selftest.belliedmonkey.workers.dev
 *
 * The harness (not part of the app deploy) completes authorization with the
 * library's own completeAuthorization() helper, because the preview Supabase
 * project requires a real email confirmation for interactive login.
 */
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..');
const OUT = process.env.OUT || resolve(REPO, '..', '..');
const PREVIEW = (process.env.PREVIEW_ORIGIN ||
  'https://belliedmonkey-mcp-remote-preview.belliedmonkey.workers.dev').replace(/\/$/, '');
const HARNESS = (process.env.SELFTEST_ORIGIN ||
  'https://belliedmonkey-mcp-remote-preview-selftest.belliedmonkey.workers.dev').replace(/\/$/, '');
const TOKEN = process.env.SELFTEST_TOKEN || '';
const DB = process.env.OAUTH_DB_BINDING || 'OAUTH_DB';
const WRANGLER = resolve(REPO, 'node_modules/.bin/wrangler');
const NONCE = crypto.randomBytes(6).toString('hex');
const USER_ID = `bel213-selftest-${NONCE}`;
const REDIRECT_URI = 'http://127.0.0.1:9876/callback';
const SCOPE = ['mcp:read', 'mcp:write', 'offline_access'];

if (!TOKEN) {
  console.error('SELFTEST_TOKEN is required');
  process.exit(2);
}
mkdirSync(OUT, { recursive: true });

const results = [];
function record(test, step, ok, detail) {
  const row = { test, step, ok: !!ok, detail, at: new Date().toISOString() };
  results.push(row);
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${test}  ${step}  ${JSON.stringify(detail)}`);
  return !!ok;
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function d1(sql) {
  const stdout = execFileSync(
    WRANGLER,
    ['d1', 'execute', DB, '--remote', '--env', 'preview', '--command', sql, '--json'],
    { cwd: REPO, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const parsed = JSON.parse(stdout);
  return parsed[0]?.results ?? [];
}

async function jsonFetch(url, init) {
  const res = await fetch(url, init);
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = { raw: text.slice(0, 300) };
  }
  return { res, status: res.status, body };
}

async function harness(path, init = {}) {
  return jsonFetch(`${HARNESS}${path}`, {
    ...init,
    headers: {
      'x-selftest-token': TOKEN,
      ...(init.body ? { 'content-type': 'application/json' } : {}),
      ...(init.headers || {}),
    },
  });
}

async function harnessJson(path, body) {
  return harness(path, { method: 'POST', body: JSON.stringify(body) });
}

async function mcp(token, method, params, id) {
  const res = await fetch(`${PREVIEW}/mcp/v1`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
  });
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    const line = text.split('\n').filter((l) => l.startsWith('data:')).pop();
    try {
      body = line ? JSON.parse(line.slice(5).trim()) : { raw: text.slice(0, 300) };
    } catch {
      body = { raw: text.slice(0, 300) };
    }
  }
  return { status: res.status, body };
}

async function main() {
  // ------------------------------------------------------------------ T1
  const reg = await jsonFetch(`${PREVIEW}/oauth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: `BEL-213 preview selftest ${NONCE}`,
      redirect_uris: [REDIRECT_URI],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      scope: SCOPE.join(' '),
    }),
  });
  const clientId = reg.body.client_id;
  record('T1', 'dcr_client', reg.status === 201 && !!clientId, {
    status: reg.status,
    client_id: clientId || null,
  });
  if (!clientId) return finish();

  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  const state = b64url(crypto.randomBytes(12));

  const complete = await harnessJson('/__complete', {
    clientId,
    redirectUri: REDIRECT_URI,
    scope: SCOPE,
    state,
    codeChallenge: challenge,
    codeChallengeMethod: 'S256',
    resource: `${PREVIEW}/mcp/v1`,
    userId: USER_ID,
  });
  const redirectTo = complete.body.redirectTo || '';
  const code = redirectTo ? new URL(redirectTo).searchParams.get('code') : null;
  record('T1', 'complete_authorization', complete.status === 200 && !!code, {
    status: complete.status,
    has_code: !!code,
    state_echo: redirectTo ? new URL(redirectTo).searchParams.get('state') : null,
  });
  if (!code) return finish();

  const tokenForm = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    client_id: clientId,
    code_verifier: verifier,
    resource: `${PREVIEW}/mcp/v1`,
  });
  const tokenRes = await jsonFetch(`${PREVIEW}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: tokenForm.toString(),
  });
  const accessToken = tokenRes.body.access_token;
  record('T1', 'token_exchange', tokenRes.status === 200 && !!accessToken, {
    status: tokenRes.status,
    token_type: tokenRes.body.token_type,
    expires_in: tokenRes.body.expires_in,
    scope: tokenRes.body.scope,
    access_token_len: accessToken ? accessToken.length : 0,
  });
  if (!accessToken) return finish();

  const clientRows = d1(`SELECT k FROM oauth_kv WHERE k = 'client:${clientId.replace(/'/g, "''")}'`);
  const grantRows = d1(`SELECT k FROM oauth_kv WHERE k LIKE 'grant:${USER_ID}:%'`);
  const tokenRows = d1(`SELECT k FROM oauth_kv WHERE k LIKE 'token:${USER_ID}:%' ORDER BY k`);
  record(
    'T1',
    'd1_client_grant_token_rows',
    clientRows.length === 1 && grantRows.length >= 1 && tokenRows.length >= 1,
    {
      client_rows: clientRows.length,
      grant_keys: grantRows.map((r) => r.k),
      token_rows: tokenRows.length,
      token_key_prefixes: tokenRows.map((r) => String(r.k).slice(0, 24) + '…'),
    },
  );

  // ------------------------------------------------------------------ T2
  if (tokenRows.length > 0) {
    const tokenKey = tokenRows[0].k;
    const first = await harness(`/__kv/get?key=${encodeURIComponent(tokenKey)}&type=json`);
    const second = await harness(`/__kv/get?key=${encodeURIComponent(tokenKey)}&type=json`);
    record(
      'T2',
      'token_get_twice_still_hits',
      first.status === 200 && second.status === 200 && first.body.value && second.body.value,
      {
        first_hit: !!first.body.value,
        second_hit: !!second.body.value,
        same_grant: first.body.value?.grantId === second.body.value?.grantId,
      },
    );
  }

  const jti = b64url(crypto.randomBytes(16));
  const jtiFirst = await harnessJson('/__jti', { issuer: 'bel213-preview', jti, exp: Math.floor(Date.now() / 1000) + 300 });
  const jtiSecond = await harnessJson('/__jti', { issuer: 'bel213-preview', jti, exp: Math.floor(Date.now() / 1000) + 300 });
  record('T2', 'same_jti_second_rejected', jtiFirst.body.replayed === false && jtiSecond.body.replayed === true, {
    first: jtiFirst.body.replayed,
    second: jtiSecond.body.replayed,
    key: jtiSecond.body.key ? `${jtiSecond.body.key.slice(0, 30)}…` : null,
  });
  if (jtiSecond.body.key) {
    d1(
      `UPDATE oauth_kv SET expires_at = unixepoch() - 1 WHERE k = '${String(jtiSecond.body.key).replace(/'/g, "''")}'`,
    );
    const jtiThird = await harnessJson('/__jti', { issuer: 'bel213-preview', jti, exp: Math.floor(Date.now() / 1000) + 300 });
    record('T2', 'expired_jti_does_not_block_retry', jtiThird.body.replayed === false, {
      after_expiry: jtiThird.body.replayed,
    });
  }

  // ------------------------------------------------------------------ T3
  const ttlKey = `token:bel213-ttl-${NONCE}`;
  const putRes = await harnessJson('/__kv/put', { key: ttlKey, value: 'ttl-value', expirationTtl: 5 });
  const ttlRow = d1(
    `SELECT expires_at - unixepoch() AS ttl FROM oauth_kv WHERE k = '${ttlKey}'`,
  );
  record('T3', 'ttl_min_60s_clamped', putRes.status === 200 && ttlRow.length === 1 && ttlRow[0].ttl >= 55, {
    requested_ttl: 5,
    stored_ttl_sec: ttlRow[0]?.ttl ?? null,
  });
  const beforeExpiry = await harness(`/__kv/get?key=${encodeURIComponent(ttlKey)}`);
  record('T3', 'get_before_expiry', beforeExpiry.body.value === 'ttl-value', {
    value: beforeExpiry.body.value,
  });
  d1(`UPDATE oauth_kv SET expires_at = unixepoch() - 1 WHERE k = '${ttlKey}'`);
  const afterExpiry = await harness(`/__kv/get?key=${encodeURIComponent(ttlKey)}`);
  const expiryList = await harness(`/__kv/list?prefix=${encodeURIComponent(ttlKey)}`);
  record(
    'T3',
    'expired_get_null_and_list_hidden',
    afterExpiry.body.value === null && Array.isArray(expiryList.body.keys) && expiryList.body.keys.length === 0,
    {
      get_after_expiry: afterExpiry.body.value,
      list_after_expiry: expiryList.body.keys?.length,
    },
  );

  const jsonKey = `client:bel213-json-${NONCE}`;
  await harnessJson('/__kv/put', { key: jsonKey, value: JSON.stringify({ a: 1, b: 'x' }), metadata: { probe: true } });
  const jsonGet = await harness(`/__kv/get?key=${encodeURIComponent(jsonKey)}&type=json`);
  const jsonList = await harness(`/__kv/list?prefix=${encodeURIComponent(jsonKey)}`);
  record(
    'T3',
    'get_json_and_list_metadata',
    jsonGet.body.value?.a === 1 &&
      jsonGet.body.value?.b === 'x' &&
      jsonList.body.keys?.[0]?.metadata?.probe === true,
    {
      json: jsonGet.body.value,
      list_metadata: jsonList.body.keys?.[0]?.metadata ?? null,
      list_name: jsonList.body.keys?.[0]?.name ?? null,
    },
  );

  // ------------------------------------------------------------------ T4 + T5
  const deviceId = `bel213-mac-${NONCE}`;
  const register = await jsonFetch(`${PREVIEW}/api/mcp/device-sessions/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
    body: JSON.stringify({ device_id: deviceId, platform: 'mac', confirm: true }),
  });
  record('T5', 'device_register_via_preview', register.status === 200 && !!register.body.device_cred, {
    status: register.status,
    ok: register.body.ok,
    device_id: deviceId,
  });

  const init = await mcp(
    accessToken,
    'initialize',
    {
      protocolVersion: '2025-03-26',
      capabilities: {},
      clientInfo: { name: 'bel213-preview-selftest', version: '0.1.0' },
    },
    1,
  );
  record('T4', 'mcp_initialize', init.status === 200 && !!init.body.result, {
    status: init.status,
    server: init.body.result?.serverInfo ?? null,
  });
  await fetch(`${PREVIEW}/mcp/v1`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
  });

  const call = await mcp(accessToken, 'tools/call', { name: 'start_live_subtitles', arguments: { source: 'mcp' } }, 2);
  const text = call.body.result?.content?.[0]?.text;
  let receipt = null;
  try {
    receipt = JSON.parse(text);
  } catch {
    receipt = null;
  }
  record(
    'T4',
    'start_live_subtitles_unconfirmed_need_confirm',
    call.status === 200 &&
      receipt?.ok === false &&
      receipt?.code === 'need_confirm' &&
      receipt?.micStarted === false &&
      receipt?.openedSubtitles === false,
    {
      http: call.status,
      ok: receipt?.ok,
      code: receipt?.code,
      micStarted: receipt?.micStarted,
      openedSubtitles: receipt?.openedSubtitles,
      pending_id: receipt?.fix?.pending_id ?? null,
      action_deeplink_has_pending: String(receipt?.fix?.action_deeplink || '').includes('pending_id='),
    },
  );

  const pendingList = await harness('/__kv/list?prefix=pending_confirm%3A');
  const pendingNames = (pendingList.body.keys || []).map((k) => k.name);
  const ourPending = pendingNames.find((name) => name.includes(USER_ID)) || pendingNames[0];
  let pendingValue = null;
  if (ourPending) {
    const got = await harness(`/__kv/get?key=${encodeURIComponent(ourPending)}`);
    pendingValue = got.body.value;
  }
  record('T5', 'pending_in_preview_kv', !!ourPending && !!pendingValue, {
    pending_keys: pendingNames.length,
    pending_key: ourPending ? `${ourPending.slice(0, 28)}…` : null,
    pending_value_present: !!pendingValue,
  });
  const pendingD1 = d1(`SELECT count(*) AS n FROM oauth_kv WHERE k LIKE 'pending_confirm:%'`);
  const deviceD1 = d1(`SELECT count(*) AS n FROM oauth_kv WHERE k LIKE 'device_session:%'`);
  record(
    'T5',
    'pending_and_device_not_in_d1',
    pendingD1[0].n === 0 && deviceD1[0].n === 0,
    { pending_rows_in_d1: pendingD1[0].n, device_rows_in_d1: deviceD1[0].n },
  );

  // Keep one token key id around for the report (never print the token itself).
  record('T1', 'access_token_not_logged', true, {
    access_token_len: accessToken.length,
    stored_token_rows: tokenRows.length,
  });

  return finish();
}

function finish() {
  const failed = results.filter((r) => !r.ok);
  const summary = {
    generated_at: new Date().toISOString(),
    preview_origin: PREVIEW,
    harness_origin: HARNESS,
    user_id: USER_ID,
    ok: failed.length === 0 && results.length > 0,
    failed: failed.length,
    passed: results.length - failed.length,
    results,
  };
  writeFileSync(resolve(OUT, 'selftest-results.json'), JSON.stringify(summary, null, 2));
  console.log(`\n${summary.ok ? 'SELFTEST PASS' : 'SELFTEST FAIL'}  passed=${summary.passed} failed=${summary.failed}`);
  process.exit(summary.ok ? 0 : 1);
}

main().catch((error) => {
  record('harness', 'uncaught', false, { error: String(error) });
  finish();
});
