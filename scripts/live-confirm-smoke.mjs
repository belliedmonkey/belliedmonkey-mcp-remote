#!/usr/bin/env node
/**
 * BEL-151 GAP-2 live smoke (public + optional authenticated B path).
 *
 * Public checks always run. If MCP_TOKEN (or /tmp/bel151-gap2-token) is set,
 * the authenticated pending -> need_confirm -> confirm allow -> resume path is
 * exercised against the live Worker. The token is never printed.
 *
 * Usage:
 *   node scripts/live-confirm-smoke.mjs
 *   MCP_TOKEN=... SMOKE_OUT=/path/verify node scripts/live-confirm-smoke.mjs
 *   MCP_TOKEN=... SMOKE_EXPIRY=1 node scripts/live-confirm-smoke.mjs   # +121s wait
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const MCP_URL = (process.env.MCP_URL || 'https://mcp.belliedmonkey.cc/mcp/v1').replace(/\/$/, '');
const ORIGIN = new URL(MCP_URL).origin;
const OUT = process.env.SMOKE_OUT || '';
let token = process.env.MCP_TOKEN || '';
if (!token && existsSync('/tmp/bel151-gap2-token')) {
  token = readFileSync('/tmp/bel151-gap2-token', 'utf8').trim();
}

const results = [];
function log(name, ok, detail) {
  const row = { name, ok: !!ok, detail };
  results.push(row);
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail === undefined ? '' : '  ' + JSON.stringify(detail)}`);
}
function skip(name, why) {
  results.push({ name, ok: true, skipped: true, detail: why });
  console.log(`SKIP  ${name}  ${why}`);
}

async function mcp(method, params, id) {
  const res = await fetch(MCP_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
  });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    const lines = text.split('\n').filter((l) => l.startsWith('data:'));
    const last = lines[lines.length - 1];
    try {
      json = last ? JSON.parse(last.slice(5).trim()) : null;
    } catch {
      json = null;
    }
  }
  return { status: res.status, json, headers: res.headers };
}

async function callTool(name, args, id) {
  const r = await mcp('tools/call', { name, arguments: args || {} }, id);
  const text = r.json?.result?.content?.[0]?.text;
  let receipt = null;
  try {
    receipt = JSON.parse(text);
  } catch {
    receipt = { parse_error: true, raw: String(text).slice(0, 200) };
  }
  return { status: r.status, receipt };
}

async function ds(path, body) {
  const res = await fetch(`${ORIGIN}/api/mcp/device-sessions/${path}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body || {}),
  });
  return { status: res.status, json: await res.json().catch(() => null), headers: res.headers };
}

// ---------- public checks ---------------------------------------------------
const health = await fetch(`${ORIGIN}/health`);
const healthJson = await health.json().catch(() => null);
log(
  'health_confirm_endpoint',
  health.ok && healthJson?.device_bridge?.confirm === `${ORIGIN}/api/mcp/device-sessions/confirm`,
  { status: health.status, confirm: healthJson?.device_bridge?.confirm },
);

const noAuth = await ds('confirm', {
  pending_id: '00000000-0000-4000-8000-000000000000',
  decision: 'allow',
  device_id: 'x',
  device_cred: 'x',
});
log('confirm_requires_bearer', noAuth.status === 401 && noAuth.json?.error === 'unauthorized', {
  status: noAuth.status,
  body: noAuth.json,
});

const badAuth = await fetch(`${ORIGIN}/api/mcp/device-sessions/confirm`, {
  method: 'POST',
  headers: { authorization: 'Bearer bogus-token', 'content-type': 'application/json' },
  body: JSON.stringify({ pending_id: 'x', decision: 'allow', device_id: 'x', device_cred: 'x' }),
});
const badAuthJson = await badAuth.json().catch(() => null);
log('confirm_rejects_bogus_bearer', badAuth.status === 401, { status: badAuth.status, body: badAuthJson });

const preflight = await fetch(`${ORIGIN}/api/mcp/device-sessions/confirm`, {
  method: 'OPTIONS',
  headers: { origin: 'null', 'access-control-request-method': 'POST' },
});
log(
  'confirm_cors_preflight',
  preflight.status === 204 && preflight.headers.get('access-control-allow-origin') === 'null',
  { status: preflight.status, acao: preflight.headers.get('access-control-allow-origin') },
);

const unauthInit = await mcp('initialize', {
  protocolVersion: '2025-03-26',
  capabilities: {},
  clientInfo: { name: 'bel151-gap2-public', version: '0.0.1' },
}, 1);
log('mcp_requires_bearer', unauthInit.status === 401 && !!unauthInit.headers.get('www-authenticate'), {
  status: unauthInit.status,
});

// ---------- authenticated B path -------------------------------------------
if (!token) {
  for (const name of [
    'initialize_caps_probe',
    'register_test_device',
    'start_need_confirm_pending_deeplink',
    'confirm_allow_resume',
    'same_pending_replay',
    'same_call_wait',
    'confirm_deny_cancelled',
    'revoke_invalidates',
  ]) {
    skip(name, 'no MCP_TOKEN (live positive path needs an OAuth test token; unit/integration tests cover it)');
  }
} else {
  const init = await mcp('initialize', {
    protocolVersion: '2025-03-26',
    capabilities: {},
    clientInfo: { name: 'bel151-gap2-live-smoke', version: '0.0.1' },
  }, 1);
  log('initialize_caps_probe', init.status === 200 && !!init.json?.result, { status: init.status });

  const ready = await callTool('ready.check', { source: 'mcp' }, 2);
  log('ready_check_probe_visible', ready.receipt?.fix?.client_elicit === 'no', {
    client_elicit: ready.receipt?.fix?.client_elicit,
    code: ready.receipt?.code,
  });

  const deviceId = `gap2-smoke-${Date.now()}`;
  const reg = await ds('register', { device_id: deviceId, platform: 'mac', confirm: true });
  const cred = reg.json?.device_cred;
  log('register_test_device', reg.status === 200 && !!cred, { status: reg.status, device_id: deviceId });

  const start = await callTool('start_live_subtitles', { source: 'mcp', video_lang: 'en' }, 3);
  const pendingId = start.receipt?.fix?.pending_id;
  log(
    'start_need_confirm_pending_deeplink',
    start.receipt?.code === 'need_confirm' &&
      typeof pendingId === 'string' &&
      start.receipt?.fix?.action_deeplink?.includes(`pending_id=${pendingId}`) &&
      !start.receipt?.fix?.action_deeplink?.includes('step=mic') &&
      start.receipt?.fix?.openedSubtitles === undefined,
    { code: start.receipt?.code, pending: pendingId, deeplink: start.receipt?.fix?.action_deeplink },
  );

  const allow = await ds('confirm', {
    pending_id: pendingId,
    decision: 'allow',
    device_id: deviceId,
    device_cred: cred,
  });
  log(
    'confirm_allow_resume',
    allow.status === 200 &&
      allow.json?.status === 'allowed' &&
      allow.json?.resumed?.openedSubtitles === true &&
      allow.json?.resumed?.micStarted === false,
    { status: allow.status, resumed: allow.json?.resumed },
  );

  const replay = await callTool('start_live_subtitles', { pending_id: pendingId, source: 'mcp' }, 4);
  log(
    'same_pending_replay',
    replay.receipt?.code === 'ok' &&
      replay.receipt?.fix?.openedSubtitles === true &&
      replay.receipt?.fix?.micStarted === false,
    { code: replay.receipt?.code },
  );

  // Same-call wait needs the server-issued pending id while the request is
  // still open; there is no public listing endpoint. Covered by tool-selftest
  // (real handler + real confirm callback) rather than guessed live ids.
  skip('same_call_wait', 'pending id is only issued at call end; covered by tool-selftest');

  const denyStart = await callTool('start_live_subtitles', { source: 'mcp' }, 7);
  const denyId = denyStart.receipt?.fix?.pending_id;
  const deny = await ds('confirm', {
    pending_id: denyId,
    decision: 'deny',
    device_id: deviceId,
    device_cred: cred,
  });
  const denied = await callTool('start_live_subtitles', { pending_id: denyId, source: 'mcp' }, 8);
  log(
    'confirm_deny_cancelled',
    deny.status === 200 &&
      deny.json?.status === 'denied' &&
      denied.receipt?.code === 'cancelled' &&
      denied.receipt?.fix?.openedSubtitles === false,
    { status: deny.status, code: denied.receipt?.code },
  );

  if (process.env.SMOKE_EXPIRY === '1') {
    const expStart = await callTool('start_live_subtitles', { source: 'mcp' }, 9);
    const expId = expStart.receipt?.fix?.pending_id;
    console.log(`WAIT  expiry test sleeps 121s for pending ${expId}`);
    await new Promise((r) => setTimeout(r, 121000));
    const expConfirm = await ds('confirm', {
      pending_id: expId,
      decision: 'allow',
      device_id: deviceId,
      device_cred: cred,
    });
    log(
      'expiry_410_no_fake_success',
      expConfirm.status === 410 && expConfirm.json?.error === 'pending_expired',
      { status: expConfirm.status, body: expConfirm.json },
    );
  }

  const revokeStart = await callTool('start_live_subtitles', { source: 'mcp' }, 10);
  const revokeId = revokeStart.receipt?.fix?.pending_id;
  const revoke = await ds('revoke', { device_id: deviceId, device_cred: cred });
  const afterRevoke = await ds('confirm', {
    pending_id: revokeId,
    decision: 'allow',
    device_id: deviceId,
    device_cred: cred,
  });
  const afterRevokePlay = await callTool('start_live_subtitles', { pending_id: revokeId, source: 'mcp' }, 11);
  log(
    'revoke_invalidates',
    revoke.status === 200 &&
      (afterRevoke.status === 410 || afterRevoke.status === 401) &&
      afterRevokePlay.receipt?.code !== 'ok' &&
      afterRevokePlay.receipt?.fix?.openedSubtitles !== true,
    { revoke: revoke.json, confirm: afterRevoke.status, replay: afterRevokePlay.receipt?.code },
  );
}

const pass = results.every((r) => r.ok);
const summary = { at: new Date().toISOString(), MCP_URL, authenticated: !!token, pass, results };
if (OUT) {
  mkdirSync(OUT, { recursive: true });
  writeFileSync(resolve(OUT, 'live-smoke.json'), JSON.stringify(summary, null, 2));
}
console.log(pass ? '\nLIVE_SMOKE_PASS' : '\nLIVE_SMOKE_FAIL');
process.exit(pass ? 0 : 1);
