#!/usr/bin/env node
/**
 * BEL-151 A3 live smoke: real Supabase login → consent → code → token → MCP.
 * Usage: node scripts/a3-smoke.mjs <outdir>
 * Reads SMOKE_EMAIL/SMOKE_PASS from env or verify/smoke-creds.env.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const ORIGIN = process.env.MCP_ORIGIN || 'https://mcp.belliedmonkey.cc';
const MCP_URL = `${ORIGIN}/mcp/v1`;
const MCP_RESOURCE = process.env.MCP_RESOURCE || MCP_URL;
const OUT = process.argv[2] || 'verify/a3';
fs.mkdirSync(OUT, { recursive: true });

function loadCreds() {
  const env = { ...process.env };
  const p = process.env.SMOKE_CREDS || 'verify/smoke-creds.env';
  if (fs.existsSync(p)) {
    for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
      const m = line.match(/^([A-Z_]+)=(.*)$/);
      if (m && !env[m[1]]) env[m[1]] = m[2];
    }
  }
  return { email: env.SMOKE_EMAIL, pass: env.SMOKE_PASS };
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

class Jar {
  constructor() { this.map = new Map(); }
  store(res) {
    const list = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    for (const c of list) {
      const [nv] = c.split(';');
      const i = nv.indexOf('=');
      if (i > 0) this.map.set(nv.slice(0, i).trim(), nv.slice(i + 1));
    }
  }
  header() { return [...this.map].map(([k, v]) => `${k}=${v}`).join('; '); }
  has(k) { return this.map.has(k); }
}

const rows = [];
function log(step, ok, detail) {
  rows.push({ step, ok: !!ok, detail, at: new Date().toISOString() });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${step}  ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`);
}

async function post(url, { jar, form, json, headers = {} } = {}) {
  const h = new Headers(headers);
  if (jar?.header()) h.set('cookie', jar.header());
  let body;
  if (form) { h.set('content-type', 'application/x-www-form-urlencoded'); body = new URLSearchParams(form).toString(); }
  else if (json) { h.set('content-type', 'application/json'); body = JSON.stringify(json); }
  const res = await fetch(url, { method: 'POST', headers: h, body, redirect: 'manual' });
  jar?.store(res);
  return res;
}

function dcr() {
  return fetch(`${ORIGIN}/oauth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_name: 'BEL-151 A3 Supabase Smoke',
      redirect_uris: ['http://127.0.0.1:8765/callback'],
      grant_types: ['authorization_code'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    }),
  });
}

function makeAuthUrl(clientId, verifier, state) {
  const u = new URL(`${ORIGIN}/authorize`);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('client_id', clientId);
  u.searchParams.set('redirect_uri', 'http://127.0.0.1:8765/callback');
  u.searchParams.set('scope', 'mcp:read');
  u.searchParams.set('state', state);
  u.searchParams.set('code_challenge', b64url(crypto.createHash('sha256').update(verifier).digest()));
  u.searchParams.set('code_challenge_method', 'S256');
  u.searchParams.set('resource', MCP_RESOURCE);
  return u.toString();
}

function parseHandle(html) {
  return html.match(/name="handle"\s+value="([^"]+)"/)?.[1] || null;
}

function decodeEntities(s) {
  return String(s)
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>');
}

async function main() {
  const creds = loadCreds();
  if (!creds.email || !creds.pass) throw new Error('missing SMOKE_EMAIL/SMOKE_PASS');

  // DCR
  const regRes = await dcr();
  const reg = await regRes.json();
  const clientId = reg.client_id;
  log('dcr', regRes.ok && !!clientId, { status: regRes.status, client_id: clientId });
  fs.writeFileSync(path.join(OUT, 'dcr.json'), JSON.stringify(reg, null, 2));

  const verifier = b64url(crypto.randomBytes(48));
  const state = b64url(crypto.randomBytes(16));
  const authUrl = makeAuthUrl(clientId, verifier, state);

  // 1) GET authorize (logged out)
  let jar = new Jar();
  let res = await fetch(authUrl, { headers: { accept: 'text/html' }, redirect: 'manual' });
  jar.store(res);
  let html = await res.text();
  const handle0 = parseHandle(html);
  fs.writeFileSync(path.join(OUT, '01-authorize-logged-out.html'), html);
  log('authorize_logged_out', res.status === 200 && !!handle0 && /登录并继续/.test(html),
    { status: res.status, handle: handle0?.slice(0, 12), hasPassword: /type="password"/.test(html) });
  log('no_free_email_send', !/name="email"[^>]*value=/.test(html), 'logged-out page has no pre-filled email token path');

  // 2) Negative: approve without session using fake email
  const fakeForm = new URLSearchParams({
    handle: handle0 || '', flavor: 'intl', action: 'consent', decision: 'approve',
    email: 'fake-a3@example.com', scope: 'mcp:read',
  });
  const fakeRes = await fetch(`${ORIGIN}/authorize`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'text/html' },
    body: fakeForm.toString(), redirect: 'manual',
  });
  const fakeBody = await fakeRes.text();
  fs.writeFileSync(path.join(OUT, '02-approve-no-session.html'), fakeBody);
  log('negative_approve_no_session', fakeRes.status === 200 && /请先登录大肚猴账号/.test(fakeBody),
    { status: fakeRes.status, location: fakeRes.headers.get('location') });

  // 3) Negative: login with fake email
  const badLogin = new URLSearchParams({ action: 'login', email: 'no-such-a3@example.com', password: 'wrongpass123', return_to: authUrl, handle: handle0 || '', flavor: 'intl' });
  const badRes = await fetch(`${ORIGIN}/authorize`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: badLogin.toString(), redirect: 'manual',
  });
  const badLoc = badRes.headers.get('location') || '';
  log('negative_fake_email_login', badRes.status === 302 && /err=/.test(badLoc) && !/code=/.test(badLoc),
    { status: badRes.status, location: badLoc.slice(0, 140) });

  // 4) Real login with Supabase smoke account
  res = await fetch(authUrl, { headers: { accept: 'text/html' }, redirect: 'manual' });
  jar.store(res);
  html = await res.text();
  const handle = parseHandle(html);
  const hiddenReturn = html.match(/name="return_to"\s+value="([^"]+)"/)?.[1];
  const loginForm = new URLSearchParams({
    action: 'login', email: creds.email, password: creds.pass,
    return_to: hiddenReturn ? decodeEntities(hiddenReturn) : authUrl,
    handle: handle || '', flavor: 'intl',
  });
  res = await post(`${ORIGIN}/authorize`, { jar, form: loginForm });
  const loginLoc = res.headers.get('location') || '';
  const gotSession = jar.has('bm_sb_access');
  fs.writeFileSync(path.join(OUT, '03-login.headers'), `${res.status}\n${[...res.headers].map(([k, v]) => `${k}: ${k === 'set-cookie' ? v.replace(/(bm_sb_access=)[^;]+/, '$1<redacted>') : v}`).join('\n')}`);
  log('login_supabase', res.status === 302 && gotSession,
    { status: res.status, sessionCookie: gotSession, location: loginLoc.slice(0, 100) });

  // 5) GET authorize with session → consent, shows email
  // Reuse the original local URL in dev (canonical host may differ from listener).
  res = await fetch(authUrl, { headers: { accept: 'text/html', cookie: jar.header() }, redirect: 'manual' });
  jar.store(res);
  html = await res.text();
  fs.writeFileSync(path.join(OUT, '04-consent.html'), html);
  const consentHandle = parseHandle(html);
  log('consent_page', res.status === 200 && html.includes(creds.email) && /允许并连接/.test(html),
    { status: res.status, showsEmail: html.includes(creds.email), handle: consentHandle?.slice(0, 12) });
  log('copy_no_banned', !/未接 Supabase/.test(html) && !/临时邮箱门/.test(html) && html.includes('连接成功不代表听译已通。'),
    { banned: /未接 Supabase|临时邮箱门/.test(html), footer: html.includes('连接成功不代表听译已通。') });

  // 6) Approve with session
  const approveForm = new URLSearchParams({ handle: consentHandle || '', flavor: 'intl', action: 'consent', decision: 'approve', scope: 'mcp:read' });
  res = await post(`${ORIGIN}/authorize`, { jar, form: approveForm });
  const loc = res.headers.get('location') || '';
  const code = new URL(loc, ORIGIN).searchParams.get('code');
  fs.writeFileSync(path.join(OUT, '05-approve.headers'), `${res.status}\n${[...res.headers].map(([k, v]) => `${k}: ${v}`).join('\n')}`);
  log('approve_redirect', res.status === 302 && !!code && new URL(loc, ORIGIN).searchParams.get('state') === state,
    { status: res.status, hasCode: !!code, stateOk: new URL(loc, ORIGIN).searchParams.get('state') === state });

  // 7) Token exchange
  const tokRes = await post(`${ORIGIN}/oauth/token`, {
    form: { grant_type: 'authorization_code', code: code || '', redirect_uri: 'http://127.0.0.1:8765/callback', client_id: clientId, code_verifier: verifier },
  });
  const tok = await tokRes.json();
  fs.writeFileSync(path.join(OUT, '06-token.json'), JSON.stringify({ ...tok, access_token: tok.access_token ? '<redacted>' : undefined, refresh_token: tok.refresh_token ? '<redacted>' : undefined }, null, 2));
  log('token_exchange', tokRes.ok && !!tok.access_token, { status: tokRes.status, token_type: tok.token_type, scope: tok.scope });

  // 8) MCP initialize / tools/list / ready.check
  const mcpHeaders = {
    authorization: `Bearer ${tok.access_token}`,
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
  };
  res = await fetch(MCP_URL, {
    method: 'POST', headers: mcpHeaders,
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'bel151-a3-smoke', version: '0.1.0' } } }),
  });
  const initText = await res.text();
  const sid = res.headers.get('mcp-session-id');
  fs.writeFileSync(path.join(OUT, '07-mcp-initialize.txt'), `status=${res.status}\nsession=${sid}\n${initText}`);
  log('mcp_initialize', res.ok && /\"protocolVersion\"/.test(initText), { status: res.status, session: !!sid, protocol: (initText.match(/protocolVersion\":\"([^\"]+)/) || [])[1] });

  if (sid) mcpHeaders['mcp-session-id'] = sid;
  await fetch(MCP_URL, {
    method: 'POST', headers: mcpHeaders,
    body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
  }).catch(() => {});

  res = await fetch(MCP_URL, {
    method: 'POST', headers: mcpHeaders,
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
  });
  const listText = await res.text();
  fs.writeFileSync(path.join(OUT, '08-tools-list.txt'), listText);
  let tools = [];
  try {
    const dataLine = listText.split('\n').find((l) => l.startsWith('data: '));
    const parsed = JSON.parse(dataLine.slice(6));
    tools = (parsed.result?.tools || []).map((t) => t.name);
  } catch {}
  const expect = ['ready.check','open_setup','start_live_subtitles','translate_page','translate_video_captions','capture_to_study','explain_or_drill'];
  log('tools_list', res.ok && expect.every((t) => tools.includes(t)), { status: res.status, count: tools.length, tools });

  res = await fetch(MCP_URL, {
    method: 'POST', headers: mcpHeaders,
    body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'ready.check', arguments: { source: 'mcp' } } }),
  });
  const callText = await res.text();
  fs.writeFileSync(path.join(OUT, '09-ready-check.txt'), callText);
  const m =
    callText.match(/debug_oauth_user[^0-9a-f]{1,10}([0-9a-f]{8}-[0-9a-f-]{27,})/i) ||
    callText.match(/oauth_user=([0-9a-f-]{36})/i);
  log('props_user_uuid', res.ok && !!m, { status: res.status, oauth_user: m?.[1], humanized: !/oauth_user=/.test(callText) });

  // 9) Unauthenticated MCP still 401
  const bare = await fetch(MCP_URL, {
    method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'noauth', version: '0' } } }),
  });
  log('unauth_401', bare.status === 401, { status: bare.status, www: (bare.headers.get('www-authenticate') || '').slice(0, 120) });

  fs.writeFileSync(path.join(OUT, 'RESULT-smoke.json'), JSON.stringify({ ok: rows.every((r) => r.ok), rows }, null, 2));
  console.log(`\nSMOKE ${rows.every((r) => r.ok) ? 'PASS' : 'FAIL'}`);
  process.exit(rows.every((r) => r.ok) ? 0 : 2);
}

main().catch((e) => { console.error(e); process.exit(1); });
