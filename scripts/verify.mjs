#!/usr/bin/env node
/**
 * BEL-151 P1-a public VERIFY (no Grok D3 claim).
 * Usage: MCP_URL=https://mcp.belliedmonkey.cc/mcp/v1 node scripts/verify.mjs
 *
 * Flow: unauth 401 → DCR → authorize (email form) → token → initialize/list/tools.
 */
import crypto from 'node:crypto';
import { writeFileSync, mkdirSync } from 'node:fs';

const MCP_URL = (process.env.MCP_URL || 'https://mcp.belliedmonkey.cc/mcp/v1').replace(/\/$/, '');
const ORIGIN = new URL(MCP_URL).origin;
const EMAIL = process.env.VERIFY_EMAIL || 'verify-p1a@belliedmonkey.cc';
const OUT = process.env.VERIFY_OUT || new URL('../verify-out', import.meta.url).pathname;

const results = [];
function log(step, ok, detail) {
  const row = { step, ok: !!ok, detail, at: new Date().toISOString() };
  results.push(row);
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${step}  ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`);
}

function b64url(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function pkce() {
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

async function main() {
  mkdirSync(OUT, { recursive: true });

  // 1) Unauthenticated → 401 + WWW-Authenticate / resource metadata
  const bare = await fetch(MCP_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-03-26',
        capabilities: {},
        clientInfo: { name: 'bel151-verify', version: '0.1.0' },
      },
    }),
  });
  const www = bare.headers.get('www-authenticate') || '';
  log('unauth_401', bare.status === 401, { status: bare.status, www: www.slice(0, 240) });

  // 2) Discover PRM
  const prmUrl =
    ORIGIN + '/.well-known/oauth-protected-resource' + new URL(MCP_URL).pathname;
  const prmRes = await fetch(prmUrl);
  const prm = prmRes.ok ? await prmRes.json() : null;
  log('prm', prmRes.ok && prm?.resource, prm);

  const asList = prm?.authorization_servers || [ORIGIN];
  const issuer = asList[0];

  // 3) AS metadata
  const asMetaRes = await fetch(new URL('/.well-known/oauth-authorization-server', issuer));
  const asMeta = asMetaRes.ok ? await asMetaRes.json() : null;
  log('as_metadata', !!asMeta?.authorization_endpoint, {
    authorization_endpoint: asMeta?.authorization_endpoint,
    token_endpoint: asMeta?.token_endpoint,
    registration_endpoint: asMeta?.registration_endpoint,
  });

  // 4) Dynamic client registration (or CIMD skip)
  let clientId;
  let clientSecret;
  const redirectUri = 'http://127.0.0.1:9876/callback';
  if (asMeta?.registration_endpoint) {
    const reg = await fetch(asMeta.registration_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'BEL-151 P1-a VERIFY',
        redirect_uris: [redirectUri],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
      }),
    });
    const regBody = await reg.json().catch(() => ({}));
    clientId = regBody.client_id;
    clientSecret = regBody.client_secret;
    log('dcr', reg.ok && !!clientId, { status: reg.status, client_id: clientId });
  } else {
    log('dcr', false, 'no registration_endpoint');
  }

  if (!clientId) {
    writeFileSync(`${OUT}/RESULT-verify.json`, JSON.stringify({ results }, null, 2));
    process.exit(1);
  }

  const { verifier, challenge } = await pkce();
  const state = b64url(crypto.randomBytes(16));
  const authUrl = new URL(asMeta.authorization_endpoint);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('scope', 'mcp:read');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('resource', MCP_URL);

  // 5) GET authorize → HTML form → POST approve
  const jar = new Map();
  function storeCookies(res) {
    const raw = res.headers.getSetCookie?.() || [];
    for (const c of raw) {
      const [nv] = c.split(';');
      const i = nv.indexOf('=');
      if (i > 0) jar.set(nv.slice(0, i), nv.slice(i + 1));
    }
    // fallback single set-cookie
    const one = res.headers.get('set-cookie');
    if (one && raw.length === 0) {
      const [nv] = one.split(';');
      const i = nv.indexOf('=');
      if (i > 0) jar.set(nv.slice(0, i), nv.slice(i + 1));
    }
  }
  function cookieHeader() {
    return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  const authGet = await fetch(authUrl, {
    redirect: 'manual',
    headers: { accept: 'text/html' },
  });
  storeCookies(authGet);
  const html = await authGet.text();
  const handleMatch = html.match(/name="handle"\s+value="([^"]+)"/);
  const handle = handleMatch?.[1];
  log('authorize_get', authGet.status === 200 && !!handle, {
    status: authGet.status,
    handle: handle ? handle.slice(0, 12) + '…' : null,
  });
  if (!handle) {
    writeFileSync(`${OUT}/authorize.html`, html.slice(0, 4000));
    writeFileSync(`${OUT}/RESULT-verify.json`, JSON.stringify({ results }, null, 2));
    process.exit(1);
  }

  const form = new URLSearchParams();
  form.set('handle', handle);
  form.set('decision', 'approve');
  form.set('email', EMAIL);
  form.set('flavor', MCP_URL.includes('.com/') && !MCP_URL.includes('.cc') ? 'china' : 'intl');
  form.append('scope', 'mcp:read');

  const authPost = await fetch(new URL('/authorize', issuer), {
    method: 'POST',
    redirect: 'manual',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      cookie: cookieHeader(),
    },
    body: form.toString(),
  });
  storeCookies(authPost);
  const loc = authPost.headers.get('location') || '';
  log('authorize_post', authPost.status >= 300 && authPost.status < 400 && loc.includes('code='), {
    status: authPost.status,
    location: loc.slice(0, 120),
  });
  if (!loc.includes('code=')) {
    writeFileSync(`${OUT}/RESULT-verify.json`, JSON.stringify({ results }, null, 2));
    process.exit(1);
  }
  const redirected = new URL(loc);
  const code = redirected.searchParams.get('code');

  // 6) Token
  const tokenBody = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri,
    client_id: clientId,
    code_verifier: verifier,
    resource: MCP_URL,
  });
  if (clientSecret) tokenBody.set('client_secret', clientSecret);
  const tokenRes = await fetch(asMeta.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: tokenBody.toString(),
  });
  const tokenJson = await tokenRes.json().catch(() => ({}));
  const access = tokenJson.access_token;
  log('token', tokenRes.ok && !!access, {
    status: tokenRes.status,
    token_type: tokenJson.token_type,
    scope: tokenJson.scope,
  });
  if (!access) {
    writeFileSync(`${OUT}/RESULT-verify.json`, JSON.stringify({ results, tokenJson }, null, 2));
    process.exit(1);
  }

  async function mcp(method, params, id) {
    const res = await fetch(MCP_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        authorization: `Bearer ${access}`,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
    });
    const text = await res.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      // SSE: take last data line
      const lines = text.split('\n').filter((l) => l.startsWith('data:'));
      const last = lines[lines.length - 1];
      json = last ? JSON.parse(last.slice(5).trim()) : { raw: text.slice(0, 500) };
    }
    return { status: res.status, json };
  }

  const init = await mcp(
    'initialize',
    {
      protocolVersion: '2025-03-26',
      capabilities: {},
      clientInfo: { name: 'bel151-verify', version: '0.1.0' },
    },
    1,
  );
  log('initialize', init.status === 200 && !!init.json?.result, {
    status: init.status,
    server: init.json?.result?.serverInfo,
  });

  // notifications/initialized (no id)
  await fetch(MCP_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      authorization: `Bearer ${access}`,
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    }),
  });

  const listed = await mcp('tools/list', {}, 2);
  const names = (listed.json?.result?.tools || []).map((t) => t.name);
  const expected = [
    'ready.check',
    'open_setup',
    'start_live_subtitles',
    'translate_page',
    'translate_video_captions',
    'capture_to_study',
    'explain_or_drill',
  ];
  log(
    'tools_list_seven',
    names.length === 7 && expected.every((n, i) => names[i] === n || names.includes(n)),
    { names },
  );

  async function callTool(name, args, id) {
    const r = await mcp('tools/call', { name, arguments: args || {} }, id);
    const text = r.json?.result?.content?.[0]?.text;
    let receipt;
    try {
      receipt = JSON.parse(text);
    } catch {
      receipt = { parse_error: true, text: String(text).slice(0, 200) };
    }
    return { status: r.status, receipt, raw: r.json };
  }

  const ready = await callTool('ready.check', { source: 'mcp' }, 3);
  log(
    'ready_check_honest_gap',
    ready.status === 200 &&
      ready.receipt?.ok === true &&
      ready.receipt?.code === 'ok' &&
      String(ready.receipt?.message || '').includes('need_app'),
    ready.receipt,
  );

  const setup = await callTool('open_setup', { step: 'install_app', source: 'mcp' }, 4);
  const link = setup.receipt?.fix?.open_setup || '';
  log(
    'open_setup',
    setup.status === 200 &&
      setup.receipt?.ok === true &&
      (link.startsWith('belliedmonkey://') || link.startsWith('belliedmonkeycn://')),
    setup.receipt,
  );

  const sens = await callTool('translate_page', { source: 'mcp' }, 5);
  log(
    'sensitive_need_app_or_confirm',
    sens.status === 200 &&
      sens.receipt?.ok === false &&
      (sens.receipt?.code === 'need_app' || sens.receipt?.code === 'need_confirm'),
    sens.receipt,
  );

  const pass = results.every((r) => r.ok);
  writeFileSync(
    `${OUT}/RESULT-verify.json`,
    JSON.stringify({ pass, MCP_URL, EMAIL, results }, null, 2),
  );
  console.log(pass ? '\nVERIFY_PASS' : '\nVERIFY_FAIL');
  process.exit(pass ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
