#!/usr/bin/env node
/**
 * BEL-151 com OAuth audience live host matrix.
 * Usage: node scripts/host-matrix-live.mjs
 *
 * Read-only. Checks both public hosts derive their own resource/issuer and
 * that the unauthenticated MCP challenge points at the same-host metadata.
 * Token E2E stays in scripts/verify.mjs (needs human consent).
 */
const HOSTS = [
  { host: 'mcp.belliedmonkey.cc', origin: 'https://mcp.belliedmonkey.cc', other: 'https://mcp.belliedmonkey.com' },
  { host: 'mcp.belliedmonkey.com', origin: 'https://mcp.belliedmonkey.com', other: 'https://mcp.belliedmonkey.cc' },
];

let failed = 0;
function log(ok, step, detail) {
  if (!ok) failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${step}  ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`);
}

async function get(url, init = {}) {
  const res = await fetch(url, {
    ...init,
    signal: AbortSignal.timeout(20000),
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    /* non-JSON */
  }
  return { res, text, json };
}

for (const { host, origin, other } of HOSTS) {
  const prmPath = `${origin}/.well-known/oauth-protected-resource/mcp/v1`;
  const bare = `${origin}/.well-known/oauth-protected-resource`;

  const health = await get(`${origin}/health`);
  log(
    health.res.status === 200 && health.json?.mcp === `${origin}/mcp/v1` && health.json?.issuer === origin,
    `${host} health`,
    { status: health.res.status, mcp: health.json?.mcp, issuer: health.json?.issuer },
  );

  const barePrm = await get(bare);
  log(
    barePrm.res.status === 200 &&
      barePrm.json?.resource === `${origin}/mcp/v1` &&
      barePrm.json?.authorization_servers?.length === 1 &&
      barePrm.json.authorization_servers[0] === origin,
    `${host} bare PRM`,
    { status: barePrm.res.status, body: barePrm.json },
  );

  const pathPrm = await get(prmPath);
  log(
    pathPrm.res.status === 200 &&
      pathPrm.json?.resource === `${origin}/mcp/v1` &&
      pathPrm.json?.authorization_servers?.[0] === origin,
    `${host} resource-path PRM`,
    { status: pathPrm.res.status, body: pathPrm.json },
  );
  log(
    JSON.stringify(barePrm.json) === JSON.stringify(pathPrm.json),
    `${host} bare PRM matches resource-path PRM`,
    { bare: barePrm.json, path: pathPrm.json },
  );

  const asMeta = await get(`${origin}/.well-known/oauth-authorization-server`);
  const resources = asMeta.json?.protected_resources || [];
  log(
    asMeta.res.status === 200 &&
      asMeta.json?.issuer === origin &&
      resources.includes(`${origin}/mcp/v1`) &&
      !resources.includes(`${other}/mcp/v1`),
    `${host} AS metadata`,
    { status: asMeta.res.status, issuer: asMeta.json?.issuer, protected_resources: resources },
  );

  const noToken = await get(`${origin}/mcp/v1`, {
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
        clientInfo: { name: 'bel151-host-matrix', version: '0.0.1' },
      },
    }),
  });
  const www = noToken.res.headers.get('www-authenticate') || '';
  log(
    noToken.res.status === 401 && www.includes(`${origin}/.well-known/oauth-protected-resource/mcp/v1`),
    `${host} unauth MCP 401 challenge`,
    { status: noToken.res.status, www_authenticate: www },
  );
}

if (failed > 0) {
  console.error(`\nHOST_MATRIX_LIVE_FAIL (${failed})`);
  process.exit(1);
}
console.log('\nHOST_MATRIX_LIVE_PASS');
