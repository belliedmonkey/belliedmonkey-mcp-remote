#!/usr/bin/env node
/**
 * BEL-151 com OAuth audience: host → (resource, issuer, well-known) matrix.
 * Pure source test (no Worker runtime): transpiles src/origins.ts and asserts
 * the .cc path is unchanged while .com derives its own origin.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as ts from 'typescript';

const CC = 'https://mcp.belliedmonkey.cc';
const COM = 'https://mcp.belliedmonkey.com';

const source = readFileSync(new URL('../src/origins.ts', import.meta.url), 'utf8');
const js = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.ESNext,
    target: ts.ScriptTarget.ES2022,
  },
}).outputText;
const origins = await import(
  `data:text/javascript;base64,${Buffer.from(js).toString('base64')}`
);

let failed = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`PASS  ${name}`);
  } catch (error) {
    failed++;
    console.error(`FAIL  ${name}\n      ${error.message}`);
  }
}

const hostCases = [
  ['mcp.belliedmonkey.cc', CC],
  ['mcp.belliedmonkey.com', COM],
  ['MCP.BELLIEDMONKEY.COM', COM],
  // China mid-host keeps the historical .cc provider unless the request Host
  // is actually .com (the edge preserves Host; see health-meta).
  ['mcp-china.belliedmonkey.cc', CC],
  ['belliedmonkey-mcp-remote.belliedmonkey.workers.dev', CC],
  ['localhost:8787', CC],
];

for (const [host, expected] of hostCases) {
  check(`origin ${host} -> ${expected}`, () => {
    assert.equal(origins.originForHostname(host), expected);
  });
}

check('.cc resource metadata is byte-identical to the historical config', () => {
  assert.deepEqual(origins.resourceMetadataFor(CC), {
    resource: 'https://mcp.belliedmonkey.cc/mcp/v1',
    authorization_servers: ['https://mcp.belliedmonkey.cc'],
  });
});

check('.com resource metadata points at .com', () => {
  assert.deepEqual(origins.resourceMetadataFor(COM), {
    resource: 'https://mcp.belliedmonkey.com/mcp/v1',
    authorization_servers: ['https://mcp.belliedmonkey.com'],
  });
});

check('.cc bare PRM document is host-correct', () => {
  assert.deepEqual(origins.protectedResourceMetadataFor(CC), {
    resource: 'https://mcp.belliedmonkey.cc/mcp/v1',
    authorization_servers: ['https://mcp.belliedmonkey.cc'],
    scopes_supported: ['mcp:read'],
    bearer_methods_supported: ['header'],
  });
});

check('.com bare PRM document is host-correct (never .cc)', () => {
  const prm = origins.protectedResourceMetadataFor(COM);
  assert.deepEqual(prm, {
    resource: 'https://mcp.belliedmonkey.com/mcp/v1',
    authorization_servers: ['https://mcp.belliedmonkey.com'],
    scopes_supported: ['mcp:read'],
    bearer_methods_supported: ['header'],
  });
  assert.ok(!JSON.stringify(prm).includes('belliedmonkey.cc'));
});

check('cross-host audiences differ', () => {
  assert.notEqual(
    origins.resourceMetadataFor(CC).resource,
    origins.resourceMetadataFor(COM).resource,
  );
  assert.notEqual(
    origins.resourceMetadataFor(CC).authorization_servers[0],
    origins.resourceMetadataFor(COM).authorization_servers[0],
  );
});

if (failed > 0) {
  console.error(`\nHOST_MATRIX_FAIL (${failed})`);
  process.exit(1);
}
console.log('\nHOST_MATRIX_PASS');
