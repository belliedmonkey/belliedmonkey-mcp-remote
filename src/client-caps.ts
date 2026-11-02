/**
 * BEL-151 GAP-2 · ACCEPT-PROBE: record MCP client initialize.capabilities.
 *
 * A is only ever attempted when the client's initialize explicitly declares
 * `capabilities.elicitation`. Absence of a record means "unobserved", never
 * "supported". No record -> A is never claimed as the positive path.
 */
export type ClientCapsRecord = {
  oauth_sub: string;
  observed_at: number;
  protocol_version?: string;
  client_name?: string;
  client_version?: string;
  capabilities: Record<string, unknown>;
  has_elicitation: boolean;
  source: 'mcp_initialize';
};

type EnvLike = { OAUTH_KV: KVNamespace };

const CAPS_TTL_SEC = 60 * 60 * 24 * 30;
const HISTORY_MAX = 5;

function latestKey(sub: string): string {
  return `mcp_client_caps:${sub}`;
}

function historyKey(sub: string): string {
  return `mcp_client_caps_history:${sub}`;
}

/** `{}` counts as form support in MCP 2025-era; any object/true is a declaration. */
export function hasElicitationCapability(caps: unknown): boolean {
  if (!caps || typeof caps !== 'object' || Array.isArray(caps)) return false;
  const e = (caps as Record<string, unknown>).elicitation;
  if (e == null || e === false) return false;
  return typeof e === 'object' || e === true;
}

function asRecord(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

/**
 * Inspect a clone of the inbound body; never consume the real request stream.
 * Handles single JSON-RPC messages and batches. Returns the captured record.
 */
export async function captureInitialize(
  request: Request,
  env: EnvLike,
  oauthSub: string | undefined | null,
): Promise<ClientCapsRecord | null> {
  if (!oauthSub) return null;
  const contentType = (request.headers.get('content-type') || '').toLowerCase();
  if (!contentType.includes('application/json')) return null;
  let text: string;
  try {
    text = await request.clone().text();
  } catch {
    return null;
  }
  if (!text || text.length > 256 * 1024) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  const messages = Array.isArray(parsed) ? parsed : [parsed];
  for (const msg of messages) {
    const m = asRecord(msg);
    if (m.method !== 'initialize') continue;
    const params = asRecord(m.params);
    const caps = asRecord(params.capabilities);
    const clientInfo = asRecord(params.clientInfo);
    const rec: ClientCapsRecord = {
      oauth_sub: oauthSub,
      observed_at: Date.now(),
      protocol_version: typeof params.protocolVersion === 'string' ? params.protocolVersion : undefined,
      client_name: typeof clientInfo.name === 'string' ? clientInfo.name : undefined,
      client_version: typeof clientInfo.version === 'string' ? clientInfo.version : undefined,
      capabilities: caps,
      has_elicitation: hasElicitationCapability(caps),
      source: 'mcp_initialize',
    };
    await env.OAUTH_KV.put(latestKey(oauthSub), JSON.stringify(rec), {
      expirationTtl: CAPS_TTL_SEC,
    });
    let history: ClientCapsRecord[] = [];
    try {
      const raw = await env.OAUTH_KV.get(historyKey(oauthSub));
      const parsedHist = raw ? JSON.parse(raw) : [];
      if (Array.isArray(parsedHist)) history = parsedHist as ClientCapsRecord[];
    } catch {
      history = [];
    }
    history.unshift(rec);
    await env.OAUTH_KV.put(historyKey(oauthSub), JSON.stringify(history.slice(0, HISTORY_MAX)), {
      expirationTtl: CAPS_TTL_SEC,
    });
    return rec;
  }
  return null;
}

export async function getClientCaps(
  env: EnvLike,
  oauthSub: string | undefined | null,
): Promise<ClientCapsRecord | null> {
  if (!oauthSub) return null;
  const raw = await env.OAUTH_KV.get(latestKey(oauthSub));
  if (!raw) return null;
  try {
    const rec = JSON.parse(raw) as ClientCapsRecord;
    return rec && typeof rec === 'object' ? rec : null;
  } catch {
    return null;
  }
}

/** Public, non-sensitive receipt hint (no client name / raw caps). */
export function elicitProbeFix(rec: ClientCapsRecord | null): Record<string, string> {
  if (!rec) return { client_elicit: 'unobserved' };
  return { client_elicit: rec.has_elicitation ? 'yes' : 'no' };
}
