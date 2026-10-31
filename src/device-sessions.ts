/**
 * BEL-151 device bridge · device_sessions KV + HTTP API
 * ACCEPT-D1…D5 · App contract: /api/mcp/device-sessions/{register,heartbeat,bootstrap,revoke}
 * Ban: claim listen-translate ready; Win/Android/Linux never UP.
 */
import type { OAuthHelpers } from '@cloudflare/workers-oauth-provider';

export const DEVICE_TTL_PAIR_SEC = 900; // 15 min
export const DEVICE_TTL_BOOTSTRAP_SEC = 300; // 5 min
export const DEVICE_TTL_DOWN_SEC = 900; // no heartbeat → DOWN

export type DevicePlatform = 'mac' | 'ios';
export type DeviceKind = 'pair' | 'bootstrap';

export type DeviceSessionRecord = {
  oauth_sub: string;
  device_id: string;
  platform: DevicePlatform;
  kind: DeviceKind;
  last_seen: number; // epoch ms
  expires_at: number; // epoch ms
  device_cred_hash: string;
  app_version?: string;
};

export type BridgeView = {
  up: boolean;
  device_id?: string;
  platform?: DevicePlatform;
  last_seen?: number;
  kind?: DeviceKind;
};

type EnvLike = {
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: OAuthHelpers;
  MCP_RESOURCE_URL: string;
  ISSUER: string;
};

const ALLOWED_PLATFORMS = new Set<string>(['mac', 'ios']);

function kvKey(sub: string, deviceId: string): string {
  return `device_session:${sub}:${deviceId}`;
}

function idxKey(sub: string): string {
  return `device_sessions_idx:${sub}`;
}

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function newCred(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return `dc_${out}`;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

async function readIdx(env: EnvLike, sub: string): Promise<string[]> {
  const raw = await env.OAUTH_KV.get(idxKey(sub));
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((x) => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

async function writeIdx(env: EnvLike, sub: string, ids: string[]): Promise<void> {
  const uniq = [...new Set(ids)];
  await env.OAUTH_KV.put(idxKey(sub), JSON.stringify(uniq));
}

async function putSession(
  env: EnvLike,
  rec: DeviceSessionRecord,
  ttlSec: number,
): Promise<void> {
  await env.OAUTH_KV.put(kvKey(rec.oauth_sub, rec.device_id), JSON.stringify(rec), {
    expirationTtl: Math.max(60, ttlSec + 60),
  });
  const ids = await readIdx(env, rec.oauth_sub);
  if (!ids.includes(rec.device_id)) {
    ids.push(rec.device_id);
    await writeIdx(env, rec.oauth_sub, ids);
  }
}

async function getSession(
  env: EnvLike,
  sub: string,
  deviceId: string,
): Promise<DeviceSessionRecord | null> {
  const raw = await env.OAUTH_KV.get(kvKey(sub, deviceId));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as DeviceSessionRecord;
  } catch {
    return null;
  }
}

async function deleteSession(env: EnvLike, sub: string, deviceId: string): Promise<void> {
  await env.OAUTH_KV.delete(kvKey(sub, deviceId));
  const ids = (await readIdx(env, sub)).filter((id) => id !== deviceId);
  await writeIdx(env, sub, ids);
}

/** Newest non-expired session for sub; platform win/android/linux never stored as UP. */
export async function getFreshBridge(
  env: EnvLike,
  oauthSub: string | undefined | null,
  now = Date.now(),
): Promise<BridgeView> {
  if (!oauthSub) return { up: false };
  const ids = await readIdx(env, oauthSub);
  let best: DeviceSessionRecord | null = null;
  for (const id of ids) {
    const rec = await getSession(env, oauthSub, id);
    if (!rec) continue;
    if (!ALLOWED_PLATFORMS.has(rec.platform)) continue;
    if (rec.expires_at <= now) continue;
    if (!best || rec.last_seen > best.last_seen) best = rec;
  }
  if (!best) return { up: false };
  return {
    up: true,
    device_id: best.device_id,
    platform: best.platform,
    last_seen: best.last_seen,
    kind: best.kind,
  };
}

type TokenProps = { userId?: string; email?: string; flavor?: string; name?: string };

async function authSub(
  request: Request,
  env: EnvLike,
): Promise<{ sub: string; props: TokenProps } | Response> {
  const h = request.headers.get('Authorization') || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  if (!m) return json(401, { ok: false, error: 'unauthorized', message: 'missing bearer' });
  const token = m[1].trim();
  const summary = await env.OAUTH_PROVIDER.unwrapToken<TokenProps>(token);
  if (!summary || !summary.userId) {
    return json(401, { ok: false, error: 'unauthorized', message: 'invalid_token' });
  }
  const props = ((summary.grant && summary.grant.props) || {}) as TokenProps;
  // Prefer props.userId (Supabase UUID) — same sub tools.ts reads from MCP auth context
  const sub = props.userId || summary.userId;
  if (!sub) return json(401, { ok: false, error: 'unauthorized', message: 'no_sub' });
  return { sub, props };
}

async function readBody(request: Request): Promise<Record<string, unknown>> {
  try {
    const j = await request.json();
    return j && typeof j === 'object' ? (j as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

export async function handleDeviceSessions(
  request: Request,
  env: EnvLike,
): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '') || '/';
  if (request.method !== 'POST') {
    return json(405, { ok: false, error: 'method_not_allowed' });
  }

  const auth = await authSub(request, env);
  if (auth instanceof Response) return auth;
  const { sub } = auth;
  const body = await readBody(request);
  const now = Date.now();

  if (path.endsWith('/register')) {
    const device_id = String(body.device_id || '');
    const platform = String(body.platform || '');
    const app_version = body.app_version != null ? String(body.app_version) : undefined;
    const confirm = body.confirm === true;
    if (!device_id || !platform) {
      return json(400, { ok: false, error: 'bad_request', message: 'device_id and platform required' });
    }
    if (!confirm) {
      return json(400, { ok: false, error: 'bad_request', message: 'confirm:true required' });
    }
    if (!ALLOWED_PLATFORMS.has(platform)) {
      // Win/Android/Linux never UP
      return json(400, {
        ok: false,
        error: 'unsupported_platform',
        message: 'only mac (P0) / ios (reserved) accepted',
      });
    }
    const device_cred = newCred();
    const ttl = DEVICE_TTL_PAIR_SEC;
    const rec: DeviceSessionRecord = {
      oauth_sub: sub,
      device_id,
      platform: platform as DevicePlatform,
      kind: 'pair',
      last_seen: now,
      expires_at: now + ttl * 1000,
      device_cred_hash: await sha256Hex(device_cred),
      app_version,
    };
    await putSession(env, rec, ttl);
    return json(200, { ok: true, device_cred, ttl_sec: ttl });
  }

  if (path.endsWith('/heartbeat')) {
    const device_id = String(body.device_id || '');
    const device_cred = String(body.device_cred || '');
    if (!device_id || !device_cred) {
      return json(400, { ok: false, error: 'bad_request', message: 'device_id and device_cred required' });
    }
    const rec = await getSession(env, sub, device_id);
    if (!rec) return json(401, { ok: false, error: 'unauthorized', message: 'no_session' });
    if (rec.oauth_sub !== sub) {
      return json(403, { ok: false, error: 'forbidden', message: 'cross_account' });
    }
    const hash = await sha256Hex(device_cred);
    if (hash !== rec.device_cred_hash) {
      return json(401, { ok: false, error: 'unauthorized', message: 'bad_cred' });
    }
    const ttl = DEVICE_TTL_PAIR_SEC;
    rec.last_seen = now;
    rec.expires_at = now + ttl * 1000;
    // heartbeats promote bootstrap → pair reachability window only; kind stays unless already pair
    if (rec.kind !== 'pair') rec.kind = 'pair';
    await putSession(env, rec, ttl);
    return json(200, { ok: true, ttl_sec: ttl, last_seen: rec.last_seen });
  }

  if (path.endsWith('/bootstrap')) {
    const device_id = String(body.device_id || '');
    const platform = String(body.platform || 'mac');
    const ttlReq = Number(body.ttl_sec);
    const ttl = Number.isFinite(ttlReq) && ttlReq > 0
      ? Math.min(Math.floor(ttlReq), DEVICE_TTL_BOOTSTRAP_SEC)
      : DEVICE_TTL_BOOTSTRAP_SEC;
    if (!device_id) {
      return json(400, { ok: false, error: 'bad_request', message: 'device_id required' });
    }
    if (!ALLOWED_PLATFORMS.has(platform)) {
      return json(400, {
        ok: false,
        error: 'unsupported_platform',
        message: 'only mac / ios accepted',
      });
    }
    const device_cred = newCred();
    const rec: DeviceSessionRecord = {
      oauth_sub: sub,
      device_id,
      platform: platform as DevicePlatform,
      kind: 'bootstrap',
      last_seen: now,
      expires_at: now + ttl * 1000,
      device_cred_hash: await sha256Hex(device_cred),
    };
    await putSession(env, rec, ttl);
    return json(200, { ok: true, device_cred, ttl_sec: ttl, kind: 'bootstrap' });
  }

  if (path.endsWith('/revoke')) {
    const device_id = String(body.device_id || '');
    const device_cred = String(body.device_cred || '');
    if (!device_id) {
      return json(400, { ok: false, error: 'bad_request', message: 'device_id required' });
    }
    const rec = await getSession(env, sub, device_id);
    if (rec) {
      if (rec.oauth_sub !== sub) {
        return json(403, { ok: false, error: 'forbidden', message: 'cross_account' });
      }
      if (device_cred) {
        const hash = await sha256Hex(device_cred);
        if (hash !== rec.device_cred_hash) {
          return json(401, { ok: false, error: 'unauthorized', message: 'bad_cred' });
        }
      }
      await deleteSession(env, sub, device_id);
    }
    // idempotent ok even if missing
    return json(200, { ok: true, revoked: true });
  }

  return json(404, { ok: false, error: 'not_found' });
}

export function isDeviceSessionsPath(pathname: string): boolean {
  const p = pathname.replace(/\/+$/, '');
  return (
    p === '/api/mcp/device-sessions/register' ||
    p === '/api/mcp/device-sessions/heartbeat' ||
    p === '/api/mcp/device-sessions/bootstrap' ||
    p === '/api/mcp/device-sessions/revoke'
  );
}
