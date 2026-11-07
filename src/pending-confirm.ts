/**
 * BEL-151 GAP-2 · pending_confirm store (B path, P0)
 *
 * Bridge UP sensitive call -> create short-lived pending (120s) -> honest
 * need_confirm + action deep link with pending_id -> App POST /confirm with
 * device_cred -> allow resumes the same call (openedSubtitles semantics,
 * micStarted:false) / deny -> cancelled. Expiry / revoke never fake success.
 *
 * Storage: existing OAUTH_KV (no new binding). Records auto-expire in KV and
 * are lazily marked expired/revoked for honest status replies.
 */
import { receipt, type Receipt } from './receipt';

export const PENDING_TTL_SEC = 120;
/** Keep terminal/expired records briefly so status/confirm is explainable. */
export const PENDING_KV_GRACE_SEC = 300;
const IDX_TTL_SEC = 3600;

export type PendingStatus = 'pending' | 'allowed' | 'denied' | 'expired' | 'revoked';
export type PendingDecision = 'allow' | 'deny';

export type PendingRecord = {
  pending_id: string;
  action: string;
  args_hash: string;
  oauth_sub: string;
  device_id: string;
  created_at: number;
  expires_at: number;
  status: PendingStatus;
  decision?: PendingDecision;
  decided_at?: number;
  result?: Receipt;
};

type EnvLike = { OAUTH_KV: KVNamespace };

function pendingKey(sub: string, id: string): string {
  return `pending_confirm:${sub}:${id}`;
}

function ownerKey(id: string): string {
  return `pending_confirm_owner:${id}`;
}

function idxKey(sub: string): string {
  return `pending_confirm_idx:${sub}`;
}

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Stable JSON: sorted object keys, arrays preserved. Never store raw args. */
export function canonicalArgs(value: unknown): string {
  const walk = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(v as Record<string, unknown>).sort()) {
        out[k] = walk((v as Record<string, unknown>)[k]);
      }
      return out;
    }
    return v;
  };
  return JSON.stringify(walk(value ?? {}));
}

/** Hash of normalized args, excluding the replay handle itself. */
export async function argsHash(args: Record<string, unknown>): Promise<string> {
  const copy: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args || {})) {
    if (k === 'pending_id' || k === 'wait_sec') continue;
    copy[k] = v;
  }
  return sha256Hex(canonicalArgs(copy));
}

export function newPendingId(): string {
  return crypto.randomUUID();
}

async function readIdx(env: EnvLike, sub: string): Promise<string[]> {
  const raw = await env.OAUTH_KV.get(idxKey(sub));
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

async function writeIdx(env: EnvLike, sub: string, ids: string[]): Promise<void> {
  await env.OAUTH_KV.put(idxKey(sub), JSON.stringify([...new Set(ids)]), {
    expirationTtl: IDX_TTL_SEC,
  });
}

async function storePending(env: EnvLike, rec: PendingRecord, now: number): Promise<void> {
  const remaining = Math.max(60, Math.ceil((rec.expires_at - now) / 1000) + PENDING_KV_GRACE_SEC);
  await env.OAUTH_KV.put(pendingKey(rec.oauth_sub, rec.pending_id), JSON.stringify(rec), {
    expirationTtl: remaining,
  });
  await env.OAUTH_KV.put(ownerKey(rec.pending_id), rec.oauth_sub, {
    expirationTtl: remaining,
  });
}

/** Lazy expiry: a pending past expires_at becomes expired for honest replies. */
async function loadPending(
  env: EnvLike,
  sub: string,
  id: string,
  now: number,
): Promise<PendingRecord | null> {
  const raw = await env.OAUTH_KV.get(pendingKey(sub, id));
  if (!raw) return null;
  let rec: PendingRecord;
  try {
    rec = JSON.parse(raw) as PendingRecord;
  } catch {
    return null;
  }
  if (rec.status === 'pending' && now >= rec.expires_at) {
    rec.status = 'expired';
    await storePending(env, rec, now);
  }
  return rec;
}

export async function getPending(
  env: EnvLike,
  sub: string,
  id: string,
  now = Date.now(),
): Promise<PendingRecord | null> {
  if (!sub || !id) return null;
  return loadPending(env, sub, id, now);
}

/**
 * B-PUSH (BEL-151): the only public view of a pending that leaves the Worker.
 * It is scoped to one oauth_sub + device_id and carries no args, hashes, text or
 * translation — just enough for the paired App to render one card.
 */
export type PendingSummary = {
  pending_id: string;
  action: string;
  expires_at: number;
  expires_in_sec: number;
};

/**
 * List this device's still-pending confirms, oldest first. Reads the existing
 * `pending_confirm_idx:<sub>` and filters by both oauth_sub and device_id, so a
 * cross-account or cross-device row can never leak into a heartbeat. A record
 * past its TTL is turned into `expired` by loadPending and therefore omitted.
 */
export async function listPendingForDevice(
  env: EnvLike,
  sub: string,
  deviceId: string,
  now = Date.now(),
): Promise<PendingSummary[]> {
  if (!sub || !deviceId) return [];
  const ids = await readIdx(env, sub);
  if (ids.length === 0) return [];
  const rows: Array<{ created_at: number; summary: PendingSummary }> = [];
  for (const id of ids) {
    const rec = await loadPending(env, sub, id, now);
    if (!rec) continue;
    if (rec.status !== 'pending') continue;
    if (rec.oauth_sub !== sub) continue;
    if (rec.device_id !== deviceId) continue;
    if (rec.expires_at <= now) continue;
    rows.push({
      created_at: rec.created_at,
      summary: {
        pending_id: rec.pending_id,
        action: rec.action,
        expires_at: rec.expires_at,
        expires_in_sec: Math.max(0, Math.ceil((rec.expires_at - now) / 1000)),
      },
    });
  }
  // FIFO: the App shows one card at a time; the Cloud decides which one is next.
  rows.sort((a, b) => a.created_at - b.created_at);
  return rows.map((row) => row.summary);
}

async function ownerOf(env: EnvLike, id: string): Promise<string | null> {
  return env.OAUTH_KV.get(ownerKey(id));
}

export async function createPending(
  env: EnvLike,
  opts: {
    oauth_sub: string;
    device_id: string;
    action: string;
    args: Record<string, unknown>;
    now?: number;
  },
): Promise<PendingRecord> {
  const now = opts.now ?? Date.now();
  await gcPending(env, opts.oauth_sub, now);
  const rec: PendingRecord = {
    pending_id: newPendingId(),
    action: opts.action,
    args_hash: await argsHash(opts.args),
    oauth_sub: opts.oauth_sub,
    device_id: opts.device_id,
    created_at: now,
    expires_at: now + PENDING_TTL_SEC * 1000,
    status: 'pending',
  };
  await storePending(env, rec, now);
  const ids = await readIdx(env, opts.oauth_sub);
  ids.push(rec.pending_id);
  await writeIdx(env, opts.oauth_sub, ids);
  return rec;
}

function resumeMessage(action: string, allowed: boolean): string {
  if (!allowed) return '已取消：未执行任何动作，也未开麦。';
  if (action === 'start_live_subtitles') {
    return '已在本机确认：只打开实时字幕表面（未开麦）。';
  }
  return '已在本机确认；具体执行由本机 App 完成，云端不代执行。';
}

/** Build the resumed receipt for a decided pending (same action, same id). */
export function buildResumeReceipt(rec: PendingRecord): Receipt {
  const allowed = rec.status === 'allowed';
  const fix: Record<string, string | number | boolean> = {
    pending_id: rec.pending_id,
    micStarted: false,
    openedSubtitles: rec.action === 'start_live_subtitles' ? allowed : false,
  };
  return receipt(rec.action, allowed ? 'ok' : 'cancelled', resumeMessage(rec.action, allowed), fix);
}

export type DecideError =
  | 'pending_not_found'
  | 'cross_account'
  | 'cross_device'
  | 'pending_expired'
  | 'pending_revoked'
  | 'already_decided';

export type DecideOutcome =
  | { ok: true; record: PendingRecord }
  | { ok: false; error: DecideError };

/**
 * Apply allow/deny. Idempotent for the same decision; a conflicting second
 * decision is refused (409 at HTTP layer). No side effect before this call.
 */
export async function decidePending(
  env: EnvLike,
  opts: {
    oauth_sub: string;
    pending_id: string;
    device_id: string;
    decision: PendingDecision;
    /** A: store a confirmation-only receipt (never openedSubtitles). */
    confirmOnly?: boolean;
    now?: number;
  },
): Promise<DecideOutcome> {
  const now = opts.now ?? Date.now();
  const owner = await ownerOf(env, opts.pending_id);
  if (owner && owner !== opts.oauth_sub) return { ok: false, error: 'cross_account' };
  const rec = await loadPending(env, opts.oauth_sub, opts.pending_id, now);
  if (!rec) return { ok: false, error: 'pending_not_found' };
  if (rec.oauth_sub !== opts.oauth_sub) return { ok: false, error: 'cross_account' };
  if (rec.device_id !== opts.device_id) return { ok: false, error: 'cross_device' };
  if (rec.status === 'expired') return { ok: false, error: 'pending_expired' };
  if (rec.status === 'revoked') return { ok: false, error: 'pending_revoked' };
  if (rec.status === 'allowed' || rec.status === 'denied') {
    const same = (rec.status === 'allowed') === (opts.decision === 'allow');
    return same ? { ok: true, record: rec } : { ok: false, error: 'already_decided' };
  }
  rec.status = opts.decision === 'allow' ? 'allowed' : 'denied';
  rec.decision = opts.decision;
  rec.decided_at = now;
  rec.result = opts.confirmOnly ? elicitConfirmReceipt(rec) : buildResumeReceipt(rec);
  await storePending(env, rec, now);
  return { ok: true, record: rec };
}

/**
 * A (elicitation) is a confirmation channel only in this slice: this receipt
 * never claims the local surface. Persisted atomically by decidePending with
 * `confirmOnly:true`, so a replay with the same pending_id stays honest.
 */
function elicitConfirmReceipt(rec: PendingRecord): Receipt {
  return receipt(
    rec.action,
    'ok',
    '已通过 MCP elicitation 确认；字幕表面仍须本机 App 执行（A 未证正路，未开麦）。',
    {
      pending_id: rec.pending_id,
      micStarted: false,
      openedSubtitles: false,
      elicit: 'accept',
    },
  );
}

/** Revoke every still-pending record for one device (revoke / bridge DOWN). */
export async function revokePendingForDevice(
  env: EnvLike,
  sub: string,
  deviceId: string,
  now = Date.now(),
): Promise<number> {
  const ids = await readIdx(env, sub);
  let n = 0;
  for (const id of ids) {
    const rec = await loadPending(env, sub, id, now);
    if (!rec) continue;
    if (rec.status === 'pending' && rec.device_id === deviceId) {
      rec.status = 'revoked';
      rec.decided_at = now;
      await storePending(env, rec, now);
      n += 1;
    }
  }
  return n;
}

/** Bridge DOWN: no target device can execute; revoke the sub's pending set. */
export async function revokeAllPending(
  env: EnvLike,
  sub: string,
  now = Date.now(),
): Promise<number> {
  const ids = await readIdx(env, sub);
  let n = 0;
  for (const id of ids) {
    const rec = await loadPending(env, sub, id, now);
    if (!rec) continue;
    if (rec.status === 'pending') {
      rec.status = 'revoked';
      rec.decided_at = now;
      await storePending(env, rec, now);
      n += 1;
    }
  }
  return n;
}

/**
 * Opportunistic GC: mark stale pending expired, drop index entries whose KV
 * record is gone or terminal for longer than the grace window.
 */
export async function gcPending(
  env: EnvLike,
  sub: string,
  now = Date.now(),
): Promise<{ expired: number; dropped: number }> {
  const ids = await readIdx(env, sub);
  if (ids.length === 0) return { expired: 0, dropped: 0 };
  const keep: string[] = [];
  let expired = 0;
  let dropped = 0;
  for (const id of ids) {
    const rec = await loadPending(env, sub, id, now);
    if (!rec) {
      dropped += 1;
      continue;
    }
    if (rec.status === 'pending') {
      keep.push(id);
      continue;
    }
    if (rec.status === 'expired') expired += 1;
    const ageMs = now - (rec.decided_at ?? rec.expires_at);
    if (ageMs > PENDING_KV_GRACE_SEC * 1000) {
      await env.OAUTH_KV.delete(pendingKey(sub, id));
      await env.OAUTH_KV.delete(ownerKey(id));
      dropped += 1;
      continue;
    }
    keep.push(id);
  }
  if (keep.length !== ids.length) await writeIdx(env, sub, keep);
  return { expired, dropped };
}
