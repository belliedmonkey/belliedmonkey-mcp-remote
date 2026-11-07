/**
 * BEL-213 preview · D1-backed subset of the KV API used by
 * `@cloudflare/workers-oauth-provider@1.2.4`.
 *
 * The provider hard-codes `env.OAUTH_KV` and has no storage adapter. Rather than
 * forking it, we wrap the binding in a thin facade: OAuth state (token/grant/
 * client/transaction/two JTI namespaces) goes to D1 (`OAUTH_DB`), while every
 * other key (pending_confirm, device_session, client caps) stays on the real KV.
 *
 * If `OAUTH_DB` is not bound the caller keeps the original KV unchanged, so the
 * production default environment is byte-for-byte the old storage path.
 */

/** Key prefixes owned by the OAuth provider's durable state. */
export const D1_KEY_PREFIXES = [
  'token:',
  'grant:',
  'client:',
  'transaction:',
  'enterprise-jti:',
  'client-assertion-jti:',
] as const;

const HEX64 = /^[0-9a-f]{64}$/i;
const KV_MIN_TTL_SECONDS = 60;
const KV_MAX_LIST_LIMIT = 1000;
const KV_DEFAULT_LIST_LIMIT = 1000;

/** A bare 64-char hex key is the legacy, prefix-less JTI marker. */
export function isD1Key(key: string): boolean {
  if (D1_KEY_PREFIXES.some((prefix) => key.startsWith(prefix))) return true;
  return !key.includes(':') && HEX64.test(key);
}

/**
 * Route a `list()` call by its prefix. Anything that can only name D1-owned
 * keys goes to D1; an empty prefix is deliberately left on KV so this slice
 * never scans the whole D1 table.
 */
function isD1ListPrefix(prefix: string): boolean {
  if (!prefix) return false;
  return D1_KEY_PREFIXES.some(
    (known) => known.startsWith(prefix) || prefix.startsWith(known),
  );
}

/** Exclusive upper bound for a key prefix. OAuth prefixes are ASCII. */
function prefixUpperBound(prefix: string): string {
  const last = prefix.charCodeAt(prefix.length - 1);
  return prefix.slice(0, -1) + String.fromCharCode(last + 1);
}

type KvPutOptions = {
  expiration?: number;
  expirationTtl?: number;
  metadata?: unknown;
};

type FacadeGetOptions = { type?: 'text' | 'json' | 'arrayBuffer' };

function expiresAtFor(
  options: KvPutOptions | undefined,
  nowSeconds: number,
): number | null {
  if (options?.expiration !== undefined && options.expiration !== null) {
    const requested = Math.floor(Number(options.expiration));
    if (Number.isFinite(requested)) {
      // KV rejects writes whose absolute expiry is less than 60s out. Clamp so
      // a provider write with a near expiry behaves like KV instead of failing.
      return Math.max(requested, nowSeconds + KV_MIN_TTL_SECONDS);
    }
  }
  if (
    options?.expirationTtl !== undefined &&
    options.expirationTtl !== null
  ) {
    const ttl = Math.floor(Number(options.expirationTtl));
    if (Number.isFinite(ttl)) {
      return nowSeconds + Math.max(KV_MIN_TTL_SECONDS, ttl);
    }
  }
  return null;
}

function metadataForDb(metadata: unknown): string | null {
  if (metadata === undefined) return null;
  return JSON.stringify(metadata);
}

async function valueToString(
  value: string | ArrayBuffer | ArrayBufferView | ReadableStream,
): Promise<string> {
  if (typeof value === 'string') return value;
  if (value instanceof ArrayBuffer) return new TextDecoder().decode(value);
  if (ArrayBuffer.isView(value)) {
    const view = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    return new TextDecoder().decode(view);
  }
  if (value instanceof ReadableStream) return new Response(value).text();
  return String(value);
}

function encodeCursor(key: string): string {
  const bytes = new TextEncoder().encode(key);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeCursor(cursor: string): string {
  const padded = cursor.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const bytes = Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

type DbRow = { k: string; v?: string; metadata?: string | null; expires_at?: number | null };

/**
 * Facade implementing the subset of `KVNamespace` that the OAuth provider uses:
 * get (text/json/arrayBuffer), put (with expirationTtl/expiration/metadata),
 * delete and list (prefix/cursor/limit with key metadata).
 *
 * Expiry is enforced at read time (`expires_at <= now` is absent), matching the
 * KV TTL semantics the provider relies on. No cron is required.
 */
export class OAuthKvD1Facade {
  constructor(
    private readonly db: D1Database,
    private readonly kv: KVNamespace,
  ) {}

  async get(
    key: string,
    options?: FacadeGetOptions,
  ): Promise<string | ArrayBuffer | null | unknown> {
    if (!isD1Key(key)) {
      return this.kv.get(key, options as never) as Promise<unknown>;
    }
    const row = await this.db
      .prepare(
        'SELECT v FROM oauth_kv WHERE k = ? AND (expires_at IS NULL OR expires_at > unixepoch())',
      )
      .bind(key)
      .first<DbRow>();
    if (!row || row.v === undefined) return null;
    if (options?.type === 'json') return JSON.parse(row.v);
    if (options?.type === 'arrayBuffer') {
      return new TextEncoder().encode(row.v).buffer;
    }
    return row.v;
  }

  async put(
    key: string,
    value: string | ArrayBuffer | ArrayBufferView | ReadableStream,
    options?: KvPutOptions,
  ): Promise<void> {
    if (!isD1Key(key)) {
      await this.kv.put(key, value as never, options as never);
      return;
    }
    const text = await valueToString(value);
    const now = Math.floor(Date.now() / 1000);
    await this.db
      .prepare(
        `INSERT INTO oauth_kv (k, v, metadata, expires_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(k) DO UPDATE SET
           v = excluded.v,
           metadata = excluded.metadata,
           expires_at = excluded.expires_at`,
      )
      .bind(key, text, metadataForDb(options?.metadata), expiresAtFor(options, now))
      .run();
  }

  async delete(key: string): Promise<void> {
    if (!isD1Key(key)) {
      await this.kv.delete(key);
      return;
    }
    await this.db.prepare('DELETE FROM oauth_kv WHERE k = ?').bind(key).run();
  }

  async list(options?: {
    prefix?: string;
    cursor?: string;
    limit?: number;
  }): Promise<{
    keys: Array<{ name: string; metadata?: unknown; expiration?: number }>;
    list_complete: boolean;
    cursor?: string;
  }> {
    const prefix = options?.prefix ?? '';
    if (!isD1ListPrefix(prefix)) {
      return this.kv.list(options as never) as unknown as Promise<{
        keys: Array<{ name: string; metadata?: unknown; expiration?: number }>;
        list_complete: boolean;
        cursor?: string;
      }>;
    }

    const requestedLimit = Math.floor(Number(options?.limit ?? KV_DEFAULT_LIST_LIMIT));
    const limit = Math.min(
      KV_MAX_LIST_LIMIT,
      Math.max(1, Number.isFinite(requestedLimit) ? requestedLimit : KV_DEFAULT_LIST_LIMIT),
    );
    const upper = prefixUpperBound(prefix);
    const cursorKey = options?.cursor ? decodeCursor(options.cursor) : null;

    const sql =
      'SELECT k, metadata, expires_at FROM oauth_kv ' +
      'WHERE k >= ? AND k < ? AND (expires_at IS NULL OR expires_at > unixepoch())' +
      (cursorKey ? ' AND k > ?' : '') +
      ' ORDER BY k LIMIT ?';
    const binds = cursorKey
      ? [prefix, upper, cursorKey, limit + 1]
      : [prefix, upper, limit + 1];
    const result = await this.db.prepare(sql).bind(...binds).all<DbRow>();
    const rows = result.results ?? [];
    const page = rows.slice(0, limit);
    const keys = page.map((row) => {
      const item: { name: string; metadata?: unknown; expiration?: number } = {
        name: row.k,
      };
      if (row.metadata !== null && row.metadata !== undefined) {
        try {
          item.metadata = JSON.parse(row.metadata);
        } catch {
          /* malformed metadata is ignored, like KV */
        }
      }
      if (row.expires_at !== null && row.expires_at !== undefined) {
        item.expiration = row.expires_at;
      }
      return item;
    });

    const list_complete = rows.length <= limit;
    if (list_complete) return { keys, list_complete: true };
    return {
      keys,
      list_complete: false,
      cursor: encodeCursor(keys[keys.length - 1].name),
    };
  }
}

const FACADE_MARK = Symbol.for('bel213.oauthKvD1');

type EnvWithOauthDb = {
  OAUTH_KV: KVNamespace;
  OAUTH_DB?: D1Database;
};

/**
 * If `OAUTH_DB` is bound, return a copy of `env` whose `OAUTH_KV` is the D1
 * facade (falling back to the raw KV for non-OAuth keys). Otherwise return the
 * original env untouched — the production default path.
 */
export function withOAuthKvD1<T extends EnvWithOauthDb>(env: T): T {
  if (!env.OAUTH_DB) return env;
  const current = env.OAUTH_KV as unknown as Record<PropertyKey, unknown>;
  if (current && current[FACADE_MARK]) return env;

  const facade = new OAuthKvD1Facade(
    env.OAUTH_DB,
    env.OAUTH_KV,
  ) as unknown as KVNamespace;
  (facade as unknown as Record<PropertyKey, unknown>)[FACADE_MARK] = true;
  return { ...env, OAUTH_KV: facade };
}
