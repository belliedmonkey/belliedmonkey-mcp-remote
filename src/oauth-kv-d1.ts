/**
 * BEL-213 · D1-backed replacement for the KV API used by
 * `@cloudflare/workers-oauth-provider@1.2.4`.
 *
 * The provider hard-codes `env.OAUTH_KV` and has no storage adapter. Rather than
 * forking it, we wrap the binding in a thin facade. With `OAUTH_DB` bound,
 * **every** key goes to D1 (`OAUTH_DB`): the OAuth provider's token/grant/
 * client/transaction/JTI state and this Worker's own pending_confirm,
 * device_session and mcp_client_caps keys (including `_owner`, `_idx` and
 * `_history` companions).
 *
 * There is deliberately no prefix routing: `isD1Key` / `isD1ListPrefix` are
 * always true, and an empty `list()` prefix scans D1 too. If `OAUTH_DB` is not
 * bound, `withOAuthKvD1` returns the original env untouched, so the rollback
 * path is byte-for-byte the old KV storage path.
 */

const KV_MIN_TTL_SECONDS = 60;
const KV_MAX_LIST_LIMIT = 1000;
const KV_DEFAULT_LIST_LIMIT = 1000;

/** All keys are D1-owned whenever the facade is installed. */
export function isD1Key(_key: string): boolean {
  return true;
}

/** All list prefixes (including the empty prefix) are D1-owned. */
function isD1ListPrefix(_prefix: string): boolean {
  return true;
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
 * Facade implementing the `KVNamespace` surface this Worker uses: get
 * (text/json/arrayBuffer), put (with expirationTtl/expiration/metadata),
 * delete and list (prefix/cursor/limit with key metadata). Every key is stored
 * in D1; there is no KV fallback inside the facade.
 *
 * Expiry is enforced at read time (`expires_at <= now` is absent), matching the
 * KV TTL semantics the provider relies on. No cron is required.
 */
export class OAuthKvD1Facade {
  constructor(private readonly db: D1Database) {}

  async get(
    key: string,
    options?: FacadeGetOptions,
  ): Promise<string | ArrayBuffer | null | unknown> {
    // isD1Key is always true here: the facade only exists when OAUTH_DB is bound.
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
    // isD1Key is always true here: the facade only exists when OAUTH_DB is bound.
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
    // isD1Key is always true here: the facade only exists when OAUTH_DB is bound.
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
    // isD1ListPrefix (including the empty prefix) is always true here.
    const requestedLimit = Math.floor(Number(options?.limit ?? KV_DEFAULT_LIST_LIMIT));
    const limit = Math.min(
      KV_MAX_LIST_LIMIT,
      Math.max(1, Number.isFinite(requestedLimit) ? requestedLimit : KV_DEFAULT_LIST_LIMIT),
    );
    const upper = prefix ? prefixUpperBound(prefix) : null;
    const cursorKey = options?.cursor ? decodeCursor(options.cursor) : null;

    const where: string[] = ['k >= ?'];
    const binds: Array<string | number> = [prefix];
    if (upper !== null) {
      where.push('k < ?');
      binds.push(upper);
    }
    where.push('(expires_at IS NULL OR expires_at > unixepoch())');
    if (cursorKey) {
      where.push('k > ?');
      binds.push(cursorKey);
    }
    binds.push(limit + 1);

    const sql =
      'SELECT k, metadata, expires_at FROM oauth_kv WHERE ' +
      where.join(' AND ') +
      ' ORDER BY k LIMIT ?';
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
 * facade: every OAuth / pending / device / caps key is read and written in D1.
 * Otherwise return the original env untouched — the 100% KV rollback path.
 */
export function withOAuthKvD1<T extends EnvWithOauthDb>(env: T): T {
  if (!env.OAUTH_DB) return env;
  const current = env.OAUTH_KV as unknown as Record<PropertyKey, unknown>;
  if (current && current[FACADE_MARK]) return env;

  const facade = new OAuthKvD1Facade(env.OAUTH_DB) as unknown as KVNamespace;
  (facade as unknown as Record<PropertyKey, unknown>)[FACADE_MARK] = true;
  return { ...env, OAUTH_KV: facade };
}
