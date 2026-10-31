/**
 * /authorize for Grok「连接应用」— BEL-151 A3 Supabase session.
 * Unauthenticated → login/signup against Supabase Auth.
 * Authenticated → consent; props.userId = Supabase user.id (UUID).
 * Arbitrary email pass-through is closed.
 */
import {
  AuthorizationError,
  CimdFetchError,
  type OAuthHelpers,
} from '@cloudflare/workers-oauth-provider';
import { flavorFromHost, type Flavor } from './receipt';

export type AuthorizeEnv = {
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
};

type SbUser = {
  id: string;
  email?: string | null;
  user_metadata?: { name?: string; full_name?: string };
};

const COOKIE = 'bm_sb_access';
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7d

function escapeHtml(s: string): string {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function page(title: string, body: string, extraHeaders?: HeadersInit): Response {
  const html = `<!doctype html>
<html lang="zh-CN">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
  body { max-width: 28rem; margin: 2.5rem auto; padding: 0 1rem; line-height: 1.45; }
  h1 { font-size: 1.25rem; }
  label { display: block; margin: 0.75rem 0 0.25rem; font-size: 0.9rem; }
  input[type=email], input[type=password] { width: 100%; padding: 0.55rem 0.65rem; font-size: 1rem; box-sizing: border-box; }
  .hint { display: block; color: #666; font-size: 0.8rem; margin: 0 0 0.35rem; line-height: 1.4; }
  .warn { background: #fff3cd; color: #664d03; padding: 0.6rem 0.75rem; border-radius: 6px; font-size: 0.9rem; }
  .err { background: #f8d7da; color: #842029; padding: 0.6rem 0.75rem; border-radius: 6px; font-size: 0.9rem; }
  .row { display: flex; gap: 0.5rem; margin-top: 1rem; flex-wrap: wrap; }
  button { padding: 0.55rem 1rem; font-size: 1rem; cursor: pointer; }
  .muted { color: #666; font-size: 0.85rem; }
  .account { background: #f0f4f8; color: #102a43; padding: 0.55rem 0.75rem; border-radius: 6px; font-size: 0.9rem; }
</style>
<body>
${body}
</body>
</html>`;
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      ...(extraHeaders || {}),
    },
  });
}

function parseCookie(req: Request, name: string): string | null {
  const raw = req.headers.get('Cookie') || '';
  for (const part of raw.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return decodeURIComponent(rest.join('=') || '');
  }
  return null;
}

function setSessionCookie(token: string): string {
  return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${COOKIE_MAX_AGE}`;
}

function clearSessionCookie(): string {
  return `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

/** Only bounce back to this Worker's own /authorize (no open redirect). */
function safeReturnTo(raw: string, origin: string): string {
  if (!raw) return '/authorize';
  try {
    const u = new URL(raw, origin);
    if (u.origin === origin && u.pathname === '/authorize') return u.toString();
  } catch {
    /* fall through */
  }
  return '/authorize';
}

async function sbFetch(
  env: AuthorizeEnv,
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const base = env.SUPABASE_URL.replace(/\/$/, '');
  const headers = new Headers(init.headers || {});
  headers.set('apikey', env.SUPABASE_ANON_KEY);
  if (!headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${env.SUPABASE_ANON_KEY}`);
  }
  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  return fetch(`${base}${path}`, { ...init, headers });
}

async function getUserFromToken(
  env: AuthorizeEnv,
  accessToken: string,
): Promise<SbUser | null> {
  if (!accessToken) return null;
  const res = await sbFetch(env, '/auth/v1/user', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) return null;
  const data = (await res.json()) as SbUser;
  if (!data?.id) return null;
  return data;
}

async function passwordGrant(
  env: AuthorizeEnv,
  email: string,
  password: string,
): Promise<{ access_token?: string; error?: string }> {
  const res = await sbFetch(env, '/auth/v1/token?grant_type=password', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  const data = (await res.json()) as {
    access_token?: string;
    error_description?: string;
    msg?: string;
    error?: string;
  };
  if (!res.ok || !data.access_token) {
    return {
      error:
        data.error_description ||
        data.msg ||
        data.error ||
        '登录失败，请检查邮箱和密码。',
    };
  }
  return { access_token: data.access_token };
}

async function signUp(
  env: AuthorizeEnv,
  email: string,
  password: string,
): Promise<{ access_token?: string; error?: string; needsConfirm?: boolean }> {
  const res = await sbFetch(env, '/auth/v1/signup', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  const data = (await res.json()) as {
    access_token?: string;
    user?: SbUser;
    error_description?: string;
    msg?: string;
    error?: string;
  };
  if (!res.ok) {
    return {
      error:
        data.error_description ||
        data.msg ||
        data.error ||
        '注册失败。',
    };
  }
  if (data.access_token) return { access_token: data.access_token };
  // Email confirm may be required — try password grant if auto-confirm
  const grant = await passwordGrant(env, email, password);
  if (grant.access_token) return grant;
  return {
    needsConfirm: true,
    error: '注册成功。若需邮箱确认，请查收邮件后再登录。',
  };
}

function displayName(user: SbUser): string {
  return (
    user.user_metadata?.name ||
    user.user_metadata?.full_name ||
    user.email ||
    user.id
  );
}

export async function handleAuthorize(
  request: Request,
  oauth: OAuthHelpers,
  env: AuthorizeEnv,
): Promise<Response> {
  const url = new URL(request.url);
  const flavor: Flavor = flavorFromHost(url.hostname, request.headers);

  if (!env.SUPABASE_URL || !env.SUPABASE_ANON_KEY) {
    return page(
      '授权配置错误',
      '<p class="err">服务未配置大肚猴账号体系。请稍后重试。</p>',
    );
  }

  try {
    const token = parseCookie(request, COOKIE);
    const sessionUser = token ? await getUserFromToken(env, token) : null;

    if (request.method === 'GET') {
      const authRequest = await oauth.parseAuthRequest(request);
      const details = await oauth.describeConsent(authRequest);
      const consent = await oauth.beginConsent(authRequest);
      const name = details.clientName || details.clientId || 'MCP client';
      const hostWarn = details.redirectIsLoopback
        ? `<p class="warn"><strong>访问将发往本机应用</strong>（${escapeHtml(details.redirectHost)}）。仅在你刚从该应用发起连接时继续。</p>`
        : `<p class="muted">回调主机：<strong>${escapeHtml(details.redirectHost)}</strong></p>`;
      const scopes = (details.scope || [])
        .map(
          (scope: string) =>
            `<label><input type="checkbox" name="scope" value="${escapeHtml(scope)}" checked> ${escapeHtml(scope)}</label>`,
        )
        .join('');

      const err = url.searchParams.get('err') || '';
      const errBlock = err
        ? `<p class="err">${escapeHtml(err)}</p>`
        : '';

      let body: string;
      if (sessionUser) {
        body = `
  <h1>连接大肚猴翻译</h1>
  <p>允许 <strong>${escapeHtml(name)}</strong> 代表你连接大肚猴翻译。云端只负责编排；开麦、读页、写学习库都在你的本机 App 或扩展里确认。</p>
  ${hostWarn}
  ${errBlock}
  <p class="account">将用你的大肚猴账号授权连接：<strong>${escapeHtml(sessionUser.email || sessionUser.id)}</strong></p>
  <form method="post" action="/authorize">
    <input type="hidden" name="handle" value="${escapeHtml(consent.handle)}">
    <input type="hidden" name="flavor" value="${escapeHtml(flavor)}">
    <input type="hidden" name="action" value="consent">
    <fieldset style="border:0;padding:0;margin:0.75rem 0 0">
      <legend class="muted">权限范围（用于连接工具；不扩大权限）</legend>
      ${scopes || '<p class="muted">mcp:read</p>'}
    </fieldset>
    <div class="row">
      <button name="decision" value="approve" type="submit">允许并连接</button>
      <button name="decision" value="deny" type="submit">拒绝</button>
    </div>
    <p class="muted">连接成功不代表听译已通。</p>
  </form>
  <form method="post" action="/authorize" style="margin-top:1rem">
    <input type="hidden" name="action" value="logout">
    <button type="submit">退出账号</button>
  </form>`;
      } else {
        // Preserve OAuth query for post-login return via consent handle only —
        // user must re-hit authorize from client after login if handle expires.
        // Store full request URL so login can bounce back.
        const returnTo = url.toString();
        body = `
  <h1>连接大肚猴翻译</h1>
  <p>允许 <strong>${escapeHtml(name)}</strong> 代表你连接大肚猴翻译。请先登录或注册大肚猴账号。</p>
  ${hostWarn}
  ${errBlock}
  <p class="hint" id="account-hint">将用你的大肚猴账号授权连接。</p>
  <form method="post" action="/authorize">
    <input type="hidden" name="handle" value="${escapeHtml(consent.handle)}">
    <input type="hidden" name="flavor" value="${escapeHtml(flavor)}">
    <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
    <label for="email">邮箱</label>
    <input id="email" name="email" type="email" required autocomplete="username" placeholder="you@example.com" aria-describedby="account-hint">
    <label for="password">密码</label>
    <input id="password" name="password" type="password" required autocomplete="current-password" minlength="6">
    <div class="row">
      <button name="action" value="login" type="submit">登录并继续</button>
      <button name="action" value="signup" type="submit">注册并继续</button>
      <button name="decision" value="deny" type="submit" formnovalidate>拒绝</button>
    </div>
    <p class="muted">连接成功不代表听译已通。</p>
  </form>`;
      }

      const res = page('授权 · 大肚猴翻译', body);
      const headers = new Headers(res.headers);
      consent.headers.forEach((v, k) => {
        if (k.toLowerCase() === 'set-cookie') headers.append(k, v);
        else if (!headers.has(k)) headers.set(k, v);
      });
      return new Response(res.body, { status: 200, headers });
    }

    if (request.method === 'POST') {
      const form = await request.formData();
      const action = String(form.get('action') || '');
      const decision = String(form.get('decision') || '');
      const handle = String(form.get('handle') || '');

      if (action === 'logout') {
        const headers = new Headers({
          Location: '/authorize',
          'Set-Cookie': clearSessionCookie(),
        });
        // Without OAuth params, landing is config-ish; clients re-enter from Grok.
        return new Response(null, { status: 302, headers });
      }

      if (decision === 'deny') {
        // BEL-151 consent-reject-landing: show COPY-LOCK interstitial, then finish OAuth deny redirect.
        const denied = await oauth.denyConsent(request, handle);
        const location =
          denied.headers.get('Location') ||
          denied.redirectTo ||
          '/';
        const safeLoc = escapeHtml(location);
        const locJs = JSON.stringify(location);
        const body = `
  <h1>已拒绝连接</h1>
  <p>已拒绝连接。可稍后再从「连接应用」重试。</p>
  <p><a href="${safeLoc}">返回连接应用</a></p>
  <meta http-equiv="refresh" content="2;url=${safeLoc}">
  <script>setTimeout(function () { location.replace(${locJs}); }, 2000);</script>`;
        const res = page('已拒绝连接', body);
        const headers = new Headers(res.headers);
        denied.headers.forEach((v, k) => {
          if (k.toLowerCase() === 'set-cookie') headers.append(k, v);
          else if (k.toLowerCase() === 'location') {
            /* keep HTML; client follows meta/script/link */
          } else if (!headers.has(k)) headers.set(k, v);
        });
        return new Response(res.body, { status: 200, headers });
      }

      if (action === 'login' || action === 'signup') {
        const email = String(form.get('email') || '')
          .trim()
          .toLowerCase();
        const password = String(form.get('password') || '');
        const returnTo = safeReturnTo(String(form.get('return_to') || ''), url.origin);
        if (!email || !email.includes('@') || password.length < 6) {
          const u = new URL(returnTo, url.origin);
          u.searchParams.set('err', '请填写有效邮箱和至少 6 位密码。');
          return Response.redirect(u.toString(), 302);
        }
        const result =
          action === 'signup'
            ? await signUp(env, email, password)
            : await passwordGrant(env, email, password);
        if (!result.access_token) {
          const u = new URL(returnTo, url.origin);
          u.searchParams.set('err', result.error || '认证失败');
          return Response.redirect(u.toString(), 302);
        }
        const headers = new Headers({
          Location: returnTo,
          'Set-Cookie': setSessionCookie(result.access_token),
        });
        // Re-merge consent cookies if any still on request
        return new Response(null, { status: 302, headers });
      }

      // Consent approve — require live Supabase session (no email form userId)
      if (decision === 'approve') {
        const access = parseCookie(request, COOKIE);
        const user = access ? await getUserFromToken(env, access) : null;
        if (!user?.id) {
          return page(
            '授权失败',
            '<p class="err">请先登录大肚猴账号后再允许连接。</p><p><a href="javascript:history.back()">返回</a></p>',
          );
        }
        const formFlavor = String(form.get('flavor') || flavor) as Flavor;
        const approved = await oauth.approveConsent(request, handle, {
          scope: form.getAll('scope').map(String),
        });
        const email = (user.email || '').toLowerCase();
        const { redirectTo } = await oauth.completeAuthorization({
          request: approved.request,
          userId: user.id,
          metadata: {},
          scope: approved.request.scope,
          props: {
            userId: user.id,
            email,
            flavor: formFlavor === 'china' ? 'china' : 'intl',
            name: displayName(user),
          },
        });
        const headers = new Headers(approved.headers);
        headers.set('Location', redirectTo);
        return new Response(null, { status: 302, headers });
      }

      return page('授权失败', '<p class="err">未知操作。</p>');
    }

    return new Response('Method Not Allowed', { status: 405 });
  } catch (error) {
    if (error instanceof AuthorizationError && error.redirectTo) {
      return Response.redirect(error.redirectTo, 302);
    }
    if (error instanceof AuthorizationError || error instanceof CimdFetchError) {
      const message =
        error instanceof AuthorizationError
          ? error.description || error.message
          : 'This app could not be verified.';
      return page('授权错误', `<p>${escapeHtml(message)}</p>`);
    }
    throw error;
  }
}
