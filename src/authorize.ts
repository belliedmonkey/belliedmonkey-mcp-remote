/**
 * /authorize for Grok「连接应用」— BEL-151 consent IdP.
 * Daily paths: Google / Apple / email OTP (intl); Apple / OTP (china, no Google).
 * Password kept as secondary (reviewer/compat). Session = HttpOnly bm_sb_access.
 * GoTrue access is NEVER used as MCP Bearer.
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
const COOKIE_VERIFIER = 'bm_idp_verifier';
const COOKIE_RETURN = 'bm_idp_return';
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7d
const VERIFIER_MAX_AGE = 60 * 10; // 10m
const IDP_CALLBACK_PATH = '/authorize/idp/callback';

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
  input[type=email], input[type=password], input[type=text] {
    width: 100%; padding: 0.55rem 0.65rem; font-size: 1rem; box-sizing: border-box;
  }
  .hint { display: block; color: #666; font-size: 0.8rem; margin: 0 0 0.35rem; line-height: 1.4; }
  .warn { background: #fff3cd; color: #664d03; padding: 0.6rem 0.75rem; border-radius: 6px; font-size: 0.9rem; }
  .err { background: #f8d7da; color: #842029; padding: 0.6rem 0.75rem; border-radius: 6px; font-size: 0.9rem; }
  .info { background: #e7f1ff; color: #084298; padding: 0.55rem 0.75rem; border-radius: 6px; font-size: 0.85rem; }
  .row { display: flex; gap: 0.5rem; margin-top: 1rem; flex-wrap: wrap; }
  button, .btn {
    padding: 0.55rem 1rem; font-size: 1rem; cursor: pointer;
    display: inline-block; text-decoration: none; color: inherit;
    border: 1px solid #8884; border-radius: 6px; background: #f7f7f8; text-align: center;
  }
  .btn-primary { background: #111; color: #fff; border-color: #111; }
  .btn-block { width: 100%; box-sizing: border-box; margin-top: 0.5rem; }
  .idp { display: flex; flex-direction: column; gap: 0.5rem; margin: 1rem 0; }
  .muted { color: #666; font-size: 0.85rem; }
  .account { background: #f0f4f8; color: #102a43; padding: 0.55rem 0.75rem; border-radius: 6px; font-size: 0.9rem; }
  details.secondary { margin-top: 1.25rem; border-top: 1px solid #8883; padding-top: 0.75rem; }
  details.secondary summary { cursor: pointer; color: #555; font-size: 0.9rem; }
  fieldset { border: 0; padding: 0; margin: 0.75rem 0 0; }
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

function setTempCookie(name: string, value: string, maxAge = VERIFIER_MAX_AGE): string {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function clearTempCookie(name: string): string {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
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

function idpCallbackUrl(origin: string): string {
  return `${origin}${IDP_CALLBACK_PATH}`;
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
  const grant = await passwordGrant(env, email, password);
  if (grant.access_token) return grant;
  return {
    needsConfirm: true,
    error: '注册成功。若需邮箱确认，请查收邮件后再登录。',
  };
}

async function sendEmailOtp(
  env: AuthorizeEnv,
  email: string,
): Promise<{ ok?: boolean; error?: string }> {
  const res = await sbFetch(env, '/auth/v1/otp', {
    method: 'POST',
    body: JSON.stringify({ email, create_user: true }),
  });
  if (res.ok) return { ok: true };
  const data = (await res.json().catch(() => ({}))) as {
    error_description?: string;
    msg?: string;
    error?: string;
    message?: string;
  };
  return {
    error:
      data.error_description ||
      data.msg ||
      data.message ||
      data.error ||
      '发送验证码失败。',
  };
}

async function verifyEmailOtp(
  env: AuthorizeEnv,
  email: string,
  token: string,
): Promise<{ access_token?: string; error?: string }> {
  const res = await sbFetch(env, '/auth/v1/verify', {
    method: 'POST',
    body: JSON.stringify({ email, token, type: 'email' }),
  });
  const data = (await res.json()) as {
    access_token?: string;
    error_description?: string;
    msg?: string;
    error?: string;
    message?: string;
  };
  if (!res.ok || !data.access_token) {
    return {
      error:
        data.error_description ||
        data.msg ||
        data.message ||
        data.error ||
        '验证码无效或已过期。',
    };
  }
  return { access_token: data.access_token };
}

function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]!);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomVerifier(): string {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return b64url(buf);
}

async function pkceChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return b64url(digest);
}

async function exchangePkce(
  env: AuthorizeEnv,
  authCode: string,
  codeVerifier: string,
): Promise<{ access_token?: string; error?: string }> {
  const res = await sbFetch(env, '/auth/v1/token?grant_type=pkce', {
    method: 'POST',
    body: JSON.stringify({
      auth_code: authCode,
      code_verifier: codeVerifier,
    }),
  });
  const data = (await res.json()) as {
    access_token?: string;
    error_description?: string;
    msg?: string;
    error?: string;
    message?: string;
  };
  if (!res.ok || !data.access_token) {
    return {
      error:
        data.error_description ||
        data.msg ||
        data.message ||
        data.error ||
        'OAuth 换票失败。',
    };
  }
  return { access_token: data.access_token };
}

function displayName(user: SbUser): string {
  return (
    user.user_metadata?.name ||
    user.user_metadata?.full_name ||
    user.email ||
    user.id
  );
}

function loginFormBody(opts: {
  name: string;
  flavor: Flavor;
  hostWarn: string;
  errBlock: string;
  returnTo: string;
  otpEmail?: string;
  otpSent?: boolean;
  chinaHoldNote?: string;
}): string {
  const {
    name,
    flavor,
    hostWarn,
    errBlock,
    returnTo,
    otpEmail = '',
    otpSent = false,
    chinaHoldNote = '',
  } = opts;
  const showGoogle = flavor !== 'china';
  const chinaNoGoogle = flavor === 'china'
    ? `<p class="info" data-testid="china-no-google">中国版不提供 Google 登录（与 App 一致）。请用 Apple 或邮箱验证码。</p>`
    : '';
  const googleBtn = showGoogle
    ? `<button class="btn btn-block" name="action" value="idp_google" type="submit" data-testid="idp-google">使用 Google 继续</button>`
    : '';
  const appleBtn = `<button class="btn btn-block" name="action" value="idp_apple" type="submit" data-testid="idp-apple">使用 Apple 继续</button>`;

  const otpBlock = otpSent
    ? `
  <form method="post" action="/authorize" data-testid="otp-verify-form">
    <input type="hidden" name="flavor" value="${escapeHtml(flavor)}">
    <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
    <input type="hidden" name="email" value="${escapeHtml(otpEmail)}">
    <p class="hint">验证码已发往 <strong>${escapeHtml(otpEmail)}</strong>。请输入六位码。</p>
    <label for="otp">邮箱验证码</label>
    <input id="otp" name="otp" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autocomplete="one-time-code" placeholder="六位数字" data-testid="otp-code">
    <div class="row">
      <button class="btn-primary" name="action" value="otp_verify" type="submit" data-testid="otp-verify">验证并继续</button>
      <button name="action" value="otp_resend" type="submit">重发验证码</button>
    </div>
  </form>`
    : `
  <form method="post" action="/authorize" data-testid="otp-send-form">
    <input type="hidden" name="flavor" value="${escapeHtml(flavor)}">
    <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
    <label for="otp_email">邮箱验证码登录</label>
    <span class="hint">日常主路之一：发送六位码到邮箱（非 magic link）。</span>
    <input id="otp_email" name="email" type="email" required autocomplete="username" placeholder="you@example.com" data-testid="otp-email">
    <div class="row">
      <button class="btn-primary" name="action" value="otp_send" type="submit" data-testid="otp-send">发送验证码</button>
    </div>
  </form>`;

  return `
  <h1>连接大肚猴翻译</h1>
  <p>允许 <strong>${escapeHtml(name)}</strong> 代表你连接大肚猴翻译。请先用日常方式登录大肚猴账号。</p>
  ${hostWarn}
  ${chinaNoGoogle}
  ${chinaHoldNote}
  ${errBlock}
  <form method="post" action="/authorize" class="idp" data-testid="idp-oauth-form">
    <input type="hidden" name="flavor" value="${escapeHtml(flavor)}">
    <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
    ${googleBtn}
    ${appleBtn}
  </form>
  ${otpBlock}
  <details class="secondary" data-testid="password-secondary">
    <summary>使用密码（审核员 / 兼容次路）</summary>
    <form method="post" action="/authorize">
      <input type="hidden" name="flavor" value="${escapeHtml(flavor)}">
      <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">
      <label for="email">邮箱</label>
      <input id="email" name="email" type="email" required autocomplete="username" placeholder="you@example.com">
      <label for="password">密码</label>
      <input id="password" name="password" type="password" required autocomplete="current-password" minlength="6">
      <div class="row">
        <button name="action" value="login" type="submit">登录并继续</button>
        <button name="action" value="signup" type="submit">注册并继续</button>
      </div>
      <p class="muted">密码门仅作审核员/兼容；日常请用上方 Google / Apple / 邮箱验证码。</p>
    </form>
  </details>
  <form method="post" action="/authorize" style="margin-top:1rem">
    <input type="hidden" name="decision" value="deny">
    <button type="submit" formnovalidate>拒绝</button>
  </form>
  <p class="muted">连接成功不代表听译已通。</p>`;
}

/** OAuth IdP callback: exchange PKCE code → Set-Cookie bm_sb_access → 302 /authorize */
export async function handleIdpCallback(
  request: Request,
  env: AuthorizeEnv,
): Promise<Response> {
  const url = new URL(request.url);
  if (!env.SUPABASE_URL || !env.SUPABASE_ANON_KEY) {
    return page(
      '授权配置错误',
      '<p class="err">服务未配置大肚猴账号体系。请稍后重试。</p>',
    );
  }
  const err = url.searchParams.get('error_description') || url.searchParams.get('error') || '';
  const code = url.searchParams.get('code') || '';
  const returnTo = safeReturnTo(parseCookie(request, COOKIE_RETURN) || '', url.origin);
  const verifier = parseCookie(request, COOKIE_VERIFIER) || '';

  const clearTemps = [
    clearTempCookie(COOKIE_VERIFIER),
    clearTempCookie(COOKIE_RETURN),
  ];

  if (err) {
    const u = new URL(returnTo, url.origin);
    u.searchParams.set('err', err);
    const headers = new Headers({ Location: u.toString() });
    for (const c of clearTemps) headers.append('Set-Cookie', c);
    return new Response(null, { status: 302, headers });
  }
  if (!code || !verifier) {
    const u = new URL(returnTo, url.origin);
    u.searchParams.set('err', '登录未完成（缺少授权码）。请重试。');
    const headers = new Headers({ Location: u.toString() });
    for (const c of clearTemps) headers.append('Set-Cookie', c);
    return new Response(null, { status: 302, headers });
  }

  const exchanged = await exchangePkce(env, code, verifier);
  if (!exchanged.access_token) {
    const u = new URL(returnTo, url.origin);
    u.searchParams.set('err', exchanged.error || 'OAuth 换票失败');
    const headers = new Headers({ Location: u.toString() });
    for (const c of clearTemps) headers.append('Set-Cookie', c);
    return new Response(null, { status: 302, headers });
  }

  const headers = new Headers({ Location: returnTo });
  headers.append('Set-Cookie', setSessionCookie(exchanged.access_token));
  for (const c of clearTemps) headers.append('Set-Cookie', c);
  return new Response(null, { status: 302, headers });
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
      const otpSent = url.searchParams.get('otp') === '1';
      const otpEmail = url.searchParams.get('email') || '';

      // china App (china.ready=true) uses api.belliedmonkey.com GoTrue; MCP Worker
      // still binds cave… — identity for device-bridge T5 is HOLD (ACCEPT-I3).
      const chinaHoldNote =
        flavor === 'china'
          ? `<p class="warn" data-testid="china-issuer-hold">说明：中国版 App 账号体系与本页当前 GoTrue 尚未对齐；本页 IdP 可点通登录，但<strong>设备桥身份验收（T5）本拍 HOLD</strong>，先清国际版。</p>`
          : '';

      let body: string;
      if (sessionUser) {
        body = `
  <h1>连接大肚猴翻译</h1>
  <p>允许 <strong>${escapeHtml(name)}</strong> 代表你连接大肚猴翻译。云端只负责编排；开麦、读页、写学习库都在你的本机 App 或扩展里确认。</p>
  ${hostWarn}
  ${errBlock}
  <p class="account" data-testid="signed-in-account">将用你的大肚猴账号授权连接：<strong>${escapeHtml(sessionUser.email || sessionUser.id)}</strong></p>
  <form method="post" action="/authorize" data-testid="consent-form">
    <input type="hidden" name="handle" value="${escapeHtml(consent.handle)}">
    <input type="hidden" name="flavor" value="${escapeHtml(flavor)}">
    <input type="hidden" name="action" value="consent">
    <fieldset>
      <legend class="muted">权限范围（用于连接工具；不扩大权限）</legend>
      ${scopes || '<p class="muted">mcp:read</p>'}
    </fieldset>
    <div class="row">
      <button name="decision" value="approve" type="submit" data-testid="approve">允许并连接</button>
      <button name="decision" value="deny" type="submit">拒绝</button>
    </div>
    <p class="muted">连接成功不代表听译已通。</p>
  </form>
  <form method="post" action="/authorize" style="margin-top:1rem">
    <input type="hidden" name="action" value="logout">
    <button type="submit">退出账号</button>
  </form>`;
      } else {
        const returnTo = url.toString();
        body = loginFormBody({
          name,
          flavor,
          hostWarn,
          errBlock,
          returnTo,
          otpEmail,
          otpSent,
          chinaHoldNote,
        });
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
        return new Response(null, { status: 302, headers });
      }

      if (decision === 'deny') {
        if (handle) {
          const denied = await oauth.denyConsent(request, handle);
          const headers = new Headers(denied.headers);
          if (!headers.has('Location')) headers.set('Location', denied.redirectTo);
          return new Response(null, { status: 302, headers });
        }
        return page(
          '已拒绝连接',
          '<p>已拒绝连接。可稍后再从「连接应用」重试。</p>',
        );
      }

      // Google / Apple → GoTrue authorize (PKCE) → /authorize/idp/callback
      if (action === 'idp_google' || action === 'idp_apple') {
        const provider = action === 'idp_google' ? 'google' : 'apple';
        if (flavor === 'china' && provider === 'google') {
          const returnTo = safeReturnTo(String(form.get('return_to') || ''), url.origin);
          const u = new URL(returnTo, url.origin);
          u.searchParams.set('err', '中国版不提供 Google 登录。');
          return Response.redirect(u.toString(), 302);
        }
        const returnTo = safeReturnTo(String(form.get('return_to') || ''), url.origin);
        const verifier = randomVerifier();
        const challenge = await pkceChallenge(verifier);
        const redirectTo = idpCallbackUrl(url.origin);
        const authUrl = new URL(`${env.SUPABASE_URL.replace(/\/$/, '')}/auth/v1/authorize`);
        authUrl.searchParams.set('provider', provider);
        authUrl.searchParams.set('redirect_to', redirectTo);
        authUrl.searchParams.set('code_challenge', challenge);
        authUrl.searchParams.set('code_challenge_method', 'S256');
        const headers = new Headers({ Location: authUrl.toString() });
        headers.append('Set-Cookie', setTempCookie(COOKIE_VERIFIER, verifier));
        headers.append('Set-Cookie', setTempCookie(COOKIE_RETURN, returnTo));
        return new Response(null, { status: 302, headers });
      }

      if (action === 'otp_send' || action === 'otp_resend') {
        const email = String(form.get('email') || '')
          .trim()
          .toLowerCase();
        const returnTo = safeReturnTo(String(form.get('return_to') || ''), url.origin);
        const u = new URL(returnTo, url.origin);
        if (!email || !email.includes('@')) {
          u.searchParams.set('err', '请填写有效邮箱。');
          return Response.redirect(u.toString(), 302);
        }
        const sent = await sendEmailOtp(env, email);
        if (!sent.ok) {
          u.searchParams.set('err', sent.error || '发送验证码失败');
          return Response.redirect(u.toString(), 302);
        }
        u.searchParams.set('otp', '1');
        u.searchParams.set('email', email);
        u.searchParams.delete('err');
        return Response.redirect(u.toString(), 302);
      }

      if (action === 'otp_verify') {
        const email = String(form.get('email') || '')
          .trim()
          .toLowerCase();
        const otp = String(form.get('otp') || '').trim();
        const returnTo = safeReturnTo(String(form.get('return_to') || ''), url.origin);
        const u = new URL(returnTo, url.origin);
        if (!email || !/^\d{6}$/.test(otp)) {
          u.searchParams.set('otp', '1');
          u.searchParams.set('email', email);
          u.searchParams.set('err', '请输入六位数字验证码。');
          return Response.redirect(u.toString(), 302);
        }
        const verified = await verifyEmailOtp(env, email, otp);
        if (!verified.access_token) {
          u.searchParams.set('otp', '1');
          u.searchParams.set('email', email);
          u.searchParams.set('err', verified.error || '验证失败');
          return Response.redirect(u.toString(), 302);
        }
        const headers = new Headers({
          Location: returnTo,
          'Set-Cookie': setSessionCookie(verified.access_token),
        });
        return new Response(null, { status: 302, headers });
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
