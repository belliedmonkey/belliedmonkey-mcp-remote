/**
 * Minimal /authorize for Grok「连接应用」.
 * Choice (documented in RESULT): Workers OAuthProvider email consent page.
 * No Supabase secrets on Mac for this deploy → email form stores userId+flavor in props.
 * Not a permanent plaintext API key path.
 */
import {
  AuthorizationError,
  CimdFetchError,
  type OAuthHelpers,
} from '@cloudflare/workers-oauth-provider';
import { flavorFromHost, type Flavor } from './receipt';

function escapeHtml(s: string): string {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function page(title: string, body: string): Response {
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
  input[type=email] { width: 100%; padding: 0.55rem 0.65rem; font-size: 1rem; box-sizing: border-box; }
  .hint { display: block; color: #666; font-size: 0.8rem; margin: 0 0 0.35rem; line-height: 1.4; }
  .warn { background: #fff3cd; color: #664d03; padding: 0.6rem 0.75rem; border-radius: 6px; font-size: 0.9rem; }
  .row { display: flex; gap: 0.5rem; margin-top: 1rem; }
  button { padding: 0.55rem 1rem; font-size: 1rem; cursor: pointer; }
  .muted { color: #666; font-size: 0.85rem; }
</style>
<body>
${body}
</body>
</html>`;
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

export async function handleAuthorize(
  request: Request,
  oauth: OAuthHelpers,
): Promise<Response> {
  const url = new URL(request.url);
  const flavor: Flavor = flavorFromHost(url.hostname);

  try {
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
      const body = `
  <h1>连接大肚猴翻译</h1>
  <p>允许 <strong>${escapeHtml(name)}</strong> 代表你连接大肚猴翻译。云端只负责编排；开麦、读页、写学习库都在你的本机 App 或扩展里确认。</p>
  ${hostWarn}
  <form method="post" action="/authorize">
    <input type="hidden" name="handle" value="${escapeHtml(consent.handle)}">
    <input type="hidden" name="flavor" value="${escapeHtml(flavor)}">
    <label for="email">邮箱</label>
    <span class="hint" id="email-hint">当前是邮箱授权门（临时），还不是大肚猴正式账号或订阅绑定。</span>
    <input id="email" name="email" type="email" required autocomplete="username" placeholder="you@example.com" aria-describedby="email-hint">
    <fieldset style="border:0;padding:0;margin:0.75rem 0 0">
      <legend class="muted">权限范围（用于连接工具；不扩大权限）</legend>
      ${scopes || '<p class="muted">mcp:read</p>'}
    </fieldset>
    <div class="row">
      <button name="decision" value="approve" type="submit">允许并连接</button>
      <button name="decision" value="deny" type="submit">拒绝</button>
    </div>
    <p class="muted">连接成功不代表听译已通。</p>
  </form>`;
      // Optional deny landing copy (not Live this order): 已拒绝连接。可稍后再从「连接应用」重试。
      const res = page('授权 · 大肚猴翻译', body);
      // Merge consent cookies/headers
      const headers = new Headers(res.headers);
      consent.headers.forEach((v, k) => {
        if (k.toLowerCase() === 'set-cookie') headers.append(k, v);
        else if (!headers.has(k)) headers.set(k, v);
      });
      return new Response(res.body, { status: 200, headers });
    }

    if (request.method === 'POST') {
      const form = await request.formData();
      const handle = String(form.get('handle') || '');
      const decision = String(form.get('decision') || '');
      if (decision !== 'approve') {
        const denied = await oauth.denyConsent(request, handle);
        const headers = new Headers(denied.headers);
        if (!headers.has('Location')) headers.set('Location', denied.redirectTo);
        return new Response(null, { status: 302, headers });
      }
      const email = String(form.get('email') || '')
        .trim()
        .toLowerCase();
      if (!email || !email.includes('@')) {
        return page('授权失败', '<p>请填写有效邮箱。</p><p><a href="/authorize">返回</a></p>');
      }
      const formFlavor = String(form.get('flavor') || flavor) as Flavor;
      const approved = await oauth.approveConsent(request, handle, {
        scope: form.getAll('scope').map(String),
      });
      const { redirectTo } = await oauth.completeAuthorization({
        request: approved.request,
        userId: email,
        metadata: {},
        scope: approved.request.scope,
        props: {
          userId: email,
          email,
          flavor: formFlavor === 'china' ? 'china' : 'intl',
          name: email,
        },
      });
      const headers = new Headers(approved.headers);
      headers.set('Location', redirectTo);
      return new Response(null, { status: 302, headers });
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
