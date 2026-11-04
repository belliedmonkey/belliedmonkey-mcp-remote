/**
 * BEL-151 P1-a · BelliedMonkey Remote MCP
 * Single Worker: OAuthProvider (AS+RS) + createMcpHandler at /mcp/v1
 * + device bridge /api/mcp/device-sessions/* (BEL-151 device-bridge P0)
 */
import OAuthProvider, {
  insufficientScope,
  type OAuthProviderOptions,
} from '@cloudflare/workers-oauth-provider';
import { McpServer } from '@modelcontextprotocol/server';
import { createMcpHandler, getMcpAuthContext } from 'agents/mcp/server';
import { handleAuthorize, handleIdpCallback } from './authorize';
import { flavorFromHost } from './receipt';
import { registerTools } from './tools';
import { handleDeviceSessions, isDeviceSessionsPath } from './device-sessions';
import { captureInitialize } from './client-caps';
import {
  CC_ORIGIN,
  COM_ORIGIN,
  originForHostname,
  protectedResourceMetadataFor,
  resourceMetadataFor,
} from './origins';

export interface Env {
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: import('@cloudflare/workers-oauth-provider').OAuthHelpers;
  MCP_RESOURCE_URL: string;
  ISSUER: string;
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
}

type AuthProps = {
  userId?: string;
  email?: string;
  flavor?: 'china' | 'intl';
  name?: string;
};

const SCOPES = ['mcp:read', 'mcp:write', 'offline_access'] as const;

const ALLOWED_HOSTS = [
  'mcp.belliedmonkey.cc',
  'mcp.belliedmonkey.com',
  'mcp-china.belliedmonkey.cc',
  'belliedmonkey-mcp-remote.belliedmonkey.workers.dev',
];

const defaultHandler = {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/authorize') {
      return handleAuthorize(request, env.OAUTH_PROVIDER, env);
    }
    if (url.pathname === '/authorize/idp/callback') {
      return handleIdpCallback(request, env);
    }
    // Device bridge APIs also accepted here (Bearer validated inside) for hosts
    // that hit defaultHandler; primary path is apiRoute list below.
    if (isDeviceSessionsPath(url.pathname)) {
      return handleDeviceSessions(request, env);
    }
    if (url.pathname === '/' || url.pathname === '/health') {
      // BEL-151 com-health-meta: health metadata must follow the public host
      // flavor. China (.com via edge) stays honest .com; intl stays env.ISSUER (.cc).
      const flavor = flavorFromHost(url.hostname, request.headers);
      const publicOrigin =
        flavor === 'china'
          ? 'https://mcp.belliedmonkey.com'
          : env.ISSUER || 'https://mcp.belliedmonkey.cc';
      return Response.json(
        {
          service: 'belliedmonkey-mcp-remote',
          track: 'BEL-151-P1-a',
          mcp: `${publicOrigin}/mcp/v1`,
          issuer: publicOrigin,
          tools: [
            'ready.check',
            'open_setup',
            'start_live_subtitles',
            'translate_page',
            'translate_video_captions',
            'capture_to_study',
            'explain_or_drill',
          ],
          device_bridge: {
            register: `${publicOrigin}/api/mcp/device-sessions/register`,
            heartbeat: `${publicOrigin}/api/mcp/device-sessions/heartbeat`,
            bootstrap: `${publicOrigin}/api/mcp/device-sessions/bootstrap`,
            revoke: `${publicOrigin}/api/mcp/device-sessions/revoke`,
            confirm: `${publicOrigin}/api/mcp/device-sessions/confirm`,
          },
          note:
            'Remote MCP orchestration only. Page translate / live-subtitle side effects stay on the local App/extension. Do not claim Grok D3 until VERIFY passes.',
        },
        { headers: { 'Cache-Control': 'no-store' } },
      );
    }
    return new Response('Not Found', { status: 404 });
  },
};

const apiHandler = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const c = ctx as ExecutionContext & {
      props?: AuthProps;
      auth?: { scope?: string[]; token?: string };
    };
    const props = c.props || {};
    if (c.auth?.scope && !c.auth.scope.includes('mcp:read')) {
      return insufficientScope(c.auth as never, ['mcp:read']);
    }
    const hostname = new URL(request.url).hostname;
    // ACCEPT-PROBE: record initialize.capabilities (cloned body; never claim A
    // supported when this record is absent or lacks elicitation).
    try {
      await captureInitialize(request, env, props.userId);
    } catch {
      /* probe is best-effort; never block MCP */
    }
    const handler = createMcpHandler(
      () => {
        const server = new McpServer({
          name: 'belliedmonkey',
          version: '0.1.0-p1a',
        });
        void getMcpAuthContext();
        registerTools(server, hostname, env);
        return server;
      },
      {
        route: '/mcp/v1',
        allowedHostnames: ALLOWED_HOSTS,
        allowedOriginHostnames: '*',
        authContext: { props },
        corsOptions: {
          origin: '*',
        },
      },
    );
    return handler(request, env, ctx);
  },
};

/** BEL-151 ACCEPT-RD2: FREEZE App custom-scheme callbacks only (exact match). */
const ALLOWED_PRIVATE_REDIRECT_URIS = new Set([
  'belliedmonkey://oauth/mcp/callback',
  'belliedmonkeycn://oauth/mcp/callback',
]);

function isHttpOrHttpsScheme(uri: string): boolean {
  try {
    const protocol = new URL(uri).protocol;
    return protocol === 'https:' || protocol === 'http:';
  } catch {
    return false;
  }
}

/**
 * Policy: with allowPrivateUseRedirectUris, library accepts any safe private-use scheme.
 * Whitelist so only product FREEZE schemes register; https/loopback clients unchanged.
 */
function clientRegistrationCallback(options: {
  clientMetadata: Record<string, unknown>;
}): { code?: string; description?: string; status?: number } | void {
  const raw = options.clientMetadata.redirect_uris;
  const uris = Array.isArray(raw) ? raw.filter((u): u is string => typeof u === 'string') : [];
  for (const uri of uris) {
    const trimmed = uri.trim();
    if (isHttpOrHttpsScheme(trimmed)) continue;
    if (!ALLOWED_PRIVATE_REDIRECT_URIS.has(trimmed)) {
      return {
        code: 'invalid_client_metadata',
        description:
          'Private-use redirect_uri is not on the BelliedMonkey allowlist (belliedmonkey://oauth/mcp/callback or belliedmonkeycn://oauth/mcp/callback)',
        status: 400,
      };
    }
  }
}

/**
 * The provider snapshots resourceMetadata at construction time (no function
 * form in 1.2.4), so one instance is built per public origin. Both share the
 * same OAUTH_KV; token records carry their audience, which keeps .cc and .com
 * tokens from crossing over.
 */
function oauthOptions(origin: string): OAuthProviderOptions<Env> {
  return {
    // Device-session paths stay on defaultHandler (unwrapToken).
    // apiRoute resource is /mcp/v1 — cannot cover /api/* without widening resource (would break Grok paste URL).
    apiRoute: '/mcp/v1',
    apiHandler,
    defaultHandler,
    authorizeEndpoint: '/authorize',
    tokenEndpoint: '/oauth/token',
    clientRegistrationEndpoint: '/oauth/register',
    scopesSupported: [...SCOPES],
    requiredScopes: ['mcp:read'],
    clientIdMetadataDocumentEnabled: true,
    // BEL-151 ACCEPT-RD1/RD2: App FREEZE custom scheme DCR (RFC 8252 private-use).
    allowPrivateUseRedirectUris: true,
    clientRegistrationCallback,
    // Must match the URL clients paste into Grok Connect Apps for this host.
    resourceMetadata: resourceMetadataFor(origin),
  };
}

const ccProvider = new OAuthProvider<Env>(oauthOptions(CC_ORIGIN));
const comProvider = new OAuthProvider<Env>(oauthOptions(COM_ORIGIN));

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);
    const origin = originForHostname(url.hostname);
    // The provider only serves the canonical resource-path document
    // (/.well-known/oauth-protected-resource/mcp/v1). RFC 9728 clients also
    // probe the bare well-known URL, so answer it here for both hosts.
    if (url.pathname === '/.well-known/oauth-protected-resource') {
      return Response.json(protectedResourceMetadataFor(origin), {
        headers: { 'Cache-Control': 'no-store' },
      });
    }
    const provider = origin === COM_ORIGIN ? comProvider : ccProvider;
    // The China edge forwards mcp.belliedmonkey.com to the mid-host
    // mcp-china.belliedmonkey.cc. Present that request to the provider as the
    // public .com origin so issuer, resource, path-PRM and the MCP challenge
    // are all .com (the edge only rewrites the Host, not the OAuth metadata).
    let providerRequest = request;
    if (
      origin === COM_ORIGIN &&
      url.hostname.toLowerCase() !== new URL(COM_ORIGIN).hostname
    ) {
      const canonicalUrl = new URL(request.url);
      canonicalUrl.protocol = 'https:';
      canonicalUrl.host = new URL(COM_ORIGIN).host;
      providerRequest = new Request(canonicalUrl.toString(), request);
    }
    // OAuthProvider injects env.OAUTH_PROVIDER only when absent. Workers may
    // reuse the env object between requests, so a shared env would pin every
    // later request to whichever provider handled the first one (making .cc
    // and .com resources leak into each other). .cc keeps the original env
    // exactly as before; only .com dispatches through a copy with the helper
    // slot cleared, so the original env never holds a .com helper.
    let providerEnv = env;
    if (origin === COM_ORIGIN) {
      providerEnv = { ...env };
      delete (providerEnv as Partial<Env>).OAUTH_PROVIDER;
    }
    return provider.fetch(providerRequest, providerEnv, ctx);
  },
};
