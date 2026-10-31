/**
 * BEL-151 P1-a · BelliedMonkey Remote MCP
 * Single Worker: OAuthProvider (AS+RS) + createMcpHandler at /mcp/v1
 * + device bridge /api/mcp/device-sessions/* (BEL-151 device-bridge P0)
 */
import OAuthProvider, { insufficientScope } from '@cloudflare/workers-oauth-provider';
import { McpServer } from '@modelcontextprotocol/server';
import { createMcpHandler, getMcpAuthContext } from 'agents/mcp/server';
import { handleAuthorize } from './authorize';
import { flavorFromHost } from './receipt';
import { registerTools } from './tools';
import { handleDeviceSessions, isDeviceSessionsPath } from './device-sessions';

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

export default new OAuthProvider<Env>({
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
  resourceMetadata: {
    // Must match the URL clients paste into Grok Connect Apps.
    resource: 'https://mcp.belliedmonkey.cc/mcp/v1',
    authorization_servers: ['https://mcp.belliedmonkey.cc'],
  },
});
