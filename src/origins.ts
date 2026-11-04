/**
 * BEL-151 com OAuth audience: the public origin (issuer + protected resource)
 * is derived from the request Host. The .cc path is the historical default and
 * must stay byte-for-byte identical; only mcp.belliedmonkey.com (and its
 * subdomains, if ever routed here) selects the .com origin.
 */
export const CC_ORIGIN = 'https://mcp.belliedmonkey.cc';
export const COM_ORIGIN = 'https://mcp.belliedmonkey.com';

export type ResourceMetadata = {
  resource: string;
  authorization_servers: string[];
};

export type ProtectedResourceMetadata = ResourceMetadata & {
  scopes_supported: string[];
  bearer_methods_supported: string[];
};

/** Host → canonical public origin. Everything except .com keeps the .cc config. */
export function originForHostname(hostname: string): string {
  const host = (hostname || '').toLowerCase();
  if (host === 'mcp.belliedmonkey.com' || host.endsWith('.belliedmonkey.com')) {
    return COM_ORIGIN;
  }
  return CC_ORIGIN;
}

export function resourceMetadataFor(origin: string): ResourceMetadata {
  return {
    resource: `${origin}/mcp/v1`,
    authorization_servers: [origin],
  };
}

/**
 * RFC 9728 document for the resource root. The provider itself only serves
 * /.well-known/oauth-protected-resource/mcp/v1 (the canonical resource path),
 * so the dispatcher answers the bare well-known URL for both hosts.
 */
export function protectedResourceMetadataFor(
  origin: string,
): ProtectedResourceMetadata {
  return {
    ...resourceMetadataFor(origin),
    scopes_supported: ['mcp:read'],
    bearer_methods_supported: ['header'],
  };
}
