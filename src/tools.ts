import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/server';
import { getMcpAuthContext } from 'agents/mcp/server';
import {
  ACTIONS,
  SETUP_STEPS,
  type Flavor,
  type SetupStep,
  flavorFromHost,
  mcpText,
  receipt,
  schemeForFlavor,
  setupLink,
} from './receipt';
import { getFreshBridge, type BridgeView } from './device-sessions';

const COMMON = {
  source: z.enum(['agent', 'mcp', 'deeplink', 'web', 'ext']).optional(),
  v: z.string().optional(),
  caller: z.string().optional(),
  caller_id: z.string().optional(),
  lang: z.string().optional(),
  return: z.string().optional(),
};

type AuthProps = {
  userId?: string;
  email?: string;
  flavor?: Flavor;
  name?: string;
};

type EnvLike = {
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: import('@cloudflare/workers-oauth-provider').OAuthHelpers;
  MCP_RESOURCE_URL: string;
  ISSUER: string;
};

function authProps(): AuthProps {
  const ctx = getMcpAuthContext();
  return (ctx?.props as AuthProps) || {};
}

function hostFlavor(hostname: string, props: AuthProps): Flavor {
  if (props.flavor === 'china' || props.flavor === 'intl') return props.flavor;
  return flavorFromHost(hostname);
}

/** Debug-only id; never splice into user-visible message. */
function debugUser(props: AuthProps): string | undefined {
  return props.userId || props.email || undefined;
}

function bridgeFix(bridge: BridgeView): Record<string, string> {
  const fix: Record<string, string> = {};
  if (bridge.up && bridge.platform) fix.device = bridge.platform;
  if (bridge.up && bridge.last_seen != null) fix.last_seen = String(bridge.last_seen);
  return fix;
}

export function registerTools(server: McpServer, hostname: string, env: EnvLike) {
  const props = authProps();
  const flavor = hostFlavor(hostname, props);
  const scheme = schemeForFlavor(flavor);
  const dbg = debugUser(props);

  server.registerTool(
    'ready.check',
    {
      description:
        'Report local readiness. Does not change settings, permissions, or the study library. Gaps use the frozen failure codes in fix.gap (not only the message). The receipt has no page text. Does not open the mic or claim listen-translate is connected.',
      inputSchema: z.object({ ...COMMON }),
    },
    async () => {
      const bridge = await getFreshBridge(env, props.userId);
      if (!bridge.up) {
        // No bridge / expired / unpaired → honest need_app (P1-a + ACCEPT-D2)
        const message =
          '尚未检测到本机大肚猴 App（或设备尚未就绪）。请先安装或打开「大肚猴翻译」，再检查一次。这不代表听译已经接通。';
        const fix: Record<string, string> = {
          gap: 'need_app',
          open_setup: setupLink(scheme, 'install_app'),
        };
        if (dbg) fix.debug_oauth_user = dbg;
        return mcpText(receipt('ready.check', 'ok', message, fix));
      }
      // Bridge UP: clear ONLY need_app-from-no-bridge. Never claim listen-translate ready / full D3.
      const message =
        '本机 App 已连通（设备桥可达）。其他缺口请在本机查看。这不代表听译已经接通，也不代表全部就绪。';
      const fix: Record<string, string> = {
        ...bridgeFix(bridge),
      };
      if (dbg) fix.debug_oauth_user = dbg;
      return mcpText(receipt('ready.check', 'ok', message, fix));
    },
  );

  server.registerTool(
    'open_setup',
    {
      description:
        'Open on-device BelliedMonkey settings or install guidance (deep link). Optional step is a setup-step query parameter (not a separate tool): install_app, install_ext, login, packs, mic, engine. Do not invent or call a tool named install_app.',
      inputSchema: z.object({
        ...COMMON,
        step: z.enum(['install_app','install_ext','login','packs','mic','engine']).optional(),
      }),
    },
    async ({ step }) => {
      const s = (step || 'install_app') as string;
      if (!(SETUP_STEPS as readonly string[]).includes(s)) {
        return mcpText(receipt('open_setup', 'bad_request', `非法设置步骤：${s}`));
      }
      const link = setupLink(scheme, s as SetupStep);
      const message =
        '请在本机打开大肚猴设置（安装或启用 App）。若链接无法点开，请复制后在 Safari/Chrome 打开，或前往 https://belliedmonkey.cc/for-agents';
      return mcpText(
        receipt('open_setup', 'ok', message, {
          open_setup: link,
          step: s,
        }),
      );
    },
  );

  // Five sensitive tools:
  // bridge DOWN → need_app + deeplink (honest; no side effects)
  // bridge UP  → need_confirm + deeplink (pull on-device confirm; never auto-execute)
  const sensitive: Array<{
    name: (typeof ACTIONS)[number];
    description: string;
    inputSchema: z.ZodObject<z.ZodRawShape>;
    messageDown: string;
    messageUp: string;
    step: SetupStep;
  }> = [
    {
      name: 'start_live_subtitles',
      description:
        'Request the live-subtitle surface. Requires on-device confirmation; does not start the microphone in the cloud. Optional video_lang and my_lang.',
      inputSchema: z.object({
        ...COMMON,
        video_lang: z.string().optional(),
        my_lang: z.string().optional(),
      }),
      messageDown: '打开实时字幕须本机 App 可达并确认；当前未检测到设备桥。云端不会开麦，也不会假装已接通听译。',
      messageUp: '打开实时字幕须在本机 App 确认；云端不会开麦，也不会假装已接通听译。',
      step: 'mic',
    },
    {
      name: 'translate_page',
      description:
        'Ask the on-device extension or App to translate the current page after the user confirms. The cloud does not read the page. App-only calls return need_ext. Optional url is a hint, not a fetch.',
      inputSchema: z.object({
        ...COMMON,
        url: z.string().optional(),
      }),
      messageDown: '页译须本机扩展或 App 可达并确认；当前未检测到设备桥。云端不读当前页，也不会标为已成功译页。',
      messageUp: '页译须本机扩展或 App 确认后执行；云端不读当前页，也不会标为已成功译页。',
      step: 'install_ext',
    },
    {
      name: 'translate_video_captions',
      description:
        'Ask the on-device extension for in-page video captions after the user confirms. The cloud does not fetch the page. Unsupported sites return site_unsupported. Optional url is a hint, not a fetch.',
      inputSchema: z.object({
        ...COMMON,
        url: z.string().optional(),
      }),
      messageDown: '视频字幕须本机扩展可达并确认；当前未检测到设备桥。云端不抓取页面，也不会标为已出字幕。',
      messageUp: '视频字幕须本机扩展确认后执行；云端不抓取页面，也不会标为已出字幕。',
      step: 'install_ext',
    },
    {
      name: 'capture_to_study',
      description:
        'Save a sentence to the study library after the user confirms on device. Requires text or quote (or a paste on the confirm card). The cloud does not write the library; the receipt does not echo the sentence.',
      inputSchema: z.object({
        ...COMMON,
        text: z.string().optional(),
        quote: z.string().optional(),
      }),
      messageDown: '写入学习库须本机 App 可达并确认；当前未检测到设备桥。云端不会写库，回执也不含句子正文。',
      messageUp: '写入学习库须在本机确认；云端不会写库，回执也不含句子正文。',
      step: 'install_app',
    },
    {
      name: 'explain_or_drill',
      description:
        'Explain or lightly drill a sentence after the user confirms on device. mode is explain or drill (default explain). The cloud does not parse the sentence; the receipt does not echo it.',
      inputSchema: z.object({
        ...COMMON,
        text: z.string().optional(),
        quote: z.string().optional(),
        mode: z.enum(['explain', 'drill']).optional(),
      }),
      messageDown: '讲解或操练须本机 App 可达并确认；当前未检测到设备桥。云端不做解析，回执也不含句子正文。',
      messageUp: '讲解或操练须在本机确认；云端不做解析，回执也不含句子正文。',
      step: 'install_app',
    },
  ];

  for (const t of sensitive) {
    server.registerTool(
      t.name,
      { description: t.description, inputSchema: t.inputSchema },
      async () => {
        const bridge = await getFreshBridge(env, props.userId);
        if (!bridge.up) {
          return mcpText(
            receipt(t.name, 'need_app', t.messageDown, {
              open_setup: setupLink(scheme, t.step),
              gap: 'need_app',
            }),
          );
        }
        // Bridge UP → need_confirm + deeplink; NO side effects before on-device confirm
        return mcpText(
          receipt(t.name, 'need_confirm', t.messageUp, {
            open_setup: setupLink(scheme, t.step),
            ...bridgeFix(bridge),
          }),
        );
      },
    );
  }

  // Sanity: exactly seven names registered
  void ACTIONS;
}
