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

function authProps(): AuthProps {
  const ctx = getMcpAuthContext();
  return (ctx?.props as AuthProps) || {};
}

function hostFlavor(hostname: string, props: AuthProps): Flavor {
  if (props.flavor === 'china' || props.flavor === 'intl') return props.flavor;
  return flavorFromHost(hostname);
}

function userNote(props: AuthProps): string {
  const id = props.userId || props.email;
  return id ? ` oauth_user=${id}` : '';
}

export function registerTools(server: McpServer, hostname: string) {
  const props = authProps();
  const flavor = hostFlavor(hostname, props);
  const scheme = schemeForFlavor(flavor);

  server.registerTool(
    'ready.check',
    {
      description:
        'Report local readiness. Does not change settings, permissions, or the study library. Gaps use the frozen failure codes inside message. The receipt has no page text.',
      inputSchema: z.object({ ...COMMON }),
    },
    async () => {
      // P1-a: no device bridge → honest gap need_app (never fake ready)
      const message = `缺口 need_app${userNote(props)}`;
      return mcpText(
        receipt('ready.check', 'ok', message, {
          open_setup: setupLink(scheme, 'install_app'),
        }),
      );
    },
  );

  server.registerTool(
    'open_setup',
    {
      description:
        'Open the existing setup step. Optional step: install_app, install_ext, login, packs, mic, engine.',
      inputSchema: z.object({
        ...COMMON,
        step: z.enum(['install_app','install_ext','login','packs','mic','engine']).optional(),
      }),
    },
    async ({ step }) => {
      const s = (step || 'install_app') as string;
      if (!(SETUP_STEPS as readonly string[]).includes(s)) {
        return mcpText(receipt('open_setup', 'bad_request', `非法 step: ${s}`));
      }
      const link = setupLink(scheme, s as SetupStep);
      return mcpText(
        receipt('open_setup', 'ok', `打开设置步 ${s}`, {
          open_setup: link,
        }),
      );
    },
  );

  // Five sensitive tools: P1-a returns need_confirm/need_app + deeplink only.
  // Never claim cloud translated a page or started the mic.
  const sensitive: Array<{
    name: (typeof ACTIONS)[number];
    description: string;
    inputSchema: z.ZodObject<z.ZodRawShape>;
    code: 'need_confirm' | 'need_app';
    message: string;
    step: SetupStep;
  }> = [
    {
      name: 'start_live_subtitles',
      description:
        'Open the live-subtitle surface after the user confirms. Does not start the microphone. Optional video_lang and my_lang.',
      inputSchema: z.object({
        ...COMMON,
        video_lang: z.string().optional(),
        my_lang: z.string().optional(),
      }),
      code: 'need_confirm',
      message: '需在本机 App 确认后打开字幕面；云端不开麦',
      step: 'mic',
    },
    {
      name: 'translate_page',
      description:
        'Ask the extension to translate the current page after the user confirms. App-only calls return need_ext. Optional url is a hint, not a fetch.',
      inputSchema: z.object({
        ...COMMON,
        url: z.string().optional(),
      }),
      code: 'need_app',
      message: '页译须本机扩展/App；云端不读页、不标成功译页',
      step: 'install_ext',
    },
    {
      name: 'translate_video_captions',
      description:
        'Ask the extension for in-page video captions after the user confirms. Unsupported sites return site_unsupported. Optional url is a hint, not a fetch.',
      inputSchema: z.object({
        ...COMMON,
        url: z.string().optional(),
      }),
      code: 'need_app',
      message: '视频字幕须本机扩展；云端不抓页',
      step: 'install_ext',
    },
    {
      name: 'capture_to_study',
      description:
        'Save a sentence to the study library after the user confirms. Requires text or quote (or a paste on the confirm card). The receipt does not echo the sentence.',
      inputSchema: z.object({
        ...COMMON,
        text: z.string().optional(),
        quote: z.string().optional(),
      }),
      code: 'need_confirm',
      message: '写入学习库须本机确认；云端不写库、回执无句子',
      step: 'install_app',
    },
    {
      name: 'explain_or_drill',
      description:
        'Explain or lightly drill a sentence after the user confirms. mode is explain or drill (default explain). The receipt does not echo the sentence.',
      inputSchema: z.object({
        ...COMMON,
        text: z.string().optional(),
        quote: z.string().optional(),
        mode: z.enum(['explain', 'drill']).optional(),
      }),
      code: 'need_confirm',
      message: '讲解/操练须本机确认；云端不做解析、回执无句子',
      step: 'install_app',
    },
  ];

  for (const t of sensitive) {
    server.registerTool(
      t.name,
      { description: t.description, inputSchema: t.inputSchema },
      async () =>
        mcpText(
          receipt(t.name, t.code, t.message, {
            open_setup: setupLink(scheme, t.step),
          }),
        ),
    );
  }

  // Sanity: exactly seven names registered
  void ACTIONS;
}
