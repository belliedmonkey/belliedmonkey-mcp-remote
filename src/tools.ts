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
  actionLink,
  receipt,
  schemeForFlavor,
  setupLink,
  type Receipt,
} from './receipt';
import { getFreshBridge, type BridgeView } from './device-sessions';
import {
  buildResumeReceipt,
  createPending,
  decidePending,
  gcPending,
  getPending,
  markElicitConfirmed,
  revokeAllPending,
  type PendingRecord,
} from './pending-confirm';
import { elicitProbeFix, getClientCaps, type ClientCapsRecord } from './client-caps';

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
  // bridge UP  → short-lived pending_confirm + need_confirm + action deeplink
  //              (pending_id appended). App confirm callback resumes the call.
  // A is attempted ONLY when the client's initialize declared elicitation;
  // it is a confirmation channel in this slice and never claims the surface.
  const PENDING_ARGS = {
    pending_id: z.string().optional(),
    wait_sec: z.number().int().min(0).max(25).optional(),
  };

  type ElicitCtx = {
    mcpReq?: {
      elicitInput?: (
        params: { message: string; requestedSchema: Record<string, unknown> },
        options?: Record<string, unknown>,
      ) => Promise<{ action?: string; content?: Record<string, unknown> }>;
    };
  };

  const sensitive: Array<{
    name: (typeof ACTIONS)[number];
    description: string;
    inputSchema: z.ZodObject<z.ZodRawShape>;
    messageDown: string;
    messageUp: string;
    step: SetupStep;
    /** need_confirm fix must be this action's own deep link, not a setup step. */
    actionDeeplink?: boolean;
  }> = [
    {
      name: 'start_live_subtitles',
      description:
        'Request the live-subtitle surface. Requires on-device confirmation; does not start the microphone in the cloud. Optional video_lang and my_lang. Pass pending_id to replay/resume an existing confirmation.',
      inputSchema: z.object({
        ...COMMON,
        ...PENDING_ARGS,
        video_lang: z.string().optional(),
        my_lang: z.string().optional(),
      }),
      messageDown: '打开实时字幕须本机 App 可达并确认；当前未检测到设备桥。云端不会开麦，也不会假装已接通听译。',
      messageUp: '打开实时字幕须在本机 App 确认；云端不会开麦，也不会假装已接通听译。',
      // BEL-151: bridge DOWN is an App-availability gap, not a microphone gap.
      step: 'install_app',
      actionDeeplink: true,
    },
    {
      name: 'translate_page',
      description:
        'Ask the on-device extension or App to translate the current page after the user confirms. The cloud does not read the page. App-only calls return need_ext. Optional url is a hint, not a fetch. Pass pending_id to replay/resume an existing confirmation.',
      inputSchema: z.object({
        ...COMMON,
        ...PENDING_ARGS,
        url: z.string().optional(),
      }),
      messageDown: '页译须本机扩展或 App 可达并确认；当前未检测到设备桥。云端不读当前页，也不会标为已成功译页。',
      messageUp: '页译须本机扩展或 App 确认后执行；云端不读当前页，也不会标为已成功译页。',
      step: 'install_ext',
    },
    {
      name: 'translate_video_captions',
      description:
        'Ask the on-device extension for in-page video captions after the user confirms. The cloud does not fetch the page. Unsupported sites return site_unsupported. Optional url is a hint, not a fetch. Pass pending_id to replay/resume an existing confirmation.',
      inputSchema: z.object({
        ...COMMON,
        ...PENDING_ARGS,
        url: z.string().optional(),
      }),
      messageDown: '视频字幕须本机扩展可达并确认；当前未检测到设备桥。云端不抓取页面，也不会标为已出字幕。',
      messageUp: '视频字幕须本机扩展确认后执行；云端不抓取页面，也不会标为已出字幕。',
      step: 'install_ext',
    },
    {
      name: 'capture_to_study',
      description:
        'Save a sentence to the study library after the user confirms on device. Requires text or quote (or a paste on the confirm card). The cloud does not write the library; the receipt does not echo the sentence. Pass pending_id to replay/resume an existing confirmation.',
      inputSchema: z.object({
        ...COMMON,
        ...PENDING_ARGS,
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
        'Explain or lightly drill a sentence after the user confirms on device. mode is explain or drill (default explain). The cloud does not parse the sentence; the receipt does not echo it. Pass pending_id to replay/resume an existing confirmation.',
      inputSchema: z.object({
        ...COMMON,
        ...PENDING_ARGS,
        text: z.string().optional(),
        quote: z.string().optional(),
        mode: z.enum(['explain', 'drill']).optional(),
      }),
      messageDown: '讲解或操练须本机 App 可达并确认；当前未检测到设备桥。云端不做解析，回执也不含句子正文。',
      messageUp: '讲解或操练须在本机确认；云端不做解析，回执也不含句子正文。',
      step: 'install_app',
    },
  ];

  function actionFix(
    t: (typeof sensitive)[number],
    bridge: BridgeView,
    input: Record<string, unknown>,
    caps: ClientCapsRecord | null,
    pendingId?: string,
  ): Record<string, string | number | boolean> {
    const fix: Record<string, string | number | boolean> = {
      ...bridgeFix(bridge),
      ...elicitProbeFix(caps),
    };
    if (pendingId) fix.pending_id = pendingId;
    if (t.actionDeeplink) {
      const link = actionLink(scheme, 'start_live_subtitles', {
        video_lang: typeof input.video_lang === 'string' ? input.video_lang : undefined,
        my_lang: typeof input.my_lang === 'string' ? input.my_lang : undefined,
        pending_id: pendingId,
      });
      // Historical key name kept for clients that read fix.open_setup; the
      // value is the action deep link with pending_id, never step=mic.
      fix.open_setup = link;
      fix.action = t.name;
      fix.action_deeplink = link;
    } else {
      fix.open_setup = setupLink(scheme, t.step);
    }
    return fix;
  }

  function cancelledReceipt(t: { name: string }, pendingId: string, message: string): Receipt {
    return receipt(t.name, 'cancelled', message, {
      pending_id: pendingId,
      micStarted: false,
      openedSubtitles: false,
    });
  }

  for (const t of sensitive) {
    server.registerTool(
      t.name,
      { description: t.description, inputSchema: t.inputSchema },
      async (args: unknown, ctx: unknown) => {
        const input = (args && typeof args === 'object' ? args : {}) as Record<string, unknown>;
        const sub = props.userId;
        const bridge = await getFreshBridge(env, sub);
        const caps = await getClientCaps(env, sub);
        if (!bridge.up) {
          // Bridge DOWN → this device cannot execute; invalidate its pending set.
          if (sub) {
            try {
              await revokeAllPending(env, sub);
            } catch {
              /* best effort; never fake success */
            }
          }
          return mcpText(
            receipt(t.name, 'need_app', t.messageDown, {
              open_setup: setupLink(scheme, t.step),
              gap: 'need_app',
              ...elicitProbeFix(caps),
            }),
          );
        }
        if (sub) {
          try {
            await gcPending(env, sub);
          } catch {
            /* GC is opportunistic */
          }
        }

        // Replay/resume by pending id (same call semantics for the same action).
        const pendingArg = typeof input.pending_id === 'string' ? input.pending_id : undefined;
        if (pendingArg && sub) {
          const existing = await getPending(env, sub, pendingArg);
          if (!existing) {
            return mcpText(
              receipt(t.name, 'bad_request', '未找到该确认（可能已过期或被作废），请重新发起。', {
                pending_id: pendingArg,
                ...elicitProbeFix(caps),
              }),
            );
          }
          if (existing.action !== t.name) {
            return mcpText(
              receipt(t.name, 'bad_request', '确认编号与当前动作不匹配。', {
                pending_id: pendingArg,
                ...elicitProbeFix(caps),
              }),
            );
          }
          if (existing.status === 'allowed') {
            return mcpText(existing.result ?? buildResumeReceipt(existing));
          }
          if (existing.status === 'denied') {
            return mcpText(cancelledReceipt(t, existing.pending_id, '该确认已拒绝：未执行，未开麦。'));
          }
          if (existing.status === 'revoked') {
            return mcpText(cancelledReceipt(t, existing.pending_id, '该确认已作废（设备断开或桥不可达）：未执行，未开麦。'));
          }
          if (existing.status === 'pending') {
            return mcpText(
              receipt(t.name, 'need_confirm', t.messageUp, actionFix(t, bridge, input, caps, existing.pending_id)),
            );
          }
          // expired → fall through and create a fresh pending
        }

        const pending: PendingRecord | null =
          sub && bridge.device_id
            ? await createPending(env, {
                oauth_sub: sub,
                device_id: bridge.device_id,
                action: t.name,
                args: input,
              })
            : null;

        // A (conditional): only when initialize explicitly declared elicitation.
        // This slice treats it as a confirmation channel only; it does NOT claim
        // the local subtitle surface was opened.
        if (pending && caps?.has_elicitation && t.name === 'start_live_subtitles') {
          const elicit = (ctx as ElicitCtx | undefined)?.mcpReq?.elicitInput;
          if (typeof elicit === 'function') {
            try {
              const res = await elicit({
                message: '是否允许这次打开实时字幕表面？只开字幕，不开麦。',
                requestedSchema: {
                  type: 'object',
                  properties: {
                    confirm: { type: 'boolean', title: '允许这一次', default: true },
                  },
                  required: ['confirm'],
                },
              });
              if (res?.action === 'accept' && res?.content?.confirm === true) {
                const decided = await decidePending(env, {
                  oauth_sub: sub as string,
                  pending_id: pending.pending_id,
                  device_id: bridge.device_id as string,
                  decision: 'allow',
                });
                if (decided.ok) {
                  return mcpText(await markElicitConfirmed(env, decided.record));
                }
              }
              if (res?.action === 'decline' || res?.action === 'cancel') {
                await decidePending(env, {
                  oauth_sub: sub as string,
                  pending_id: pending.pending_id,
                  device_id: bridge.device_id as string,
                  decision: 'deny',
                });
                return mcpText(cancelledReceipt(t, pending.pending_id, '已取消：未执行，未开麦。'));
              }
            } catch {
              /* A failed → honest B fallback below */
            }
          }
        }

        // Same-call resume: optional bounded wait for the App callback.
        const waitRaw = Number(input.wait_sec);
        const waitSec = Number.isFinite(waitRaw) ? Math.max(0, Math.min(25, Math.floor(waitRaw))) : 0;
        if (pending && sub && waitSec > 0) {
          const deadline = Date.now() + waitSec * 1000;
          while (Date.now() < deadline) {
            await new Promise((r) => setTimeout(r, 400));
            const rec = await getPending(env, sub, pending.pending_id);
            if (!rec) break;
            if (rec.status === 'allowed') {
              return mcpText(rec.result ?? buildResumeReceipt(rec));
            }
            if (rec.status === 'denied' || rec.status === 'revoked') {
              return mcpText(cancelledReceipt(t, pending.pending_id, '已取消：未执行，未开麦。'));
            }
            if (rec.status === 'expired') break;
          }
        }

        // B: honest need_confirm + action deep link carrying pending_id.
        return mcpText(
          receipt(
            t.name,
            'need_confirm',
            t.messageUp,
            actionFix(t, bridge, input, caps, pending?.pending_id),
          ),
        );
      },
    );
  }

  // Sanity: exactly seven names registered
  void ACTIONS;
}
