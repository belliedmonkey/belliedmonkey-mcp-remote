/** W2 §5 receipt + §6 codes — Remote P1-a (no local app bridge). */

export const ACTIONS = [
  'ready.check',
  'open_setup',
  'start_live_subtitles',
  'translate_page',
  'translate_video_captions',
  'capture_to_study',
  'explain_or_drill',
] as const;

export type Action = (typeof ACTIONS)[number];

export const SENSITIVE = new Set<Action>([
  'start_live_subtitles',
  'translate_page',
  'translate_video_captions',
  'capture_to_study',
  'explain_or_drill',
]);

export const CODES = [
  'ok',
  'need_confirm',
  'cancelled',
  'unsupported_action',
  'bad_request',
  'untrusted_denied',
  'need_app',
  'need_ext',
  'need_login',
  'need_packs',
  'need_engine',
  'need_os',
  'need_permission_mic',
  'site_unsupported',
  'quota_or_key',
  'study_capture_off',
] as const;

export type Code = (typeof CODES)[number];

const CODE_SET = new Set<string>(CODES);

export const SETUP_STEPS = [
  'install_app',
  'install_ext',
  'login',
  'packs',
  'mic',
  'engine',
] as const;

export type SetupStep = (typeof SETUP_STEPS)[number];

export type Flavor = 'china' | 'intl';

export function schemeForFlavor(flavor: Flavor): string {
  return flavor === 'china' ? 'belliedmonkeycn' : 'belliedmonkey';
}

export function flavorFromHost(hostname: string, headers?: Headers): Flavor {
  const h = (hostname || '').toLowerCase();
  const xf = (headers?.get('x-forwarded-host') || '').toLowerCase();
  const flavorHdr = (headers?.get('x-bm-flavor') || '').toLowerCase();
  // BEL-151 A2: EdgeOne/Lighthouse mid host mcp-china.*.cc + X-Forwarded-Host=.com
  if (
    flavorHdr === 'china' ||
    xf === 'mcp.belliedmonkey.com' ||
    xf.endsWith('.belliedmonkey.com') ||
    h === 'mcp.belliedmonkey.com' ||
    h.endsWith('.belliedmonkey.com') ||
    h === 'mcp-china.belliedmonkey.cc' ||
    h.startsWith('mcp-china.')
  ) {
    return 'china';
  }
  return 'intl';
}

export function setupLink(scheme: string, step: SetupStep, source = 'mcp'): string {
  const q = new URLSearchParams({ step, source });
  return `${scheme}://agent/v1/open_setup?${q.toString()}`;
}

function newId(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return `agt_${hex}`;
}

export type Receipt = {
  ok: boolean;
  action: string;
  code: Code;
  message: string;
  fix: Record<string, string>;
  receipt_id: string;
};

export function receipt(
  action: string,
  code: Code,
  message: string,
  fix: Record<string, string> = {},
): Receipt {
  if (!CODE_SET.has(code)) {
    throw new Error(`failure code outside §6: ${code}`);
  }
  return {
    ok: code === 'ok',
    action: action || '',
    code,
    message: message || '',
    fix: fix && typeof fix === 'object' ? fix : {},
    receipt_id: newId(),
  };
}

export function mcpText(rec: Receipt) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(rec) }],
    // Business failures stay isError:false; failure lives in receipt.code
  };
}
