# BelliedMonkey Remote MCP (BEL-151 P1-a)

Public Streamable HTTP MCP for [大肚猴翻译](https://belliedmonkey.cc) / [China site](https://belliedmonkey.com).

| Flavor | MCP URL |
| --- | --- |
| intl | `https://mcp.belliedmonkey.cc/mcp/v1` |
| china | `https://mcp.belliedmonkey.com/mcp/v1` (DNS may lag; same Worker code) |

## What this is

- OAuth (Cloudflare Workers OAuth Provider) → Grok / MCP clients show **已连接**
- Seven W2 tools (same schema as local stdio): `ready.check`, `open_setup`, `start_live_subtitles`, `translate_page`, `translate_video_captions`, `capture_to_study`, `explain_or_drill`
- Cloud side **orchestrates only**. Page translate / live subtitles / mic side effects stay on the **local App or extension**. Sensitive tools return `need_confirm` / `need_app` + a deeplink.
  - `start_live_subtitles` `need_confirm` uses the **action deep link** `belliedmonkey://agent/v1/start_live_subtitles?source=mcp&video_lang=…&my_lang=…&pending_id=…` (CN: `belliedmonkeycn://…`) in `fix.action_deeplink` and, for compatibility, in `fix.open_setup`. It is **never** `open_setup?step=mic`.
  - Other sensitive tools keep `fix.open_setup` pointing at their setup step.

## GAP-2 pending confirm (B path)

- Bridge UP sensitive call creates a **120s** `pending_confirm` bound to `oauth_sub` + `device_id` and returns honest `need_confirm` with `fix.pending_id` in the action deep link.
- App callback: `POST /api/mcp/device-sessions/confirm` with Bearer OAuth + `{pending_id, decision: allow|deny, device_id, device_cred}`.
  - allow → `resumed.openedSubtitles=true`, `resumed.micStarted=false` (subtitle surface only; never opens the mic)
  - deny → `cancelled` (no side effects)
  - cross-account/device → 403; unknown → 404; expired/revoked → 410; conflicting re-decision → 409
- Same-call resume: the confirm response carries the resumed receipt; replaying the tool with the same `pending_id` returns the same `receipt_id`; optional `wait_sec` (≤25) waits inside the call for the callback.
- `revoke` / bridge DOWN invalidates that device's still-pending records.
- ACCEPT-PROBE: `initialize.capabilities` is recorded; `elicitation/create` is attempted **only** when `capabilities.elicitation` is declared. No record → A is never claimed as the positive path. This slice's A is a confirmation channel only; it does not claim the local surface opened.

```bash
npm run test:confirm   # pending store + /confirm matrix (mock KV)
npm run test:tools     # real tool handlers: need_confirm/replay/wait/A-gate/negative
```


## What this is not

- Not a claim that listen-translate already works inside the chat
- Not localhost / stdio pretending to be the user’s machine
- Not App Store Submit / PPO

## Connect (Grok)

1. Open Connect Apps / Add connector
2. Paste `https://mcp.belliedmonkey.cc/mcp/v1`
3. Complete OAuth (email consent on `/authorize`)
4. Call `ready.check` / `open_setup`

## Develop

```bash
npm install
npx wrangler kv namespace create OAUTH_KV
# put id into wrangler.jsonc
npm run deploy
MCP_URL=https://mcp.belliedmonkey.cc/mcp/v1 npm run verify
```

Linear: BEL-151 · do not Done until product VERIFY. GAP-2 pending/confirm does **not** by itself prove “subtitle surface via Grok”; the real-Grok VERIFY 1–5 is a separate order.
