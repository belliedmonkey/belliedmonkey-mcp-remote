# BelliedMonkey Remote MCP (BEL-151 P1-a)

Public Streamable HTTP MCP for [大肚猴翻译](https://belliedmonkey.cc) / [China site](https://belliedmonkey.com).

| Flavor | MCP URL |
| --- | --- |
| intl | `https://mcp.belliedmonkey.cc/mcp/v1` |
| china | `https://mcp.belliedmonkey.com/mcp/v1` (DNS may lag; same Worker code) |

## What this is

- OAuth (Cloudflare Workers OAuth Provider) → Grok / MCP clients show **已连接**
- Seven W2 tools (same schema as local stdio): `ready.check`, `open_setup`, `start_live_subtitles`, `translate_page`, `translate_video_captions`, `capture_to_study`, `explain_or_drill`
- Cloud side **orchestrates only**. Page translate / live subtitles / mic side effects stay on the **local App or extension**. Sensitive tools return `need_confirm` / `need_app` + `fix.open_setup` deeplink.

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

Linear: BEL-151 · do not Done until product VERIFY.
