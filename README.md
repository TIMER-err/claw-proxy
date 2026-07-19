# claw-proxy

A local proxy that lets **claw-code** talk to the Anthropic API using a Claude
Code OAuth subscription token, by impersonating the official Claude Code CLI
closely enough that Anthropic accepts the traffic.

claw-code sends an `x-api-key` and a bare-string `system` prompt. The official
CLI sends an OAuth Bearer token and a multi-block `system` prompt. Anthropic
rejects requests that don't look like the official CLI with **HTTP 429**. This
proxy rewrites claw's requests to match the official client, forwarding them to
`api.anthropic.com`.

The transformations mirror the Claude Code "cloaking" in
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI), reduced to two
dependency-free Python files.

## What it does

- Swap `x-api-key` for `Authorization: Bearer <token>`.
- Replace `system` with three blocks: a billing header (with fingerprint + CCH
  xxHash64 signature), the identity line `You are Claude Code, Anthropic's
  official CLI for Claude.`, and the official Claude Code system prompt.
- Move the original system into the first user message (neutralized in OAuth
  mode).
- Inject `metadata.user_id` and the official headers / beta set /
  `x-stainless-*` / session-id / request-id.
- TitleCase-remap tool names (`bash`→`Bash`) on the request and reverse it in
  the response.
- Auto-inject `cache_control`, normalize thinking, restore the model name in
  the response.
- Strip inference-only fields on `/v1/messages/count_tokens`.

## Files

- `proxy.py` — the proxy.
- `xxh64.py` — pure-Python XXH64 for CCH signing; self-tests against the
  `xxhash` library when run directly.

## Usage

```sh
export CLAUDE_CODE_OAUTH_TOKEN="sk-ant-oat01-..."
python proxy.py
```

Point claw-code's Anthropic base URL at `http://127.0.0.1:8787`. Listens on
`127.0.0.1:8787`, forwards to `api.anthropic.com`.

## Env vars

| Variable | Default | Purpose |
|---|---|---|
| `CLAUDE_CODE_OAUTH_TOKEN` | _(required)_ | OAuth Bearer token. |
| `CLAW_PROXY_HOST` | `127.0.0.1` | Listen address. |
| `CLAW_PROXY_PORT` | `8787` | Listen port. |
| `CLAW_PROXY_MODEL` | _(unset = none)_ | Force a model on every request. |
| `CLAW_PROXY_TRACE` | `claw-request-trace.jsonl` | Sanitized request/response trace; empty to disable. |

For personal use with your own Claude Code subscription, on localhost.
