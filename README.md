# claw-proxy

A local proxy that lets any Anthropic API client (**claw-code**, **opencode**,
etc.) talk to the Anthropic API using a Claude Code OAuth subscription token, by
impersonating the official Claude Code CLI closely enough that Anthropic accepts
the traffic.

Third-party clients send an `x-api-key` and a bare-string `system` prompt. The
official CLI sends an OAuth Bearer token and a multi-block `system` prompt.
Anthropic rejects requests that don't look like the official CLI with **HTTP
429**. This proxy rewrites the client's requests to match the official client,
forwarding them to `api.anthropic.com`.

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
- TitleCase-remap tool names (`bash`→`Bash`) on the request and reverse it
  per-frame in the response (only the frames that need it).
- Auto-inject `cache_control`, cap it at Anthropic's 4-breakpoint limit,
  normalize TTL ordering, normalize thinking, and restore the model name in the
  response.
- Strip empty `web_search` domain lists; supply a `max_tokens` fallback.
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

Point the client's Anthropic base URL at `http://127.0.0.1:8787`. Listens on
`127.0.0.1:8787`, forwards to `api.anthropic.com`. The `apiKey` the client sends
is ignored — the proxy substitutes your OAuth token — so any placeholder works.

### opencode

`~/.config/opencode/opencode.json` (Windows: `C:\Users\<you>\.config\opencode\opencode.json`):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "claude-proxy": {
      "npm": "@ai-sdk/anthropic",
      "name": "Claude via local proxy",
      "api": "http://127.0.0.1:8787/v1",
      "options": {
        "baseURL": "http://127.0.0.1:8787/v1",
        "apiKey": "placeholder"
      },
      "models": {
        "claude-opus-4-8": {
          "name": "Claude Opus 4.8",
          "tool_call": true,
          "attachment": true,
          "reasoning": true,
          "limit": { "context": 1000000, "output": 128000 }
        }
      }
    }
  }
}
```

## Env vars

| Variable | Default | Purpose |
|---|---|---|
| `CLAUDE_CODE_OAUTH_TOKEN` | _(required)_ | OAuth Bearer token. |
| `CLAW_PROXY_HOST` | `127.0.0.1` | Listen address. |
| `CLAW_PROXY_PORT` | `8787` | Listen port. |
| `CLAW_PROXY_MODEL` | _(unset = none)_ | Force a model on every request. |
| `CLAW_PROXY_UPSTREAM_PROXY` | _(unset)_ | Upstream HTTP/HTTPS proxy for the connection to Anthropic, e.g. `http://127.0.0.1:7890` or `http://user:pass@host:port`. Falls back to `HTTPS_PROXY` / `https_proxy`. |

For personal use with your own Claude Code subscription, on localhost.
