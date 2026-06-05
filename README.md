# delegated-http-proxy

A tiny signed HTTP fetch service for edge runtimes that cannot use normal
HTTP/SOCKS proxies or need better control over TLS, cookies, POST bodies, and
upstream proxy selection.

It is designed for Cloudflare Workers-style callers: send a JSON RPC request to
`/v1/fetch`, and the service performs the delegated HTTP/S request with a normal
server-side client.

## Features

- Signed bearer-token access.
- GET/POST/any HTTP method supported by `reqwest`.
- Base64 or text request bodies.
- Per-request headers.
- Server-side named cookie jars for stateful portal flows.
- Direct fetches or caller-supplied upstream HTTP/SOCKS proxy URLs.
- Host allowlist and private-IP blocking to reduce SSRF risk.
- Concurrent fetch cap and streaming response body limit.
- Optional per-request invalid-cert escape hatch for broken public portals.
- MIT licensed.

## Run

```bash
DELEGATED_HTTP_TOKEN=dev-token \
ALLOW_HOSTS=development.towerhamlets.gov.uk,planning.lambeth.gov.uk \
cargo run
```

Health check:

```bash
curl http://127.0.0.1:8080/healthz
```

Delegated fetch:

```bash
curl -sS http://127.0.0.1:8080/v1/fetch \
  -H 'authorization: Bearer dev-token' \
  -H 'content-type: application/json' \
  -d '{
    "url": "https://development.towerhamlets.gov.uk/online-applications/search.do?action=advanced&searchType=Enforcement",
    "method": "GET",
    "cookie_jar": "tower"
  }'
```

The response body is base64 encoded:

```json
{
  "status": 200,
  "final_url": "https://example.com/",
  "headers": {},
  "set_cookies": [],
  "body_base64": "...",
  "elapsed_ms": 123,
  "proxy_used": null,
  "body_sha256": "..."
}
```

## Stateful POST Example

1. Fetch a form with `cookie_jar`.
2. Parse the returned HTML and CSRF token in the caller.
3. POST the form with the same `cookie_jar`.

```json
{
  "url": "https://example.gov/advancedSearchResults.do?action=firstPage",
  "method": "POST",
  "headers": {
    "content-type": "application/x-www-form-urlencoded",
    "referer": "https://example.gov/search.do?action=advanced"
  },
  "body_text": "_csrf=...&searchType=Enforcement",
  "cookie_jar": "example-source"
}
```

## Broken TLS Chains

Some public portals serve incomplete or otherwise broken certificate chains.
Keep verification on by default. For recon targets that need it, opt the service
in and request it per call:

```bash
ALLOW_INVALID_CERTS=true cargo run
```

```json
{
  "url": "https://example.gov/",
  "danger_accept_invalid_certs": true
}
```

## Upstream Proxy

Pass upstream proxy credentials with the request:

```json
{
  "url": "https://example.gov/",
  "proxy_url": "http://user:pass@host:port"
}
```

The older `proxy` object shape is also accepted:

```json
{ "proxy": "direct" }
{ "proxy": { "url": "http://user:pass@host:port" } }
```

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `BIND` | `0.0.0.0:8080` | Listen address |
| `DELEGATED_HTTP_TOKEN` | required | Bearer token |
| `ALLOW_HOSTS` | unset | Comma-separated host allowlist |
| `DENY_PRIVATE_IPS` | `true` | Block private/link-local/loopback resolved IPs |
| `ALLOW_INVALID_CERTS` | `false` | Permit per-request `danger_accept_invalid_certs` |
| `MAX_BODY_BYTES` | `10485760` | Max request and response body size |
| `MAX_RPC_BYTES` | `10489856` | Max JSON RPC request size |
| `MAX_CONCURRENT_REQUESTS` | `64` | Max simultaneous delegated upstream fetches |
| `DEFAULT_TIMEOUT_MS` | `45000` | Upstream request timeout |

## Fly

```bash
fly launch --name delegated-http-proxy
fly secrets set DELEGATED_HTTP_TOKEN=...
fly deploy
```

See `Dockerfile` for the tiny runtime image.

For the DirtSignal Fly deployment that scales to zero:

```bash
fly apps create dirtsignal-delegated-proxy
fly secrets set DELEGATED_HTTP_TOKEN=...
fly deploy -c fly-proxy.toml
```
