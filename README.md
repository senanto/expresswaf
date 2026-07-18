# @expresswaf/expresswaf

> This repository is a source distribution. Before using it, run: `npm install && npm run build` (dependencies are defined in the `dependencies` field; the `dist/` folder is generated automatically during `npm publish`, and is included in this zip as a pre-built example, but `node_modules` is not included).

A modular, event-driven Web Application Firewall middleware written in TypeScript for Express 4.x/5.x. Published as both CommonJS and ESM (compiled with `tsup`), with type definitions included.

```bash
npm install @expresswaf/expresswaf
```

## Quick start

```js
const { waf } = require('@expresswaf/expresswaf');
app.use(waf());
```

```ts
import { waf } from '@expresswaf/expresswaf';
app.use(waf({ mode: 'block', riskThresholdBlock: 70 }));
```

## Advanced usage

```ts
import { createWaf } from '@expresswaf/expresswaf';

const instance = createWaf({ mode: 'block' });
await instance.loadConfigFile('./waf.config.yaml'); // supports json | yaml | js, hotReload: true enables live reloading via fs.watch

instance.use({
  name: 'slack-notifier',
  onThreat(event) { /* event.category, event.rule, event.riskScore, event.ip */ }
});

app.use(instance.middleware());
app.use('/api', instance.rateLimit({ windowMs: 60_000, max: 120, algorithm: 'token-bucket' }));
```

Config can also be overridden via `ENV` variables: `WAF_MODE`, `WAF_RISK_BLOCK`, `WAF_RISK_CHALLENGE`, `WAF_RATE_LIMIT_MAX`, `WAF_REDIS_URL`.

## What it actually detects

A regex + normalization (URL decode, HTML entity decode) based signature engine; a rule-based, honest approach — it does not make claims like "AST-based SQL parsing" or "real ML anomaly detection":

- **SQL Injection**: union/boolean/error/time-based/stacked queries, hex encoding, information_schema access, comment-based evasion
- **XSS**: script tags, event handlers, javascript: URIs, SVG vectors, HTML entity evasion, DOM sinks (`innerHTML`, `eval`), CSS expressions
- **Command Injection**: shell metacharacter chains, command substitution (`` `cmd` ``, `$()`), pipe-to-shell
- **NoSQL Injection**: detection of `$where`, `$ne`, `$regex`, etc. operators
- **Prototype Pollution**: detection of `__proto__`, `constructor`, `prototype` keys + `stripPollutedKeys()` helper function
- **Path Traversal / LFI-RFI**: `../` chains, single/double encoding, null bytes, sensitive file paths
- **SSRF**: private IP ranges (RFC1918), `169.254.169.254` (AWS/Alibaba), `metadata.google.internal` (GCP), `localhost`/`.internal`/`.local` hostnames, optional allowlist
- **CRLF / Header Injection**: raw and encoded `
`, header smuggling patterns
- **HTTP Parameter Pollution**: repeated query parameters
- **Security headers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, removal of `X-Powered-By`

## Bot detection

`analyzeBotSignals()` uses **HTTP-layer heuristics** such as User-Agent signatures (headless Chrome, Selenium, Puppeteer, Playwright, curl, python-requests, etc.), missing `Accept-Language`, and missing/inconsistent `Sec-Fetch-*`/client-hints. It also includes a cookie-based JS challenge (`ChallengeManager`) that solves a SHA-256 proof-of-work in the browser.

These are **not real TLS/JA3 fingerprints** — JA3 is read from the raw socket/proxy layer that sees the TLS handshake (e.g., Nginx/Envoy module), not from the Express/Node HTTP layer. Client-side signals like Canvas/WebGL/Audio/Font fingerprinting also require a separate script running in the browser; since this package is a server-side middleware, it cannot collect those signals on its own. You can feed the result of such a client-side fingerprinting script (e.g., via an `X-Client-Fingerprint` header) through the `Plugin` interface.

## Rate limiting

`RateLimiter` supports sliding-window (counter + TTL) and token-bucket algorithms. The default store is in-memory (`MemoryStore`); with `rateLimit.store: 'redis'`, a distributed counter is used via `ioredis` (optional dependency — falls back to memory automatically if not installed).

## IP filtering

`ipFilterMiddleware` applies CIDR-supported whitelist/blacklist (`ip-cidr`). `DynamicBanList` is used for temporary/permanent IP bans at runtime: `instance.banList.ban(ip, ms)`.

## Plugin / hook system

```ts
interface Plugin {
  name: string;
  onInit?(ctx: PluginContext): void;
  onRequest?(req, res, ctx): 'block' | 'challenge' | 'allow' | void;
  onThreat?(event: ThreatEvent, ctx: PluginContext): void;
}
```

`instance.bus` is an `EventEmitter`; you can listen to `threat`, `block`, `challenge`, `config:reload`, and `request:start` events — Slack/Discord/webhook/SIEM integrations are expected to be written as simple plugins attached to these events (e.g., `fetch(webhookUrl, ...)` inside `onThreat`). The package does not provide a ready-made HTTP client for these integrations; external service contracts (Slack webhook format, Elastic bulk API, etc.) change frequently, so they are left to you via hooks instead of being hard-coded.

## Out of scope

The following are not architecturally incompatible with this package, but a real implementation requires external services/infrastructure and is not falsely presented here as "working":

- JA3/TLS fingerprint → requires access to the raw TLS layer (Nginx/Envoy/Node `tls` socket)
- GeoIP / ASN / IP reputation → requires a licensed database like MaxMind GeoLite2 or a paid API
- Real ML-based anomaly detection → requires training data and model serving; you can plug in your own model via the `Plugin.onRequest` hook
- Cluster/worker_threads → this is an Express middleware; your application determines the process topology (each worker creates its own `Waf` instance alongside `cluster.fork()`; use a Redis store for shared state)
- Fastify adapter → the `Waf` class is not tied to Express (only the `middleware()` method expects `req/res/next`); the same `DetectorEngine`/`RiskEngine` APIs can be reused in a Fastify `onRequest` hook, but a ready-made adapter is not packaged today

## Tests

```bash
npm run build
node tests/integration.test.mjs   # SQLi/XSS/SSRF/path-traversal block tests
node tests/ratelimit.test.mjs     # sliding-window rate limit + dynamic ban
```
