# @expresswaf/expresswaf

> Bu depo bir kaynak dağıtımıdır. Kullanmadan önce: `npm install && npm run build` (bağımlılıklar `dependencies` alanında tanımlıdır; `dist/` klasörü npm publish sırasında otomatik oluşturulur, bu zip'te de örnek olarak build edilmiş haliyle bulunur ama `node_modules` dahil değildir).

Express 4.x/5.x için modüler, event-driven, TypeScript ile yazılmış Web Application Firewall middleware'i. CommonJS ve ESM olarak yayınlanır (`tsup` ile derlenir), tip tanımları dahildir.

```bash
npm install @expresswaf/expresswaf
```

## Hızlı başlangıç

```js
const { waf } = require('@expresswaf/expresswaf');
app.use(waf());
```

```ts
import { waf } from '@expresswaf/expresswaf';
app.use(waf({ mode: 'block', riskThresholdBlock: 70 }));
```

## Gelişmiş kullanım

```ts
import { createWaf } from '@expresswaf/expresswaf';

const instance = createWaf({ mode: 'block' });
await instance.loadConfigFile('./waf.config.yaml'); // json | yaml | js destekler, hotReload: true ile fs.watch üzerinden canlı yeniden yükleme yapar

instance.use({
  name: 'slack-notifier',
  onThreat(event) { /* event.category, event.rule, event.riskScore, event.ip */ }
});

app.use(instance.middleware());
app.use('/api', instance.rateLimit({ windowMs: 60_000, max: 120, algorithm: 'token-bucket' }));
```

Config; `ENV` değişkenleriyle de override edilebilir: `WAF_MODE`, `WAF_RISK_BLOCK`, `WAF_RISK_CHALLENGE`, `WAF_RATE_LIMIT_MAX`, `WAF_REDIS_URL`.

## Neyi tespit ediyor?

Regex + normalizasyon (URL decode, HTML entity decode) tabanlı imza motoru; kural bazlı, dürüst bir yaklaşımdır — "AST tabanlı SQL ayrıştırma" ya da "gerçek ML anomali tespiti" gibi iddialar içermez:

- **SQL Injection**: union/boolean/error/time-based/stacked queries, hex encoding, information_schema erişimi, yorum satırı evasion
- **XSS**: script tag, event handler, javascript: URI, SVG vektörü, HTML entity evasion, DOM sink (`innerHTML`, `eval`), CSS expression
- **Command Injection**: shell metakarakter zincirleri, komut ikamesi (`` `cmd` ``, `$()`), pipe-to-shell
- **NoSQL Injection**: `$where`, `$ne`, `$regex` vb. operatör tespiti
- **Prototype Pollution**: `__proto__`, `constructor`, `prototype` anahtar tespiti + `stripPollutedKeys()` yardımcı fonksiyonu
- **Path Traversal / LFI-RFI**: `../` zincirleri, tek/çift encoding, null byte, hassas dosya yolları
- **SSRF**: private IP aralıkları (RFC1918), `169.254.169.254` (AWS/Alibaba), `metadata.google.internal` (GCP), `localhost`/`.internal`/`.local` host adları, opsiyonel allowlist
- **CRLF / Header Injection**: ham ve encoded `\r\n`, header smuggling örüntüleri
- **HTTP Parameter Pollution**: tekrarlanan query parametreleri
- **Güvenlik başlıkları**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, `X-Powered-By` kaldırma

## Bot tespiti

`analyzeBotSignals()` User-Agent imzaları (headless Chrome, Selenium, Puppeteer, Playwright, curl, python-requests vb.), eksik `Accept-Language`, eksik `Sec-Fetch-*`/client-hints tutarsızlığı gibi **HTTP katmanı heuristikleri** kullanır. Ayrıca cookie tabanlı ve tarayıcıda SHA-256 proof-of-work çözen bir JS challenge (`ChallengeManager`) içerir.

Bunlar **gerçek TLS/JA3 parmak izi değildir** — JA3, Express/Node HTTP katmanından değil, TLS handshake'ini gören ham soket/proxy katmanından (ör. Nginx/Envoy modülü) okunur. Canvas/WebGL/Audio/Font fingerprint gibi istemci taraflı sinyaller de tarayıcıda çalışan ayrı bir script gerektirir; bu paket sunucu tarafı bir middleware olduğundan bu sinyalleri kendi başına toplayamaz. `Plugin` arayüzü üzerinden böyle bir istemci-taraflı fingerprint script'inin sonucunu (`X-Client-Fingerprint` header'ı gibi) besleyebilirsiniz.

## Rate limiting

`RateLimiter`, sliding-window (sayaç + TTL) ve token-bucket algoritmalarını destekler. Varsayılan store bellek içidir (`MemoryStore`); `rateLimit.store: 'redis'` ile `ioredis` üzerinden dağıtık sayaç kullanılır (opsiyonel bağımlılık — kurulu değilse otomatik olarak belleğe düşer).

## IP filtreleme

`ipFilterMiddleware` CIDR destekli whitelist/blacklist uygular (`ip-cidr`). `DynamicBanList` çalışma zamanında geçici/kalıcı IP banı için kullanılır: `instance.banList.ban(ip, ms)`.

## Plugin / hook sistemi

```ts
interface Plugin {
  name: string;
  onInit?(ctx: PluginContext): void;
  onRequest?(req, res, ctx): 'block' | 'challenge' | 'allow' | void;
  onThreat?(event: ThreatEvent, ctx: PluginContext): void;
}
```

`instance.bus` bir `EventEmitter`'dır; `threat`, `block`, `challenge`, `config:reload`, `request:start` olaylarını dinleyebilirsiniz — Slack/Discord/webhook/SIEM entegrasyonlarını bu olaylara bağlı basit bir plugin olarak yazmanız beklenir (ör. `onThreat` içinde `fetch(webhookUrl, ...)`). Paket bu entegrasyonların HTTP client'ını hazır vermez; dış servis sözleşmeleri (Slack webhook formatı, Elastic bulk API vb.) sık değiştiği için bunları sabit kod olarak gömmek yerine hook üzerinden size bırakılmıştır.

## Test

```bash
npm run build
node tests/integration.test.mjs   # SQLi/XSS/SSRF/path-traversal blok testleri
node tests/ratelimit.test.mjs     # sliding-window rate limit + dynamic ban
```
