import express from 'express';
import { createWaf } from '@expresswaf/expresswaf';

const app = express();
app.use(express.json({ limit: '1mb' }));

const instance = createWaf({
  mode: 'block',
  riskThresholdBlock: 70,
  riskThresholdChallenge: 40,
  ipFilter: { whitelist: [], blacklist: ['203.0.113.0/24'], blockedCountries: [] },
  rateLimit: { enabled: true, store: 'redis', redisUrl: process.env.REDIS_URL, global: { windowMs: 60000, max: 300 }, routes: [] }
});

await instance.loadConfigFile('./waf.config.yaml');

instance.use({
  name: 'audit-logger',
  onThreat(event) {
    console.log(`[waf] ${event.category}/${event.rule} risk=${event.riskScore} ip=${event.ip}`);
  }
});

app.use(instance.middleware());
app.use('/api', instance.rateLimit({ windowMs: 60000, max: 120, algorithm: 'token-bucket' }));

app.get('/', (req, res) => res.json({ ok: true }));
app.listen(3000);
