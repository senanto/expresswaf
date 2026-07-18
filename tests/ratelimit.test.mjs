import express from 'express';
import { createWaf } from '../dist/index.mjs';

const instance = createWaf({ ipFilter: { whitelist: [], blacklist: ['10.10.10.0/24'], blockedCountries: [] } });
const app = express();
app.use(instance.middleware());
app.use(instance.rateLimit({ windowMs: 2000, max: 3, algorithm: 'sliding-window' }));
app.get('/', (req, res) => res.json({ ok: true }));

const server = app.listen(0, async () => {
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;
  const statuses = [];
  for (let i = 0; i < 5; i++) {
    const r = await fetch(base + '/', { headers: { 'user-agent': 'Mozilla/5.0' } });
    statuses.push(r.status);
  }
  console.log('rate limit sequence (expect 200,200,200,429,429):', statuses.join(','));
  instance.banList.ban('127.0.0.1', 3000);
  const banned = await fetch(base + '/', { headers: { 'user-agent': 'Mozilla/5.0' } });
  console.log('after dynamic ban status (expect 403):', banned.status);
  server.close();
});
