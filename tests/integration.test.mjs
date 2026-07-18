import express from 'express';
import { waf } from '../dist/index.mjs';

const app = express();
app.use(express.json());
app.use(waf({ mode: 'block', botDetection: { enabled: true, blockHeadless: true, challengeSuspicious: false } }));
app.get('/', (req, res) => res.json({ ok: true }));
app.post('/search', (req, res) => res.json({ ok: true }));

const server = app.listen(0, async () => {
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;

  const legit = await fetch(base + '/', { headers: { 'user-agent': 'Mozilla/5.0', 'accept-language': 'en' } });
  console.log('legit request status:', legit.status);

  const sqli = await fetch(base + `/?id=1' UNION SELECT username,password FROM users--`, {
    headers: { 'user-agent': 'Mozilla/5.0' }
  });
  console.log('sqli request status:', sqli.status);

  const xss = await fetch(base + '/', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'user-agent': 'Mozilla/5.0' },
    body: JSON.stringify({ comment: '<script>alert(document.cookie)</script>' })
  });
  console.log('xss request status:', xss.status);

  const ssrf = await fetch(base + '/', {
    headers: { 'user-agent': 'Mozilla/5.0', 'x-url': 'http://169.254.169.254/latest/meta-data/' }
  });
  console.log('ssrf-metadata request status:', ssrf.status);

  const traversal = await fetch(base + '/?file=' + encodeURIComponent('../../../../etc/passwd'), {
    headers: { 'user-agent': 'Mozilla/5.0' }
  });
  console.log('path-traversal request status:', traversal.status);

  const botReq = await fetch(base + '/', { headers: { 'user-agent': 'python-requests/2.31' } });
  console.log('automation-ua request status:', botReq.status);

  const headerCheck = await fetch(base + '/', { headers: { 'user-agent': 'Mozilla/5.0' } });
  console.log('security headers:', {
    hsts: headerCheck.headers.get('strict-transport-security'),
    csp: headerCheck.headers.get('content-security-policy'),
    xfo: headerCheck.headers.get('x-frame-options'),
    xcto: headerCheck.headers.get('x-content-type-options')
  });

  server.close();
});
