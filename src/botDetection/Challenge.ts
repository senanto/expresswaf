import { createHash, randomBytes } from 'node:crypto';
import type { Request, Response } from 'express';

const COOKIE_NAME = 'waf_challenge';
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

export class ChallengeManager {
  private secret = randomBytes(32).toString('hex');
  private difficulty: number;

  constructor(difficulty = 4) {
    this.difficulty = difficulty;
  }

  hasValidCookie(req: Request): boolean {
    const token = req.headers.cookie?.split(';').map((c) => c.trim()).find((c) => c.startsWith(`${COOKIE_NAME}=`));
    if (!token) return false;
    const value = token.split('=')[1];
    return this.verifyToken(value);
  }

  issueToken(): string {
    const expiry = Date.now() + CHALLENGE_TTL_MS;
    const payload = `${expiry}`;
    const signature = createHash('sha256').update(`${payload}:${this.secret}`).digest('hex');
    return Buffer.from(`${payload}.${signature}`).toString('base64url');
  }

  private verifyToken(token: string): boolean {
    try {
      const decoded = Buffer.from(token, 'base64url').toString('utf-8');
      const [payload, signature] = decoded.split('.');
      const expected = createHash('sha256').update(`${payload}:${this.secret}`).digest('hex');
      if (signature !== expected) return false;
      return Number(payload) > Date.now();
    } catch {
      return false;
    }
  }

  renderChallengePage(res: Response, powNonce: string): void {
    res.status(403).setHeader('Content-Type', 'text/html');
    res.end(challengeHtml(powNonce, this.difficulty));
  }

  verifyProofOfWork(nonce: string, solution: string): boolean {
    const hash = createHash('sha256').update(`${nonce}:${solution}`).digest('hex');
    return hash.startsWith('0'.repeat(this.difficulty));
  }

  cookieHeader(): string {
    return `${COOKIE_NAME}=${this.issueToken()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${CHALLENGE_TTL_MS / 1000}`;
  }
}

function challengeHtml(nonce: string, difficulty: number): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Verifying</title></head><body>
<p>Checking your browser...</p>
<script>
async function solve(nonce, difficulty) {
  const target = '0'.repeat(difficulty);
  let solution = 0;
  while (true) {
    const data = new TextEncoder().encode(nonce + ':' + solution);
    const digest = await crypto.subtle.digest('SHA-256', data);
    const hex = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
    if (hex.startsWith(target)) break;
    solution++;
  }
  document.cookie = 'waf_pow=' + solution + '; path=/';
  location.reload();
}
solve('${nonce}', ${difficulty});
</script>
</body></html>`;
}
