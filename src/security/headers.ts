import type { Request, Response, NextFunction } from 'express';
import type { WafConfig } from '../types/index.js';

export function securityHeaders(config: WafConfig['headers']) {
  return function headersMiddleware(req: Request, res: Response, next: NextFunction): void {
    if (config.hsts) res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    if (config.csp) res.setHeader('Content-Security-Policy', config.csp);
    if (config.xFrameOptions) res.setHeader('X-Frame-Options', config.xFrameOptions);
    if (config.xContentTypeOptions) res.setHeader('X-Content-Type-Options', 'nosniff');
    if (config.referrerPolicy) res.setHeader('Referrer-Policy', config.referrerPolicy);
    res.setHeader('X-XSS-Protection', '0');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    res.removeHeader('X-Powered-By');
    next();
  };
}
