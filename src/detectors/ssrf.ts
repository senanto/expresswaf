import type { Detector, DetectorResult, ScanInput, WafConfig } from '../types/index.js';
import { ipMatchesCidr } from '../firewall/cidr.js';

const CLOUD_METADATA_HOSTS = new Set([
  '169.254.169.254',
  'metadata.google.internal',
  'metadata.google.com',
  '100.100.100.200'
]);

const PRIVATE_CIDRS = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '0.0.0.0/8'];

function isPrivateIp(ip: string): boolean {
  return PRIVATE_CIDRS.some((cidr) => ipMatchesCidr(ip, cidr));
}

function extractUrls(raw: string): string[] {
  const matches = raw.match(/https?:\/\/[^\s"'<>]+/gi) ?? [];
  return matches;
}

export function makeSsrfDetector(config: WafConfig['ssrf']): Detector {
  return {
    name: 'ssrf',
    scan(input: ScanInput): DetectorResult[] {
      const results: DetectorResult[] = [];
      for (const url of extractUrls(input.raw)) {
        let host: string;
        try {
          host = new URL(url).hostname.toLowerCase();
        } catch {
          continue;
        }
        if (config.blockCloudMetadata && CLOUD_METADATA_HOSTS.has(host)) {
          results.push({ matched: true, category: 'ssrf', rule: 'cloud-metadata', score: 95, meta: { field: input.key, host } });
          continue;
        }
        if (config.blockPrivateNetworks && isPrivateIp(host)) {
          results.push({ matched: true, category: 'ssrf', rule: 'private-network', score: 85, meta: { field: input.key, host } });
          continue;
        }
        if (host === 'localhost' || host.endsWith('.internal') || host.endsWith('.local')) {
          results.push({ matched: true, category: 'ssrf', rule: 'internal-hostname', score: 75, meta: { field: input.key, host } });
        }
        if (config.allowedHosts && config.allowedHosts.length > 0 && !config.allowedHosts.includes(host)) {
          results.push({ matched: true, category: 'ssrf', rule: 'host-not-allowlisted', score: 50, meta: { field: input.key, host } });
        }
      }
      return results;
    }
  };
}
