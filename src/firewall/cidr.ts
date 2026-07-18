export function ipToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return -1;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function cidrRange(cidr: string): [number, number] | null {
  const [base, prefixRaw] = cidr.split('/');
  const prefix = prefixRaw === undefined ? 32 : Number(prefixRaw);
  const start = ipToInt(base);
  if (start === -1 || Number.isNaN(prefix) || prefix < 0 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return [start & mask, (start | (~mask >>> 0)) >>> 0];
}

export function ipMatchesCidr(ip: string, cidr: string): boolean {
  const asInt = ipToInt(ip);
  if (asInt === -1) return false;
  const range = cidrRange(cidr);
  if (!range) return false;
  return asInt >= range[0] && asInt <= range[1];
}
