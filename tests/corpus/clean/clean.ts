import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve, sep } from 'node:path';

export interface SessionClaim {
  readonly sub: string;
  readonly orgId: string;
}

export function hashApiToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function generateNonceHex(byteLength = 16): string {
  return randomBytes(byteLength).toString('hex');
}

export function readScopedAsset(rootDir: string, relFile: string): string {
  const base = resolve(rootDir);
  const full = resolve(base, relFile);
  if (full !== base && !full.startsWith(base + sep)) {
    throw new Error('Path outside asset root');
  }
  return readFileSync(full, 'utf8');
}

export function sanitizeRedirectTarget(rawPath: string): string {
  const candidate = String(rawPath || '/');
  if (!candidate.startsWith('/') || candidate.startsWith('//')) {
    return '/dashboard';
  }
  const u = new URL(candidate, 'https://app.example.com');
  return u.pathname + u.search;
}

export function isAuthorizedClaim(claim: SessionClaim | null, expectedOrgId: string): boolean {
  if (!claim) return false;
  return Boolean(claim.sub && claim.orgId && claim.orgId === expectedOrgId);
}
