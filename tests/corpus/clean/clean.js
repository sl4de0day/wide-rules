import crypto from 'node:crypto';
import path from 'node:path';
import { execFile } from 'node:child_process';

export function buildSafeUserQuery(pool, orgId, limitRaw) {
  const limit = Math.min(Math.max(Number(limitRaw || 20), 1), 100);
  return pool.query('SELECT id, email, display_name FROM users WHERE org_id = $1 LIMIT $2', [orgId, limit]);
}

export function copyPlainFields(target, payload) {
  const safeTarget = Object.create(null);
  for (const key of Object.keys(payload || {})) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (Object.hasOwn(payload, key)) {
      safeTarget[key] = payload[key];
    }
  }
  return Object.assign(target, safeTarget);
}

export function resolveUploadFile(baseDir, untrustedName) {
  const resolvedBase = path.resolve(baseDir);
  const resolvedTarget = path.resolve(resolvedBase, String(untrustedName || ''));
  const rel = path.relative(resolvedBase, resolvedTarget);
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error('Invalid upload path');
  }
  return resolvedTarget;
}

export function runGitDiff(repoDir, revision) {
  return new Promise((resolve, reject) => {
    execFile('git', ['diff', '--stat', String(revision)], { cwd: repoDir }, (err, stdout) => {
      if (err) reject(err);
      else resolve(stdout);
    });
  });
}

export function verifyWebhookSignature(secret, payload, providedHex) {
  const digest = crypto.createHmac('sha256', secret).update(payload).digest();
  const provided = Buffer.from(String(providedHex || ''), 'hex');
  if (digest.length !== provided.length) return false;
  return crypto.timingSafeEqual(digest, provided);
}

export function parseOutboundHost(rawUrl, allowlist) {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== 'https:') return null;
  return allowlist.includes(parsed.hostname) ? parsed.toString() : null;
}

export function formatRoleLabel(user) {
  const label = user.role === 'member' ? 'Member' : 'Guest';
  return `<span class="badge">${label}</span>`;
}
