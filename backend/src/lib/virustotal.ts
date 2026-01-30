/**
 * VirusTotal API v3 integration for malware scanning on upload.
 * Uses hash-based lookup for faster scanning - no file upload required.
 * API key can be set via setup wizard, admin dashboard, or env VIRUSTOTAL_API_KEY.
 */

import { db, schema } from '../db/index.js';
import { eq } from 'drizzle-orm';
import { createHash, randomUUID } from 'crypto';

const VT_FILE_REPORT_URL = 'https://www.virustotal.com/api/v3/files';

const SETTINGS_KEY_VT_API = 'virustotal_api_key';
const SETTINGS_KEY_VT_KEYS = 'virustotal_api_keys';
const SETTINGS_KEY_VT_USAGE = 'virustotal_usage';
const VT_DAILY_LIMIT = 500;

export interface VirusTotalKey {
  id: string;
  key: string;
  enabled: boolean;
  label?: string;
  createdAt?: string;
}

export interface VirusTotalKeyPublic {
  id: string;
  maskedKey: string;
  enabled: boolean;
  label?: string;
  usageToday: number;
}

interface VirusTotalUsageState {
  date: string;
  perKey: Record<string, number>;
}

function getTodayString(): string {
  return new Date().toISOString().slice(0, 10);
}

function maskApiKey(key: string): string {
  if (key.length <= 8) return `${key.slice(0, 2)}...${key.slice(-2)}`;
  return `${key.slice(0, 4)}...${key.slice(-4)}`;
}

async function getStoredKeys(): Promise<VirusTotalKey[]> {
  const row = await db.query.settings.findFirst({
    where: eq(schema.settings.key, SETTINGS_KEY_VT_KEYS),
  });
  if (row?.value) {
    try {
      const parsed = JSON.parse(row.value) as VirusTotalKey[];
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  // Migrate legacy single key to list format if present
  const legacy = await db.query.settings.findFirst({
    where: eq(schema.settings.key, SETTINGS_KEY_VT_API),
  });
  if (legacy?.value) {
    const migrated: VirusTotalKey[] = [
      {
        id: randomUUID(),
        key: legacy.value.trim(),
        enabled: true,
        label: 'Primary',
        createdAt: new Date().toISOString(),
      },
    ];
    await setStoredKeys(migrated);
    await db.delete(schema.settings).where(eq(schema.settings.key, SETTINGS_KEY_VT_API));
    return migrated;
  }

  return [];
}

async function setStoredKeys(keys: VirusTotalKey[]): Promise<void> {
  await db.delete(schema.settings).where(eq(schema.settings.key, SETTINGS_KEY_VT_KEYS));
  await db.insert(schema.settings).values({
    key: SETTINGS_KEY_VT_KEYS,
    value: JSON.stringify(keys),
  });
}

async function getUsageState(): Promise<VirusTotalUsageState> {
  const row = await db.query.settings.findFirst({
    where: eq(schema.settings.key, SETTINGS_KEY_VT_USAGE),
  });
  const today = getTodayString();
  if (row?.value) {
    try {
      const parsed = JSON.parse(row.value) as VirusTotalUsageState;
      if (parsed?.date === today && parsed?.perKey) return parsed;
    } catch {
      // ignore parse errors
    }
  }
  return { date: today, perKey: {} };
}

async function setUsageState(state: VirusTotalUsageState): Promise<void> {
  await db.delete(schema.settings).where(eq(schema.settings.key, SETTINGS_KEY_VT_USAGE));
  await db.insert(schema.settings).values({
    key: SETTINGS_KEY_VT_USAGE,
    value: JSON.stringify(state),
  });
}

async function incrementUsage(keyId: string): Promise<void> {
  const state = await getUsageState();
  state.perKey[keyId] = (state.perKey[keyId] ?? 0) + 1;
  await setUsageState(state);
}

async function getUsageForKey(keyId: string): Promise<number> {
  const state = await getUsageState();
  return state.perKey[keyId] ?? 0;
}

async function getActiveVirusTotalKey(): Promise<{ id: string; key: string } | null> {
  const keys = await getStoredKeys();
  const enabled = keys.filter((k) => k.enabled);
  if (enabled.length === 0) {
    const envKey = process.env.VIRUSTOTAL_API_KEY;
    if (envKey && envKey.trim()) return { id: 'env', key: envKey.trim() };
    return null;
  }

  const usageState = await getUsageState();
  const sorted = [...enabled].sort((a, b) => {
    const usageA = usageState.perKey[a.id] ?? 0;
    const usageB = usageState.perKey[b.id] ?? 0;
    return usageA - usageB;
  });

  for (const key of sorted) {
    const used = usageState.perKey[key.id] ?? 0;
    if (used < VT_DAILY_LIMIT) return { id: key.id, key: key.key };
  }

  return null;
}

export async function getVirusTotalApiKey(): Promise<string | null> {
  const active = await getActiveVirusTotalKey();
  return active?.key ?? null;
}

export async function setVirusTotalApiKey(apiKey: string | null): Promise<void> {
  if (apiKey !== null && apiKey.trim() !== '') {
    const keys = await getStoredKeys();
    const newKey: VirusTotalKey = {
      id: randomUUID(),
      key: apiKey.trim(),
      enabled: true,
      label: 'Primary',
      createdAt: new Date().toISOString(),
    };
    await setStoredKeys([...keys, newKey]);
  }
}

export async function listVirusTotalKeys(): Promise<VirusTotalKeyPublic[]> {
  const keys = await getStoredKeys();
  const usage = await getUsageState();
  return keys.map((k) => ({
    id: k.id,
    maskedKey: maskApiKey(k.key),
    enabled: k.enabled,
    label: k.label,
    usageToday: usage.perKey[k.id] ?? 0,
  }));
}

export async function addVirusTotalKey(key: string, label?: string): Promise<VirusTotalKey> {
  const keys = await getStoredKeys();
  const newKey: VirusTotalKey = {
    id: randomUUID(),
    key: key.trim(),
    enabled: true,
    label,
    createdAt: new Date().toISOString(),
  };
  await setStoredKeys([...keys, newKey]);
  return newKey;
}

export async function updateVirusTotalKey(
  id: string,
  updates: { enabled?: boolean; label?: string }
): Promise<VirusTotalKey | null> {
  const keys = await getStoredKeys();
  const index = keys.findIndex((k) => k.id === id);
  if (index === -1) return null;
  const updated = { ...keys[index], ...updates };
  keys[index] = updated;
  await setStoredKeys(keys);
  return updated;
}

export async function removeVirusTotalKey(id: string): Promise<boolean> {
  const keys = await getStoredKeys();
  const next = keys.filter((k) => k.id !== id);
  if (next.length === keys.length) return false;
  await setStoredKeys(next);
  return true;
}

export async function getVirusTotalUsageSummary(): Promise<{ date: string; total: number; limit: number }> {
  const usage = await getUsageState();
  const total = Object.values(usage.perKey).reduce((sum, val) => sum + val, 0);
  return { date: usage.date, total, limit: VT_DAILY_LIMIT };
}

export interface ScanResult {
  safe: boolean;
  malicious?: number;
  suspicious?: number;
  hashFound?: boolean;
  error?: string;
}

/**
 * Calculate SHA256 hash of a buffer
 */
function calculateSHA256(buffer: Buffer): string {
  return createHash('sha256').update(buffer).digest('hex');
}

/**
 * Scan a file by its hash with VirusTotal.
 * This is much faster than uploading the file - it just checks if VT already has analysis for this hash.
 * If the hash is not found in VT database, we treat it as safe (unknown file).
 */
export async function scanFile(buffer: Buffer, filename: string, fileHash?: string): Promise<ScanResult> {
  const storedKeys = await getStoredKeys();
  const envKey = process.env.VIRUSTOTAL_API_KEY?.trim();
  const usageState = await getUsageState();

  const enabledKeys = storedKeys.filter((k) => k.enabled);
  const candidates = enabledKeys.length > 0
    ? [...enabledKeys].sort((a, b) => (usageState.perKey[a.id] ?? 0) - (usageState.perKey[b.id] ?? 0))
    : envKey
      ? [{ id: 'env', key: envKey, enabled: true } as VirusTotalKey]
      : [];

  if (candidates.length === 0) {
    console.log('[VirusTotal] No API key configured, skipping scan');
    return { safe: true }; // No key configured = skip scan
  }

  try {
    const hash = fileHash || calculateSHA256(buffer);
    console.log(`[VirusTotal] Scanning file: ${filename} (SHA256: ${hash}, size: ${buffer.length} bytes, hashProvided: ${!!fileHash})`);

    for (const key of candidates) {
      if (key.id !== 'env') {
        const used = usageState.perKey[key.id] ?? 0;
        if (used >= VT_DAILY_LIMIT) continue;
      }

      await incrementUsage(key.id);

      const reportUrl = `${VT_FILE_REPORT_URL}/${hash}`;
      const reportRes = await fetch(reportUrl, {
        headers: { 'x-apikey': key.key },
      });

      console.log(`[VirusTotal] API Response status: ${reportRes.status}`);

      if (reportRes.status === 404) {
        console.log(`[VirusTotal] Hash not found in VT database (404) - file unknown`);
        return { safe: true, hashFound: false };
      }

      if (reportRes.status === 429) {
        console.log(`[VirusTotal] Rate limited (429) for key ${key.id}, trying next key if available`);
        continue;
      }

      if (!reportRes.ok) {
        const errBody = await reportRes.text();
        console.error(`[VirusTotal] API error: ${reportRes.status} - ${errBody.slice(0, 200)}`);
        return {
          safe: false,
          error: `VirusTotal lookup failed: ${reportRes.status} ${errBody.slice(0, 200)}`,
        };
      }

      const reportJson = (await reportRes.json()) as {
        data?: {
          attributes?: {
            last_analysis_stats?: { malicious?: number; suspicious?: number };
          };
        };
      };

      const stats = reportJson?.data?.attributes?.last_analysis_stats;
      if (stats == null) {
        console.log(`[VirusTotal] Hash found but no analysis stats available`);
        return { safe: true, hashFound: true };
      }

      const malicious = stats.malicious ?? 0;
      const suspicious = stats.suspicious ?? 0;

      console.log(`[VirusTotal] Analysis complete - Malicious: ${malicious}, Suspicious: ${suspicious}`);

      if (malicious > 0 || suspicious > 0) {
        console.warn(`[VirusTotal] File flagged as malicious!`);
        return { safe: false, malicious, suspicious, hashFound: true };
      }

      console.log(`[VirusTotal] File is clean`);
      return { safe: true, malicious: 0, suspicious: 0, hashFound: true };
    }

    return { safe: true, error: 'VirusTotal rate limit; all keys exhausted' };
  } catch (err: any) {
    console.error(`[VirusTotal] Error during scan:`, err);
    return { safe: false, error: err?.message ?? 'VirusTotal scan failed' };
  }
}
