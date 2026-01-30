/**
 * VirusTotal API v3 integration for malware scanning on upload.
 * API key can be set via setup wizard, admin dashboard, or env VIRUSTOTAL_API_KEY.
 */

import { db, schema } from '../db/index.js';
import { eq } from 'drizzle-orm';

const VT_FILES_URL = 'https://www.virustotal.com/api/v3/files';
const VT_ANALYSES_URL = 'https://www.virustotal.com/api/v3/analyses';
const VT_FILE_REPORT_URL = 'https://www.virustotal.com/api/v3/files';
const VT_MAX_FILE_SIZE = 32 * 1024 * 1024; // 32MB - larger files need upload_url flow
const POLL_INTERVAL_MS = 5000;
const POLL_ATTEMPTS = 12; // ~1 min max wait

const SETTINGS_KEY_VT_API = 'virustotal_api_key';

export async function getVirusTotalApiKey(): Promise<string | null> {
  const envKey = process.env.VIRUSTOTAL_API_KEY;
  if (envKey && envKey.trim()) return envKey.trim();

  const row = await db.query.settings.findFirst({
    where: eq(schema.settings.key, SETTINGS_KEY_VT_API),
  });
  return row?.value ?? null;
}

export async function setVirusTotalApiKey(apiKey: string | null): Promise<void> {
  await db.delete(schema.settings).where(eq(schema.settings.key, SETTINGS_KEY_VT_API));
  if (apiKey !== null && apiKey.trim() !== '') {
    await db.insert(schema.settings).values({ key: SETTINGS_KEY_VT_API, value: apiKey.trim() });
  }
}

export interface ScanResult {
  safe: boolean;
  malicious?: number;
  suspicious?: number;
  error?: string;
}

/**
 * Scan a file buffer with VirusTotal. Returns safe: false if malicious/suspicious or on error.
 * Files > 32MB are skipped (VT requires upload_url flow) and treated as safe to avoid blocking.
 */
export async function scanFile(buffer: Buffer, filename: string): Promise<ScanResult> {
  const apiKey = await getVirusTotalApiKey();
  if (!apiKey) {
    return { safe: true }; // No key configured = skip scan
  }

  if (buffer.length > VT_MAX_FILE_SIZE) {
    // VirusTotal direct upload limit 32MB; larger files need upload_url - skip scan for now
    return { safe: true };
  }

  try {
    const form = new FormData();
    form.append('file', new Blob([buffer]), filename);

    const uploadRes = await fetch(VT_FILES_URL, {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
      },
      body: form,
    });

    if (!uploadRes.ok) {
      const errBody = await uploadRes.text();
      if (uploadRes.status === 429) {
        return { safe: true, error: 'VirusTotal rate limit; try again later' }; // Fail open to avoid blocking
      }
      return {
        safe: false,
        error: `VirusTotal upload failed: ${uploadRes.status} ${errBody.slice(0, 200)}`,
      };
    }

    const uploadJson = (await uploadRes.json()) as {
      data?: { type?: string; id?: string };
    };
    const resourceId = uploadJson?.data?.id;
    if (!resourceId) {
      return { safe: false, error: 'VirusTotal: no id in response' };
    }

    const isAnalysis = uploadJson?.data?.type === 'analysis';

    // Poll for result: either GET /analyses/{id} or GET /files/{id}
    for (let i = 0; i < POLL_ATTEMPTS; i++) {
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));

      const reportUrl = isAnalysis
        ? `${VT_ANALYSES_URL}/${resourceId}`
        : `${VT_FILE_REPORT_URL}/${resourceId}`;
      const reportRes = await fetch(reportUrl, {
        headers: { 'x-apikey': apiKey },
      });
      if (!reportRes.ok) {
        return { safe: false, error: `VirusTotal report fetch failed: ${reportRes.status}` };
      }

      const reportJson = (await reportRes.json()) as {
        data?: {
          attributes?: {
            status?: string;
            stats?: { malicious?: number; suspicious?: number };
            last_analysis_stats?: { malicious?: number; suspicious?: number };
          };
        };
      };
      const attrs = reportJson?.data?.attributes;
      const stats = attrs?.stats ?? attrs?.last_analysis_stats;
      const status = attrs?.status;

      if (isAnalysis) {
        if (status === 'completed' && stats != null) {
          const malicious = stats.malicious ?? 0;
          const suspicious = stats.suspicious ?? 0;
          if (malicious > 0 || suspicious > 0) {
            return { safe: false, malicious, suspicious };
          }
          return { safe: true, malicious: 0, suspicious: 0 };
        }
      } else {
        // File report: last_analysis_stats present when scan is done
        if (stats != null) {
          const malicious = stats.malicious ?? 0;
          const suspicious = stats.suspicious ?? 0;
          if (malicious > 0 || suspicious > 0) {
            return { safe: false, malicious, suspicious };
          }
          return { safe: true, malicious: 0, suspicious: 0 };
        }
      }
    }

    return { safe: false, error: 'VirusTotal scan timed out' };
  } catch (err: any) {
    return { safe: false, error: err?.message ?? 'VirusTotal scan failed' };
  }
}
