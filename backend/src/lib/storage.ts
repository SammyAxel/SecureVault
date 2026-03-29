import { mkdir, writeFile, readFile, unlink, stat } from 'fs/promises';
import { libLogger } from './logger.js';
import { join } from 'path';
import { randomBytes } from 'crypto';
import { existsSync, createReadStream, readFileSync } from 'fs';
import type { ReadStream } from 'fs';

export interface StorageResult {
  relativePath: string;
  fullPath: string;
  size: number;
}

/** Filesystem capacity (total/free in bytes). null if backend does not expose this (e.g. S3). */
export interface StorageStats {
  total: number;
  free: number;
}

interface StorageConfig {
  driver?: string;
  local?: { path?: string };
}

function loadStorageConfig(): { root: string } {
  const envPath = process.env.STORAGE_PATH;
  if (envPath) return { root: envPath };

  try {
    const configPath = process.env.STORAGE_CONFIG_PATH || join(process.cwd(), 'config', 'storage.json');
    if (existsSync(configPath)) {
      const raw = readFileSync(configPath, 'utf-8');
      const config: StorageConfig = JSON.parse(raw);
      const localPath = config.local?.path;
      if (config.driver === 'local' && localPath) return { root: localPath };
    }
  } catch {
    // ignore: use default
  }

  return { root: './uploads' };
}

const { root: STORAGE_ROOT } = loadStorageConfig();

/**
 * Save a file to organized storage: {userId}/{YYYY-MM}/{randomName}.enc
 */
export async function saveFile(userId: number, buffer: Buffer): Promise<StorageResult> {
  const now = new Date();
  const yearMonth = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
  const filename = randomBytes(16).toString('hex') + '.enc';

  const relativePath = `${userId}/${yearMonth}/${filename}`;
  const dirPath = join(STORAGE_ROOT, String(userId), yearMonth);
  const fullPath = join(dirPath, filename);

  await mkdir(dirPath, { recursive: true });
  await writeFile(fullPath, buffer);

  return {
    relativePath,
    fullPath,
    size: buffer.length,
  };
}

export async function getFile(relativePath: string): Promise<Buffer> {
  const fullPath = join(STORAGE_ROOT, relativePath);
  return readFile(fullPath);
}

export async function deleteFile(relativePath: string): Promise<boolean> {
  try {
    const fullPath = join(STORAGE_ROOT, relativePath);
    await unlink(fullPath);
    return true;
  } catch (error) {
    libLogger.warn({ relativePath, err: error }, 'Failed to delete file');
    return false;
  }
}

export async function fileExists(relativePath: string): Promise<boolean> {
  const fullPath = join(STORAGE_ROOT, relativePath);
  return existsSync(fullPath);
}

export async function getFileSize(relativePath: string): Promise<number> {
  const fullPath = join(STORAGE_ROOT, relativePath);
  const stats = await stat(fullPath);
  return stats.size;
}

export function getFullPath(relativePath: string): string {
  return join(STORAGE_ROOT, relativePath);
}

/**
 * Get a readable stream for the file (for download). Prefer this over getFullPath + createReadStream
 * so the backend can be swapped (e.g. S3/NFS) later without changing routes.
 */
export function getStream(relativePath: string): ReadStream {
  const fullPath = join(STORAGE_ROOT, relativePath);
  return createReadStream(fullPath);
}

/**
 * Get filesystem stats for the storage root (total/free in bytes).
 * Follows the actual disk or mount (e.g. NFS). Returns null if unavailable (e.g. old Node or non-filesystem backend).
 */
export async function getStats(): Promise<StorageStats | null> {
  try {
    const fs = await import('fs');
    const statfsSync = (fs as any).statfsSync;
    if (typeof statfsSync !== 'function') return null;
    const s = statfsSync(STORAGE_ROOT);
    const blockSize = s.bsize ?? s.blockSize ?? 4096;
    const total = Number(s.blocks) * blockSize;
    const free = Number(s.bavail ?? s.bfree) * blockSize;
    return { total, free };
  } catch {
    return null;
  }
}
