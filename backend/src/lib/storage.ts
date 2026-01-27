import { mkdir, writeFile, readFile, unlink, stat } from 'fs/promises';
import { join } from 'path';
import { randomBytes } from 'crypto';
import { existsSync } from 'fs';

const STORAGE_ROOT = process.env.STORAGE_PATH || './uploads';

export interface StorageResult {
  relativePath: string; // Path stored in database
  fullPath: string;     // Absolute path on disk
  size: number;
}

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
  
  // Create directory structure
  await mkdir(dirPath, { recursive: true });
  
  // Write encrypted file
  await writeFile(fullPath, buffer);
  
  return {
    relativePath,
    fullPath,
    size: buffer.length,
  };
}

/**
 * Read a file from storage
 */
export async function getFile(relativePath: string): Promise<Buffer> {
  const fullPath = join(STORAGE_ROOT, relativePath);
  return readFile(fullPath);
}

/**
 * Delete a file from storage
 */
export async function deleteFile(relativePath: string): Promise<boolean> {
  try {
    const fullPath = join(STORAGE_ROOT, relativePath);
    await unlink(fullPath);
    return true;
  } catch (error) {
    console.error(`Failed to delete file: ${relativePath}`, error);
    return false;
  }
}

/**
 * Check if a file exists
 */
export async function fileExists(relativePath: string): Promise<boolean> {
  const fullPath = join(STORAGE_ROOT, relativePath);
  return existsSync(fullPath);
}

/**
 * Get file size
 */
export async function getFileSize(relativePath: string): Promise<number> {
  const fullPath = join(STORAGE_ROOT, relativePath);
  const stats = await stat(fullPath);
  return stats.size;
}

/**
 * Get full path for streaming
 */
export function getFullPath(relativePath: string): string {
  return join(STORAGE_ROOT, relativePath);
}
