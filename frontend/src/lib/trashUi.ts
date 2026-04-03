import { TRASH_RETENTION_DAYS } from './config';

/** Whole days until server-side permanent purge (matches default retention window). */
export function daysUntilTrashPurge(deletedAtIso: string, retentionDays = TRASH_RETENTION_DAYS): number {
  const t = new Date(deletedAtIso).getTime();
  if (Number.isNaN(t)) return retentionDays;
  const purgeAt = t + retentionDays * 24 * 60 * 60 * 1000;
  return Math.max(0, Math.ceil((purgeAt - Date.now()) / (24 * 60 * 60 * 1000)));
}
