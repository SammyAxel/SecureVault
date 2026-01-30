const API_BASE = '/api';

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const token = localStorage.getItem('securevault_token');
  
  const headers: HeadersInit = {
    ...options.headers,
  };
  
  if (token) {
    (headers as Record<string, string>)['Authorization'] = `Bearer ${token}`;
  }
  
  if (options.body && !(options.body instanceof FormData)) {
    (headers as Record<string, string>)['Content-Type'] = 'application/json';
  }
  
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });
  
  const data = await response.json();
  
  if (!response.ok) {
    throw new ApiError(response.status, data.msg || 'Request failed');
  }
  
  return data;
}

// ============ SETUP ============

export async function checkSetupStatus() {
  return request<{ ok: boolean; needsSetup: boolean; userCount: number }>('/setup/status');
}

export async function setupAdmin(
  username: string,
  publicKey: string,
  encryptionPublicKey: string
) {
  return request<{ ok: boolean; userId: number; username: string; isAdmin: boolean }>('/setup/admin', {
    method: 'POST',
    body: JSON.stringify({ username, publicKey, encryptionPublicKey }),
  });
}

// ============ AUTH ============

export async function register(
  username: string,
  publicKey: string,
  encryptionPublicKey: string
) {
  return request<{ ok: boolean; userId: number; username: string }>('/register', {
    method: 'POST',
    body: JSON.stringify({ username, publicKey, encryptionPublicKey }),
  });
}

export async function getChallenge(username: string) {
  return request<{
    ok: boolean;
    challenge: string;
    challengeId: string;
    requires2FA: boolean;
  }>('/auth/challenge', {
    method: 'POST',
    body: JSON.stringify({ username }),
  });
}

export async function verifyLogin(
  username: string,
  challengeId: string,
  signature: string,
  totp?: string
) {
  return request<{
    ok: boolean;
    token: string;
    expiresAt: string;
    user: {
      id: number;
      username: string;
      isAdmin: boolean;
      storageUsed: number;
      storageQuota: number;
    };
  }>('/auth/verify', {
    method: 'POST',
    body: JSON.stringify({ username, challengeId, signature, totp }),
  });
}

export async function logout() {
  return request<{ ok: boolean }>('/logout', { method: 'POST' });
}

export async function getCurrentUser() {
  return request<{
    ok: boolean;
    user: {
      id: number;
      username: string;
      isAdmin: boolean;
      storageUsed: number;
      storageQuota: number;
      totpEnabled: boolean;
      displayName?: string;
      avatar?: string;
      createdAt?: string;
    };
  }>('/me');
}

export async function getUserPublicKey(username: string) {
  return request<{
    ok: boolean;
    username: string;
    publicKey: string;
    encryptionPublicKey: string;
  }>(`/users/${username}/publickey`);
}

// ============ PROFILE ============

export async function updateProfile(data: { displayName?: string; avatar?: string }) {
  return request<{ ok: boolean }>('/profile', {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export interface SessionInfo {
  id: number;
  deviceInfo?: string;
  ipAddress?: string;
  userAgent?: string;
  createdAt: string;
  lastActive: string;
  isCurrent: boolean;
}

export async function getSessions() {
  return request<{ ok: boolean; sessions: SessionInfo[] }>('/sessions');
}

export async function revokeSession(id: number) {
  return request<{ ok: boolean }>(`/sessions/${id}`, {
    method: 'DELETE',
  });
}

export async function revokeAllSessions() {
  return request<{ ok: boolean }>('/sessions/revoke-all', {
    method: 'POST',
  });
}

export async function deleteAccount(confirmation: string) {
  return request<{ ok: boolean }>('/account', {
    method: 'DELETE',
    body: JSON.stringify({ confirmation }),
  });
}

// ============ 2FA ============

export async function setup2FA() {
  return request<{ ok: boolean; secret: string; qrCode: string }>('/auth/2fa/setup', {
    method: 'POST',
  });
}

export async function confirm2FA(code: string) {
  return request<{ ok: boolean; backupCodes: string[] }>('/auth/2fa/confirm', {
    method: 'POST',
    body: JSON.stringify({ code }),
  });
}

export async function disable2FA(code: string) {
  return request<{ ok: boolean }>('/auth/2fa/disable', {
    method: 'POST',
    body: JSON.stringify({ code }),
  });
}

// ============ FILES ============

export interface FileItem {
  id: string;
  uid?: string;
  filename: string;
  fileSize: number;
  isFolder: boolean;
  parentId: string | null;
  createdAt: string;
  encryptedKey: string;
  iv: string;
}

export async function listFiles(parentId?: string) {
  const query = parentId ? `?parentId=${parentId}` : '';
  return request<{ ok: boolean; files: FileItem[] }>(`/files${query}`);
}

export async function getFileByUid(uid: string) {
  return request<{
    ok: boolean;
    file: FileItem;
    parentPath: Array<{ id: string; uid: string | null; name: string }>;
  }>(`/f/${uid}`);
}

export async function uploadFile(
  file: File,
  encryptedData: ArrayBuffer,
  encryptedKey: string,
  iv: string,
  parentId?: string
) {
  const formData = new FormData();
  formData.append('file', new Blob([encryptedData]), file.name);
  formData.append('encrypted_key', encryptedKey);
  formData.append('iv', iv);
  if (parentId) {
    formData.append('parent_id', parentId);
  }
  
  return request<{ ok: boolean; fileId: string }>('/upload', {
    method: 'POST',
    body: formData,
  });
}

export async function createFolder(name: string, parentId?: string) {
  return request<{ ok: boolean; folderId: string }>('/folders', {
    method: 'POST',
    body: JSON.stringify({ name, parentId }),
  });
}

export async function downloadFile(fileId: string): Promise<{
  data: ArrayBuffer;
  encryptedKey: string;
  iv: string;
  filename: string;
}> {
  const token = localStorage.getItem('securevault_token');
  
  const response = await fetch(`${API_BASE}/files/${fileId}/download`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new ApiError(response.status, error.msg || 'Download failed');
  }
  
  return {
    data: await response.arrayBuffer(),
    encryptedKey: response.headers.get('X-Encrypted-Key') || '',
    iv: response.headers.get('X-IV') || '',
    filename: response.headers.get('Content-Disposition')?.match(/filename="(.+)"/)?.[1] || 'download',
  };
}

export async function deleteFile(fileId: string, permanent = false) {
  const query = permanent ? '?permanent=true' : '';
  return request<{ ok: boolean }>(`/files/${fileId}${query}`, {
    method: 'DELETE',
  });
}

export async function restoreFile(fileId: string) {
  return request<{ ok: boolean }>(`/files/${fileId}/restore`, {
    method: 'POST',
  });
}

export async function getTrash() {
  return request<{
    ok: boolean;
    files: Array<{
      id: string;
      filename: string;
      fileSize: number;
      isFolder: boolean;
      deletedAt: string;
    }>;
  }>('/trash');
}

// ============ SHARING ============

export async function shareWithUser(
  fileId: string,
  recipientUsername: string,
  encryptedKey: string
) {
  return request<{ ok: boolean }>('/share', {
    method: 'POST',
    body: JSON.stringify({ fileId, recipientUsername, encryptedKey }),
  });
}

export async function getSharedWithMe() {
  return request<{
    ok: boolean;
    files: Array<{
      id: string;
      filename: string;
      fileSize: number;
      isFolder: boolean;
      owner: string;
      encryptedKey: string;
      iv: string;
      sharedAt: string;
    }>;
  }>('/shared-with-me');
}

export async function createPublicShare(
  fileId: string,
  expiresInHours = 24,
  maxAccess?: number
) {
  return request<{
    ok: boolean;
    token: string;
    url: string;
    expiresAt: string;
  }>('/share/public', {
    method: 'POST',
    body: JSON.stringify({ fileId, expiresInHours, maxAccess }),
  });
}

export async function getFileShares(fileId: string) {
  return request<{
    ok: boolean;
    shares: Array<{
      token: string;
      expiresAt: string;
      accessCount: number;
      maxAccess: number | null;
      createdAt: string;
      url: string;
    }>;
  }>(`/files/${fileId}/shares`);
}

export async function deletePublicShare(token: string) {
  return request<{ ok: boolean }>(`/share/public/${token}`, {
    method: 'DELETE',
  });
}

// ============ FILE MANAGEMENT ============

export async function renameFile(fileId: string, name: string) {
  return request<{ ok: boolean; filename: string }>(`/files/${fileId}/rename`, {
    method: 'PATCH',
    body: JSON.stringify({ name }),
  });
}

export async function moveFile(fileId: string, parentId: string | null) {
  return request<{ ok: boolean; parentId: string | null }>(`/files/${fileId}/move`, {
    method: 'PATCH',
    body: JSON.stringify({ parentId }),
  });
}

export async function getAllFolders() {
  return request<{
    ok: boolean;
    folders: Array<{
      id: string;
      filename: string;
      parentId: string | null;
    }>;
  }>('/folders');
}

// ============ ADMIN ============

export interface AdminStats {
  totalUsers: number;
  totalStorage: number;
  activeSessions: number;
  totalFiles: number;
  suspendedUsers: number;
}

export interface AdminUser {
  id: number;
  username: string;
  isAdmin: boolean;
  isSuspended: boolean;
  suspendedAt: string | null;
  storageUsed: number;
  storageQuota: number;
  totpEnabled: boolean;
  createdAt: string;
}

export interface AuditLogEntry {
  id: number;
  userId: number | null;
  username: string;
  action: string;
  resourceType: string | null;
  resourceId: string | null;
  details: Record<string, any> | null;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
}

export interface UserSession {
  id: number;
  deviceInfo: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
  lastActive: string;
  expiresAt: string;
  isActive: boolean;
}

export async function getAdminStats() {
  return request<{ ok: boolean; stats: AdminStats }>('/admin/stats');
}

export async function getAdminUsers(page = 1, limit = 20) {
  return request<{
    ok: boolean;
    users: AdminUser[];
    pagination: {
      page: number;
      limit: number;
      total: number;
      totalPages: number;
    };
  }>(`/admin/users?page=${page}&limit=${limit}`);
}

export async function suspendUser(userId: number, suspended: boolean) {
  return request<{ ok: boolean; suspended: boolean }>(`/admin/users/${userId}/suspend`, {
    method: 'PATCH',
    body: JSON.stringify({ suspended }),
  });
}

export async function updateUserQuota(userId: number, quota: number) {
  return request<{ ok: boolean; quota: number }>(`/admin/users/${userId}/quota`, {
    method: 'PATCH',
    body: JSON.stringify({ quota }),
  });
}

export async function getAuditLogs(page = 1, limit = 50) {
  return request<{
    ok: boolean;
    logs: AuditLogEntry[];
    pagination: {
      page: number;
      limit: number;
      total: number;
      totalPages: number;
    };
  }>(`/admin/audit-logs?page=${page}&limit=${limit}`);
}

export async function getUserSessions(userId: number) {
  return request<{ ok: boolean; sessions: UserSession[] }>(`/admin/users/${userId}/sessions`);
}

export async function adminRevokeSession(sessionId: number) {
  return request<{ ok: boolean }>(`/admin/sessions/${sessionId}`, {
    method: 'DELETE',
  });
}

export { ApiError };
