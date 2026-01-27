import { createSignal, createEffect, For, Show } from 'solid-js';
import { useAuth } from '../stores/auth.jsx';
import * as api from '../lib/api';
import type { AdminStats, AdminUser, AuditLogEntry, UserSession } from '../lib/api';
import { toast } from '../stores/toast';
import { openConfirm } from '../stores/confirm';

type TabType = 'overview' | 'users' | 'audit';

export default function AdminDashboard() {
  const { user, logout } = useAuth();
  const [activeTab, setActiveTab] = createSignal<TabType>('overview');
  const [stats, setStats] = createSignal<AdminStats | null>(null);
  const [users, setUsers] = createSignal<AdminUser[]>([]);
  const [auditLogs, setAuditLogs] = createSignal<AuditLogEntry[]>([]);
  const [isLoading, setIsLoading] = createSignal(false);
  
  // Pagination
  const [usersPage, setUsersPage] = createSignal(1);
  const [usersTotalPages, setUsersTotalPages] = createSignal(1);
  const [logsPage, setLogsPage] = createSignal(1);
  const [logsTotalPages, setLogsTotalPages] = createSignal(1);
  
  // User sessions modal
  const [selectedUser, setSelectedUser] = createSignal<AdminUser | null>(null);
  const [userSessions, setUserSessions] = createSignal<UserSession[]>([]);
  
  // Quota edit modal
  const [quotaUser, setQuotaUser] = createSignal<AdminUser | null>(null);
  const [newQuota, setNewQuota] = createSignal('');

  // Load stats
  const loadStats = async () => {
    try {
      const result = await api.getAdminStats();
      setStats(result.stats);
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  };

  // Load users
  const loadUsers = async (page = 1) => {
    setIsLoading(true);
    try {
      const result = await api.getAdminUsers(page, 20);
      setUsers(result.users);
      setUsersPage(result.pagination.page);
      setUsersTotalPages(result.pagination.totalPages);
    } catch (error) {
      console.error('Failed to load users:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // Load audit logs
  const loadAuditLogs = async (page = 1) => {
    setIsLoading(true);
    try {
      const result = await api.getAuditLogs(page, 50);
      setAuditLogs(result.logs);
      setLogsPage(result.pagination.page);
      setLogsTotalPages(result.pagination.totalPages);
    } catch (error) {
      console.error('Failed to load audit logs:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // Handle suspend/unsuspend
  const handleSuspend = async (targetUser: AdminUser) => {
    const action = targetUser.isSuspended ? 'unsuspend' : 'suspend';
    const confirmed = await openConfirm({
      title: `${action.charAt(0).toUpperCase() + action.slice(1)} User`,
      message: `Are you sure you want to ${action} user "${targetUser.username}"?`,
      confirmText: action.charAt(0).toUpperCase() + action.slice(1),
      type: action === 'suspend' ? 'danger' : 'warning',
    });
    if (!confirmed) return;
    
    try {
      await api.suspendUser(targetUser.id, !targetUser.isSuspended);
      toast.success(`User ${targetUser.username} has been ${action}ed`);
      loadUsers(usersPage());
      loadStats();
    } catch (error: any) {
      toast.error(`Failed to ${action} user: ${error.message}`);
    }
  };

  // Handle quota update
  const openQuotaModal = (targetUser: AdminUser) => {
    setQuotaUser(targetUser);
    setNewQuota(String(Math.round(targetUser.storageQuota / (1024 * 1024)))); // Convert to MB
  };

  const handleQuotaUpdate = async () => {
    const targetUser = quotaUser();
    if (!targetUser) return;
    
    const quotaMB = parseInt(newQuota());
    if (isNaN(quotaMB) || quotaMB < 0) {
      toast.warning('Please enter a valid quota in MB');
      return;
    }
    
    try {
      await api.updateUserQuota(targetUser.id, quotaMB * 1024 * 1024);
      toast.success(`Quota updated for ${targetUser.username}`);
      setQuotaUser(null);
      loadUsers(usersPage());
    } catch (error: any) {
      toast.error(`Failed to update quota: ${error.message}`);
    }
  };

  // View user sessions
  const viewSessions = async (targetUser: AdminUser) => {
    try {
      const result = await api.getUserSessions(targetUser.id);
      setUserSessions(result.sessions);
      setSelectedUser(targetUser);
    } catch (error: any) {
      toast.error(`Failed to load sessions: ${error.message}`);
    }
  };

  // Revoke session
  const revokeSession = async (sessionId: number) => {
    const confirmed = await openConfirm({
      title: 'Revoke Session',
      message: 'Are you sure you want to revoke this session?',
      confirmText: 'Revoke',
      type: 'danger',
    });
    if (!confirmed) return;
    
    try {
      await api.adminRevokeSession(sessionId);
      toast.success('Session revoked successfully');
      const targetUser = selectedUser();
      if (targetUser) {
        viewSessions(targetUser);
      }
      loadStats();
    } catch (error: any) {
      toast.error(`Failed to revoke session: ${error.message}`);
    }
  };

  // Format file size
  const formatSize = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  // Format date
  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString();
  };

  // Load data on mount and tab change
  createEffect(() => {
    const tab = activeTab();
    if (tab === 'overview') {
      loadStats();
    } else if (tab === 'users') {
      loadUsers(1);
    } else if (tab === 'audit') {
      loadAuditLogs(1);
    }
  });

  return (
    <div class="pb-20">
      {/* Header */}
      <div class="flex items-center justify-between mb-6">
        <div>
          <h2 class="text-2xl font-bold text-white">Admin Dashboard</h2>
          <p class="text-gray-400 mt-1">Manage users, view statistics, and audit logs</p>
        </div>
        <button
          onClick={() => window.location.pathname = '/'}
          class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm flex items-center gap-2"
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
          </svg>
          Back to Files
        </button>
      </div>

      {/* Tabs */}
      <div class="flex gap-2 mb-6 border-b border-gray-700">
        <button
          onClick={() => setActiveTab('overview')}
          class={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
            activeTab() === 'overview'
              ? 'border-primary-500 text-primary-400'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          Overview
        </button>
        <button
          onClick={() => setActiveTab('users')}
          class={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
            activeTab() === 'users'
              ? 'border-primary-500 text-primary-400'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          User Management
        </button>
        <button
          onClick={() => setActiveTab('audit')}
          class={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
            activeTab() === 'audit'
              ? 'border-primary-500 text-primary-400'
              : 'border-transparent text-gray-400 hover:text-white'
          }`}
        >
          Audit Logs
        </button>
      </div>

      {/* Overview Tab */}
      <Show when={activeTab() === 'overview'}>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* Total Users */}
          <div class="bg-gray-800 rounded-xl p-6">
            <div class="flex items-center gap-4">
              <div class="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                <svg class="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
                </svg>
              </div>
              <div>
                <p class="text-gray-400 text-sm">Total Users</p>
                <p class="text-2xl font-bold text-white">{stats()?.totalUsers || 0}</p>
              </div>
            </div>
          </div>

          {/* Active Sessions */}
          <div class="bg-gray-800 rounded-xl p-6">
            <div class="flex items-center gap-4">
              <div class="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center">
                <svg class="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5.636 18.364a9 9 0 010-12.728m12.728 0a9 9 0 010 12.728m-9.9-2.829a5 5 0 010-7.07m7.072 0a5 5 0 010 7.07M13 12a1 1 0 11-2 0 1 1 0 012 0z" />
                </svg>
              </div>
              <div>
                <p class="text-gray-400 text-sm">Active Sessions</p>
                <p class="text-2xl font-bold text-white">{stats()?.activeSessions || 0}</p>
              </div>
            </div>
          </div>

          {/* Total Storage */}
          <div class="bg-gray-800 rounded-xl p-6">
            <div class="flex items-center gap-4">
              <div class="w-12 h-12 bg-purple-500/20 rounded-lg flex items-center justify-center">
                <svg class="w-6 h-6 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
                </svg>
              </div>
              <div>
                <p class="text-gray-400 text-sm">Total Storage Used</p>
                <p class="text-2xl font-bold text-white">{formatSize(stats()?.totalStorage || 0)}</p>
              </div>
            </div>
          </div>

          {/* Total Files */}
          <div class="bg-gray-800 rounded-xl p-6">
            <div class="flex items-center gap-4">
              <div class="w-12 h-12 bg-yellow-500/20 rounded-lg flex items-center justify-center">
                <svg class="w-6 h-6 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <div>
                <p class="text-gray-400 text-sm">Total Files</p>
                <p class="text-2xl font-bold text-white">{stats()?.totalFiles || 0}</p>
              </div>
            </div>
          </div>

          {/* Suspended Users */}
          <div class="bg-gray-800 rounded-xl p-6">
            <div class="flex items-center gap-4">
              <div class="w-12 h-12 bg-red-500/20 rounded-lg flex items-center justify-center">
                <svg class="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                </svg>
              </div>
              <div>
                <p class="text-gray-400 text-sm">Suspended Users</p>
                <p class="text-2xl font-bold text-white">{stats()?.suspendedUsers || 0}</p>
              </div>
            </div>
          </div>
        </div>
      </Show>

      {/* Users Tab */}
      <Show when={activeTab() === 'users'}>
        <div class="bg-gray-800 rounded-xl overflow-hidden">
          <Show when={isLoading()}>
            <div class="flex items-center justify-center py-12">
              <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
            </div>
          </Show>
          
          <Show when={!isLoading()}>
            <table class="w-full">
              <thead class="bg-gray-900">
                <tr>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">User</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Storage</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">2FA</th>
                  <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Created</th>
                  <th class="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-gray-700">
                <For each={users()}>
                  {(u) => (
                    <tr class="hover:bg-gray-700/50">
                      <td class="px-4 py-3">
                        <div class="flex items-center gap-3">
                          <div class="w-8 h-8 bg-primary-600 rounded-full flex items-center justify-center text-white font-medium">
                            {u.username.charAt(0).toUpperCase()}
                          </div>
                          <div>
                            <p class="text-white font-medium">{u.username}</p>
                            {u.isAdmin && (
                              <span class="text-xs text-primary-400">Admin</span>
                            )}
                          </div>
                        </div>
                      </td>
                      <td class="px-4 py-3">
                        <div class="text-sm">
                          <p class="text-white">{formatSize(u.storageUsed)}</p>
                          <p class="text-gray-500">of {formatSize(u.storageQuota)}</p>
                        </div>
                      </td>
                      <td class="px-4 py-3">
                        {u.isSuspended ? (
                          <span class="px-2 py-1 bg-red-500/20 text-red-400 rounded text-xs">Suspended</span>
                        ) : (
                          <span class="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs">Active</span>
                        )}
                      </td>
                      <td class="px-4 py-3">
                        {u.totpEnabled ? (
                          <span class="text-green-400">✓ Enabled</span>
                        ) : (
                          <span class="text-gray-500">Disabled</span>
                        )}
                      </td>
                      <td class="px-4 py-3 text-gray-400 text-sm">
                        {new Date(u.createdAt).toLocaleDateString()}
                      </td>
                      <td class="px-4 py-3 text-right">
                        <div class="flex items-center justify-end gap-2">
                          <button
                            onClick={() => viewSessions(u)}
                            class="p-2 text-gray-400 hover:text-primary-400 rounded-lg hover:bg-gray-700"
                            title="View Sessions"
                          >
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                            </svg>
                          </button>
                          <button
                            onClick={() => openQuotaModal(u)}
                            class="p-2 text-gray-400 hover:text-yellow-400 rounded-lg hover:bg-gray-700"
                            title="Edit Quota"
                          >
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                            </svg>
                          </button>
                          {!u.isAdmin && u.id !== user()?.id && (
                            <button
                              onClick={() => handleSuspend(u)}
                              class={`p-2 rounded-lg hover:bg-gray-700 ${
                                u.isSuspended 
                                  ? 'text-green-400 hover:text-green-300' 
                                  : 'text-red-400 hover:text-red-300'
                              }`}
                              title={u.isSuspended ? 'Unsuspend' : 'Suspend'}
                            >
                              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                {u.isSuspended ? (
                                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                ) : (
                                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                                )}
                              </svg>
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
            
            {/* Pagination */}
            <Show when={usersTotalPages() > 1}>
              <div class="flex items-center justify-center gap-2 py-4 border-t border-gray-700">
                <button
                  onClick={() => loadUsers(usersPage() - 1)}
                  disabled={usersPage() <= 1}
                  class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Previous
                </button>
                <span class="text-gray-400 text-sm">
                  Page {usersPage()} of {usersTotalPages()}
                </span>
                <button
                  onClick={() => loadUsers(usersPage() + 1)}
                  disabled={usersPage() >= usersTotalPages()}
                  class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next
                </button>
              </div>
            </Show>
          </Show>
        </div>
      </Show>

      {/* Audit Logs Tab */}
      <Show when={activeTab() === 'audit'}>
        <div class="bg-gray-800 rounded-xl overflow-hidden">
          <Show when={isLoading()}>
            <div class="flex items-center justify-center py-12">
              <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
            </div>
          </Show>
          
          <Show when={!isLoading()}>
            <div class="overflow-x-auto">
              <table class="w-full">
                <thead class="bg-gray-900">
                  <tr>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Time</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">User</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Action</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Resource</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">IP Address</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Details</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-gray-700">
                  <For each={auditLogs()}>
                    {(log) => (
                      <tr class="hover:bg-gray-700/50">
                        <td class="px-4 py-3 text-gray-400 text-sm whitespace-nowrap">
                          {formatDate(log.createdAt)}
                        </td>
                        <td class="px-4 py-3 text-white">
                          {log.username}
                        </td>
                        <td class="px-4 py-3">
                          <span class={`px-2 py-1 rounded text-xs font-medium ${
                            log.action.includes('LOGIN') ? 'bg-green-500/20 text-green-400' :
                            log.action.includes('LOGOUT') ? 'bg-blue-500/20 text-blue-400' :
                            log.action.includes('DELETE') || log.action.includes('SUSPEND') ? 'bg-red-500/20 text-red-400' :
                            log.action.includes('UPLOAD') ? 'bg-purple-500/20 text-purple-400' :
                            'bg-gray-500/20 text-gray-400'
                          }`}>
                            {log.action}
                          </span>
                        </td>
                        <td class="px-4 py-3 text-gray-400 text-sm">
                          {log.resourceType && (
                            <span>{log.resourceType}: {log.resourceId?.substring(0, 8)}...</span>
                          )}
                        </td>
                        <td class="px-4 py-3 text-gray-400 text-sm font-mono">
                          {log.ipAddress || '-'}
                        </td>
                        <td class="px-4 py-3 text-gray-500 text-sm max-w-xs truncate">
                          {log.details ? JSON.stringify(log.details) : '-'}
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
            
            {/* Empty state */}
            <Show when={auditLogs().length === 0}>
              <div class="text-center py-12 text-gray-500">
                No audit logs yet
              </div>
            </Show>
            
            {/* Pagination */}
            <Show when={logsTotalPages() > 1}>
              <div class="flex items-center justify-center gap-2 py-4 border-t border-gray-700">
                <button
                  onClick={() => loadAuditLogs(logsPage() - 1)}
                  disabled={logsPage() <= 1}
                  class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Previous
                </button>
                <span class="text-gray-400 text-sm">
                  Page {logsPage()} of {logsTotalPages()}
                </span>
                <button
                  onClick={() => loadAuditLogs(logsPage() + 1)}
                  disabled={logsPage() >= logsTotalPages()}
                  class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next
                </button>
              </div>
            </Show>
          </Show>
        </div>
      </Show>

      {/* User Sessions Modal */}
      <Show when={selectedUser()}>
        <div class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4" onClick={() => setSelectedUser(null)}>
          <div class="bg-gray-800 rounded-xl max-w-2xl w-full overflow-hidden" onClick={(e) => e.stopPropagation()}>
            <div class="flex items-center justify-between px-6 py-4 border-b border-gray-700">
              <h3 class="text-lg font-medium text-white">
                Sessions for {selectedUser()?.username}
              </h3>
              <button
                onClick={() => setSelectedUser(null)}
                class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div class="p-6 max-h-96 overflow-y-auto">
              <Show when={userSessions().length === 0}>
                <p class="text-center text-gray-500 py-8">No active sessions</p>
              </Show>
              <For each={userSessions()}>
                {(session) => (
                  <div class="flex items-center justify-between p-4 bg-gray-700 rounded-lg mb-3">
                    <div>
                      <p class="text-white text-sm">
                        {session.ipAddress || 'Unknown IP'}
                      </p>
                      <p class="text-gray-400 text-xs mt-1">
                        Created: {formatDate(session.createdAt)}
                      </p>
                      <p class="text-gray-400 text-xs">
                        Last Active: {formatDate(session.lastActive)}
                      </p>
                      <span class={`text-xs mt-2 inline-block px-2 py-0.5 rounded ${
                        session.isActive ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'
                      }`}>
                        {session.isActive ? 'Active' : 'Expired'}
                      </span>
                    </div>
                    <button
                      onClick={() => revokeSession(session.id)}
                      class="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-sm rounded"
                    >
                      Revoke
                    </button>
                  </div>
                )}
              </For>
            </div>
          </div>
        </div>
      </Show>

      {/* Quota Edit Modal */}
      <Show when={quotaUser()}>
        <div class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4" onClick={() => setQuotaUser(null)}>
          <div class="bg-gray-800 rounded-xl max-w-md w-full overflow-hidden" onClick={(e) => e.stopPropagation()}>
            <div class="flex items-center justify-between px-6 py-4 border-b border-gray-700">
              <h3 class="text-lg font-medium text-white">
                Edit Quota for {quotaUser()?.username}
              </h3>
              <button
                onClick={() => setQuotaUser(null)}
                class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div class="p-6">
              <p class="text-gray-400 text-sm mb-4">
                Current usage: {formatSize(quotaUser()?.storageUsed || 0)}
              </p>
              <label class="block text-sm text-gray-400 mb-2">New quota (MB)</label>
              <input
                type="number"
                value={newQuota()}
                onInput={(e) => setNewQuota(e.currentTarget.value)}
                class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
                min="0"
              />
              <div class="flex justify-end gap-3 mt-6">
                <button
                  onClick={() => setQuotaUser(null)}
                  class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-300"
                >
                  Cancel
                </button>
                <button
                  onClick={handleQuotaUpdate}
                  class="px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg text-white"
                >
                  Save
                </button>
              </div>
            </div>
          </div>
        </div>
      </Show>
    </div>
  );
}
