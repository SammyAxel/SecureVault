import { createSignal, createEffect, For, Show, onCleanup } from 'solid-js';
import * as api from '../lib/api';
import { toast } from '../stores/toast';

export default function NotificationCenter() {
  const [notifications, setNotifications] = createSignal<api.NotificationItem[]>([]);
  const [unreadCount, setUnreadCount] = createSignal(0);
  const [isOpen, setIsOpen] = createSignal(false);
  const [isLoading, setIsLoading] = createSignal(false);
  const [lastCheckTime, setLastCheckTime] = createSignal<number>(Date.now());

  // Load notifications
  const loadNotifications = async () => {
    try {
      setIsLoading(true);
      const result = await api.getNotifications();
      
      // Check for new notifications since last check
      const newNotifications = result.notifications.filter(n => 
        !n.read && new Date(n.createdAt).getTime() > lastCheckTime()
      );
      
      // Show toast for new notifications
      newNotifications.forEach(n => {
        toast.info(`${n.title}: ${n.message}`, 6000);
      });
      
      setNotifications(result.notifications);
      setUnreadCount(result.unreadCount);
      setLastCheckTime(Date.now());
    } catch (err) {
      console.error('Failed to load notifications:', err);
    } finally {
      setIsLoading(false);
    }
  };

  // Poll every 30 seconds
  createEffect(() => {
    loadNotifications();
    const interval = setInterval(loadNotifications, 30000);
    onCleanup(() => clearInterval(interval));
  });

  // Mark as read
  const markAsRead = async (id: number) => {
    try {
      await api.markNotificationRead(id);
      setNotifications(prev => prev.map(n => n.id === id ? { ...n, read: true } : n));
      setUnreadCount(prev => Math.max(0, prev - 1));
    } catch (err) {
      toast.error('Failed to mark notification as read');
    }
  };

  // Mark all as read
  const markAllAsRead = async () => {
    try {
      await api.markAllNotificationsRead();
      setNotifications(prev => prev.map(n => ({ ...n, read: true })));
      setUnreadCount(0);
      toast.success('All notifications marked as read');
    } catch (err) {
      toast.error('Failed to mark all as read');
    }
  };

  // Delete notification
  const deleteNotification = async (id: number) => {
    try {
      await api.deleteNotification(id);
      const wasUnread = notifications().find(n => n.id === id)?.read === false;
      setNotifications(prev => prev.filter(n => n.id !== id));
      if (wasUnread) setUnreadCount(prev => Math.max(0, prev - 1));
    } catch (err) {
      toast.error('Failed to delete notification');
    }
  };

  // Clear all
  const clearAll = async () => {
    try {
      await api.clearAllNotifications();
      setNotifications([]);
      setUnreadCount(0);
      toast.success('All notifications cleared');
    } catch (err) {
      toast.error('Failed to clear notifications');
    }
  };

  // Format time ago
  const timeAgo = (date: Date) => {
    const seconds = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
    if (seconds < 60) return 'Just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
    return new Date(date).toLocaleDateString();
  };

  // Get icon for notification type
  const getIcon = (type: string) => {
    switch (type) {
      case 'file_shared': return '📁';
      case 'admin_action': return '⚡';
      case 'storage_warning': return '⚠️';
      case 'public_access': return '🔗';
      default: return 'ℹ️';
    }
  };

  return (
    <div class="relative">
      {/* Bell Icon */}
      <button
        onClick={() => setIsOpen(!isOpen())}
        class="relative p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700 transition-colors"
      >
        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
        </svg>
        
        {/* Badge */}
        <Show when={unreadCount() > 0}>
          <span class="absolute top-0 right-0 inline-flex items-center justify-center px-1.5 py-0.5 text-xs font-bold leading-none text-white transform translate-x-1/2 -translate-y-1/2 bg-red-500 rounded-full min-w-[18px]">
            {unreadCount() > 99 ? '99+' : unreadCount()}
          </span>
        </Show>
      </button>

      {/* Dropdown Panel */}
      <Show when={isOpen()}>
        <div class="absolute right-0 mt-2 w-96 bg-gray-800 rounded-lg shadow-xl border border-gray-700 z-50 max-h-[600px] flex flex-col">
          {/* Header */}
          <div class="flex items-center justify-between p-4 border-b border-gray-700">
            <h3 class="text-lg font-semibold text-white">Notifications</h3>
            <div class="flex gap-2">
              <Show when={unreadCount() > 0}>
                <button
                  onClick={markAllAsRead}
                  class="text-xs text-primary-400 hover:text-primary-300"
                >
                  Mark all read
                </button>
              </Show>
              <Show when={notifications().length > 0}>
                <button
                  onClick={clearAll}
                  class="text-xs text-gray-400 hover:text-white"
                >
                  Clear all
                </button>
              </Show>
            </div>
          </div>

          {/* Notifications List */}
          <div class="overflow-y-auto flex-1">
            <Show
              when={!isLoading() && notifications().length > 0}
              fallback={
                <div class="p-8 text-center">
                  <Show when={isLoading()}>
                    <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500 mx-auto mb-2"></div>
                    <p class="text-gray-400 text-sm">Loading...</p>
                  </Show>
                  <Show when={!isLoading()}>
                    <svg class="w-12 h-12 mx-auto text-gray-600 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
                    </svg>
                    <p class="text-gray-400">No notifications</p>
                  </Show>
                </div>
              }
            >
              <For each={notifications()}>
                {(notification) => (
                  <div
                    class={`p-4 border-b border-gray-700 hover:bg-gray-750 transition-colors ${
                      !notification.read ? 'bg-gray-750/50' : ''
                    }`}
                  >
                    <div class="flex items-start gap-3">
                      <span class="text-2xl">{getIcon(notification.type)}</span>
                      <div class="flex-1 min-w-0">
                        <div class="flex items-start justify-between gap-2">
                          <h4 class={`text-sm font-medium ${!notification.read ? 'text-white' : 'text-gray-300'}`}>
                            {notification.title}
                          </h4>
                          <button
                            onClick={() => deleteNotification(notification.id)}
                            class="text-gray-500 hover:text-white text-xs"
                          >
                            ✕
                          </button>
                        </div>
                        <p class="text-sm text-gray-400 mt-1">{notification.message}</p>
                        <div class="flex items-center gap-3 mt-2">
                          <span class="text-xs text-gray-500">{timeAgo(notification.createdAt)}</span>
                          <Show when={!notification.read}>
                            <button
                              onClick={() => markAsRead(notification.id)}
                              class="text-xs text-primary-400 hover:text-primary-300"
                            >
                              Mark as read
                            </button>
                          </Show>
                          <Show when={notification.actionUrl}>
                            <a
                              href={notification.actionUrl!}
                              class="text-xs text-primary-400 hover:text-primary-300"
                              onClick={() => setIsOpen(false)}
                            >
                              View →
                            </a>
                          </Show>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </For>
            </Show>
          </div>
        </div>
      </Show>

      {/* Close on outside click */}
      <Show when={isOpen()}>
        <div
          class="fixed inset-0 z-40"
          onClick={() => setIsOpen(false)}
        />
      </Show>
    </div>
  );
}
