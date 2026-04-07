import { createSignal, createEffect, createMemo, For, Show, onCleanup, onMount, untrack } from 'solid-js';
import { useAuth } from '../../stores/auth.jsx';
import * as api from '../../lib/api';
import { ApiError } from '../../lib/api';
import type { FileItem } from '../../lib/api';
import { formatSize } from '../../lib/format';
import ShareModal from '../ShareModal';
import NotificationCenter from '../NotificationCenter';
import Breadcrumb from '../Breadcrumb';
import { toast } from '../../stores/toast';
import { ROUTES, hrefWithCurrentSearch } from '../../lib/routes';
import { awaitMinElapsed, MIN_CONTENT_LOAD_MS } from '../../lib/motion';
import { getFileExtension } from '../../lib/files';
import { logger } from '../../lib/logger';
import { prefersExplicitSaveStep, saveBlobToDevice } from '../../lib/downloadBlob';
import BlobSavePrompt from '../BlobSavePrompt';
import { TRASH_RETENTION_DAYS } from '../../lib/config';
import { daysUntilTrashPurge } from '../../lib/trashUi';
import { openConfirm } from '../../stores/confirm';
import { isTypingInField } from '../../lib/keyboardShortcuts';
import { formatAbsolute, formatRelative } from '../../lib/time';
import { CsvPreview, ExcelPreview, WordPreview, getPreviewMimeType, isPreviewableFile } from '../FilePreview';
import { SkeletonDashboard } from '../Skeleton';
import DashboardTextPreview from './DashboardTextPreview';
import {
  getCurrentKeys,
  importEncryptionPrivateKey,
  importEncryptionPublicKey,
  encryptFile,
  decryptFile,
  wrapKey,
  unwrapKey,
  base64ToUint8Array,
  arrayBufferToBase64,
} from '../../lib/crypto';

// Helper to get MIME type from filename
function getMimeType(filename: string): string {
  return getPreviewMimeType(filename);
}

function isPreviewable(filename: string): boolean {
  return isPreviewableFile(filename);
}

interface DashboardProps {
  navigate?: (path: string) => void;
  /** Updates URL without a new history entry; keeps App route state in sync with `replaceState`. */
  replaceHref?: (href: string) => void;
  /** When provided, Dashboard will load this folder/file by UID and sync breadcrumbs. */
  uid?: string | null;
  /** Sidebar section (My Drive / Shared / Trash). */
  section?: 'drive' | 'shared' | 'trash';
  /** Used to normalize the URL back to `/` when leaving folder views. */
  onRequestNavigateRoot?: () => void;
  /** Committed search query from header (after Enter). */
  globalSearch?: string;
  /** Clear header search + `?q=` (e.g. “Clear filters”). */
  clearVaultSearch?: () => void;
  /** Brief overlay while search is applied. */
  searchLoading?: boolean;
}

export default function Dashboard(props: DashboardProps) {
  const { updateUser, user } = useAuth();
  const [files, setFiles] = createSignal<FileItem[]>([]);
  const [currentFolder, setCurrentFolder] = createSignal<string | null>(null);
  const [currentFolderUid, setCurrentFolderUid] = createSignal<string | null>(null);
  const [folderPath, setFolderPath] = createSignal<Array<{ id: string | null; uid: string | null; name: string }>>([{ id: null, uid: null, name: 'My Files' }]);
  const [isLoading, setIsLoading] = createSignal(false);
  const [loadError, setLoadError] = createSignal<string | null>(null);
  const [loadRetryNonce, setLoadRetryNonce] = createSignal(0);
  const [isDragging, setIsDragging] = createSignal(false);
  const [uploadProgress, setUploadProgress] = createSignal<string | null>(null);
  const [pendingBlobSave, setPendingBlobSave] = createSignal<{ blob: Blob; filename: string } | null>(null);
  
  // Preview state
  const [previewFile, setPreviewFile] = createSignal<{ url: string; filename: string; mimeType: string; fileUid?: string } | null>(null);
  
  // Share modal state
  const [shareFile, setShareFile] = createSignal<FileItem | null>(null);

  // Rename modal state
  const [renameFile, setRenameFile] = createSignal<FileItem | null>(null);
  const [renameName, setRenameName] = createSignal('');

  // Move modal state
  const [moveFile, setMoveFile] = createSignal<FileItem | null>(null);
  const [allFolders, setAllFolders] = createSignal<Array<{ id: string; filename: string; parentId: string | null }>>([]);
  const [selectedMoveTarget, setSelectedMoveTarget] = createSignal<string | null>(null);

  // Bulk selection state
  const [selectedFiles, setSelectedFiles] = createSignal<Set<string>>(new Set());
  
  // Drag file to folder state
  const [draggedFile, setDraggedFile] = createSignal<FileItem | null>(null);
  const [dropTargetFolder, setDropTargetFolder] = createSignal<string | null>(null);

  // Create folder modal state
  const [showCreateFolder, setShowCreateFolder] = createSignal(false);
  const [newFolderName, setNewFolderName] = createSignal('');

  // Search & Filter state
  const [searchQuery, setSearchQuery] = createSignal('');
  const [filterType, setFilterType] = createSignal<'all' | 'images' | 'documents' | 'videos' | 'audio' | 'folders'>('all');
  const [sortBy, setSortBy] = createSignal<'name' | 'date' | 'size'>('name');
  const [sortOrder, setSortOrder] = createSignal<'asc' | 'desc'>('asc');

  // Action menu dropdown state
  const [openMenuId, setOpenMenuId] = createSignal<string | null>(null);
  const [menuPosition, setMenuPosition] = createSignal<{ top: number; left: number } | null>(null);
  /** Keyboard highlight index in `filteredFiles()`; list region must be focused (Tab). */
  const [listNavIndex, setListNavIndex] = createSignal<number | null>(null);
  const section = () => props.section || 'drive';

  const listNavBlocked = () =>
    !!(
      previewFile() ||
      shareFile() ||
      renameFile() ||
      moveFile() ||
      showCreateFolder() ||
      openMenuId()
    );

  // Trash folder navigation state
  const [trashCurrentFolder, setTrashCurrentFolder] = createSignal<string | null>(null);
  const [trashFolderPath, setTrashFolderPath] = createSignal<Array<{ id: string | null; uid: string | null; name: string }>>([{ id: null, uid: null, name: 'Trash' }]);

  // Sync local search with global header search
  createEffect(() => {
    const q = props.globalSearch ?? '';
    if (q !== searchQuery()) setSearchQuery(q);
  });

  // File type detection helpers
  const getFileCategory = (filename: string, isFolder: boolean): string => {
    if (isFolder) return 'folders';
    const ext = getFileExtension(filename);
    const imageExts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'ico'];
    const videoExts = ['mp4', 'webm', 'ogg', 'mov', 'avi', 'mkv'];
    const audioExts = ['mp3', 'wav', 'flac', 'm4a', 'ogg', 'aac'];
    const docExts = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'md', 'csv', 'json'];
    
    if (imageExts.includes(ext)) return 'images';
    if (videoExts.includes(ext)) return 'videos';
    if (audioExts.includes(ext)) return 'audio';
    if (docExts.includes(ext)) return 'documents';
    return 'other';
  };

  // For trash: pre-filter files to only show items at the current trash navigation level
  const trashLevelFiles = createMemo((): FileItem[] => {
    if (section() !== 'trash') return files();
    const currentTrashFolder = trashCurrentFolder();
    const allFiles = files();
    if (currentTrashFolder === null) {
      // Root of trash: only show items whose parent is not also in the trash list
      const trashedIds = new Set(allFiles.map(f => f.id));
      return allFiles.filter(f => f.parentId === null || !trashedIds.has(f.parentId));
    } else {
      // Inside a trashed folder: show only direct children
      return allFiles.filter(f => f.parentId === currentTrashFolder);
    }
  });

  // Filtered and sorted files (memoized: JSX reads this multiple times per update)
  const filteredFiles = createMemo((): FileItem[] => {
    let result = trashLevelFiles();

    const query = searchQuery().toLowerCase().trim();
    if (query) {
      result = result.filter(f => f.filename.toLowerCase().includes(query));
    }

    const filter = filterType();
    if (filter !== 'all') {
      result = result.filter(f => getFileCategory(f.filename, f.isFolder) === filter);
    }

    const sort = sortBy();
    const order = sortOrder();
    result = [...result].sort((a, b) => {
      let comparison = 0;

      if (a.isFolder && !b.isFolder) return -1;
      if (!a.isFolder && b.isFolder) return 1;

      if (sort === 'name') {
        comparison = a.filename.localeCompare(b.filename);
      } else if (sort === 'date') {
        comparison = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
      } else if (sort === 'size') {
        comparison = a.fileSize - b.fileSize;
      }

      return order === 'asc' ? comparison : -comparison;
    });

    return result;
  });

  createEffect(() => {
    section();
    currentFolder();
    trashCurrentFolder();
    untrack(() => setListNavIndex(null));
  });

  createEffect(() => {
    const files = filteredFiles();
    const idx = listNavIndex();
    if (idx === null) return;
    untrack(() => {
      if (files.length === 0) setListNavIndex(null);
      else if (idx >= files.length) setListNavIndex(files.length - 1);
    });
  });

  // Load files for the active section
  const loadFiles = async () => {
    const started = Date.now();
    setLoadError(null);
    setIsLoading(true);
    try {
      if (section() === 'drive') {
        const sq = searchQuery().trim();
        const result = await api.listFiles(
          sq ? undefined : currentFolder() || undefined,
          sq || undefined,
        );
        setFiles(result.files);
        return;
      }
      if (section() === 'shared') {
        const result = await api.getSharedWithMe();
        // Map to FileItem shape (owner shown via filename suffix for now in UI layer below)
        setFiles(
          result.files.map((f: any) => ({
            id: f.id,
            uid: undefined,
            filename: f.filename,
            fileSize: f.fileSize,
            isFolder: f.isFolder,
            parentId: null,
            createdAt: f.sharedAt,
            encryptedKey: f.encryptedKey,
            iv: f.iv,
            owner: f.owner,
          }))
        );
        return;
      }
      if (section() === 'trash') {
        const result = await api.getTrash();
        setFiles(
          result.files.map((f: any) => ({
            id: f.id,
            uid: undefined,
            filename: f.filename,
            fileSize: f.fileSize,
            isFolder: f.isFolder,
            parentId: f.parentId,
            createdAt: f.deletedAt,
            deletedAt: f.deletedAt,
            encryptedKey: '',
            iv: '',
          }))
        );
        return;
      }
    } catch (error) {
      logger.error('Failed to load files:', error);
      const msg =
        error instanceof ApiError
          ? error.message
          : error instanceof Error
            ? error.message
            : 'Could not load this view.';
      setLoadError(msg);
    } finally {
      await awaitMinElapsed(started, MIN_CONTENT_LOAD_MS);
      setIsLoading(false);
    }
  };

  // Refresh user storage (so storage bar updates after upload/delete)
  const refreshStorage = async () => {
    try {
      const data = await api.getCurrentUser();
      if (data?.user) updateUser(data.user);
    } catch (_) {
      // Ignore; storage bar will update on next full refresh
    }
  };

  createEffect(() => {
    // Re-load when folder, section, vault search text, retry, or UID changes (UID effect below can also trigger load)
    section();
    currentFolder();
    searchQuery();
    loadRetryNonce();
    loadFiles();
  });

  // If route UID is provided (/f/:uid), hydrate currentFolder + breadcrumb path to match
  createEffect(() => {
    const uid = props.uid;
    if (!uid) return;
    if (section() !== 'drive') return; // only meaningful for My Drive

    let cancelled = false;
    onCleanup(() => {
      cancelled = true;
    });

    (async () => {
      try {
        const result = await api.getFileByUid(uid);
        if (cancelled) return;
        if (!result?.file) return;

        const root = { id: null, uid: null, name: 'My Files' as const };
        const parents = (result.parentPath || []).map((p) => ({ id: p.id, uid: p.uid, name: p.name }));
        const current = { id: result.file.id, uid: result.file.uid || null, name: result.file.filename };

        if (result.file.isFolder) {
          setFolderPath([root, ...parents, current]);
          setCurrentFolderUid(result.file.uid || null);
          setCurrentFolder(result.file.id);
        } else {
          // If UID points to a file, keep folder context but open preview (if possible)
          setFolderPath([root, ...parents]);
          setCurrentFolderUid(parents.length ? parents[parents.length - 1].uid : null);
          setCurrentFolder(parents.length ? parents[parents.length - 1].id : null);
          await handleOpen(result.file);
        }
      } catch (e) {
        if (cancelled) return;
        const is404 = e instanceof ApiError && e.status === 404;
        if (is404) {
          setFolderPath([{ id: null, uid: null, name: 'My Files' }]);
          setCurrentFolderUid(null);
          setCurrentFolder(null);
          props.onRequestNavigateRoot?.();
          return;
        }
        toast.error(e instanceof Error ? e.message : 'Could not open this link');
      }
    })();
  });

  const closeActionMenu = () => {
    setOpenMenuId(null);
    setMenuPosition(null);
  };

  // Close menu when clicking outside; Escape closes menu
  createEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (openMenuId() && !target.closest('.action-menu-container')) {
        closeActionMenu();
      }
    };
    document.addEventListener('click', handleClickOutside);
    return () => document.removeEventListener('click', handleClickOutside);
  });

  createEffect(() => {
    if (!openMenuId()) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') closeActionMenu();
    };
    document.addEventListener('keydown', onKey);
    onCleanup(() => document.removeEventListener('keydown', onKey));
  });

  createEffect(() => {
    const id = openMenuId();
    if (!id) return;
    const raf = requestAnimationFrame(() => {
      const root = document.getElementById(`action-menu-${id}`);
      const first = root?.querySelector<HTMLElement>('button, [href]');
      first?.focus();
    });
    onCleanup(() => cancelAnimationFrame(raf));
  });

  // Navigate to folder (Google Drive style)
  const navigateToFolder = (folderId: string | null, folderName: string, folderUid?: string | null) => {
    if (folderId === null) {
      setFolderPath([{ id: null, uid: null, name: 'My Files' }]);
      setCurrentFolderUid(null);
      setCurrentFolder(null);
      if (props.navigate) props.navigate(hrefWithCurrentSearch(ROUTES.drive));
    } else {
      setFolderPath([...folderPath(), { id: folderId, uid: folderUid || null, name: folderName }]);
      setCurrentFolderUid(folderUid || null);
      setCurrentFolder(folderId);
      if (props.navigate && folderUid) props.navigate(hrefWithCurrentSearch(`/f/${folderUid}`));
    }
  };

  const navigateUp = (index: number) => {
    const newPath = folderPath().slice(0, index + 1);
    setFolderPath(newPath);
    const lastItem = newPath[newPath.length - 1];
    setCurrentFolder(lastItem.id);
    setCurrentFolderUid(lastItem.uid);
    // Update URL so deep links remain stable
    if (props.navigate) {
      if (lastItem.uid) props.navigate(hrefWithCurrentSearch(`/f/${lastItem.uid}`));
      else props.navigate(hrefWithCurrentSearch(ROUTES.drive));
    }
  };

  const goToParentFolder = () => {
    const pathLen = folderPath().length;
    if (pathLen <= 1) return;
    navigateUp(pathLen - 2);
  };

  // Trash folder navigation
  const navigateIntoTrashFolder = (file: FileItem) => {
    setTrashCurrentFolder(file.id);
    setTrashFolderPath(prev => [...prev, { id: file.id, uid: null, name: file.filename }]);
  };

  const navigateTrashUp = (index: number) => {
    const newPath = trashFolderPath().slice(0, index + 1);
    setTrashFolderPath(newPath);
    const lastItem = newPath[newPath.length - 1];
    setTrashCurrentFolder(lastItem.id);
  };

  const goToParentTrashFolder = () => {
    const pathLen = trashFolderPath().length;
    if (pathLen <= 1) return;
    navigateTrashUp(pathLen - 2);
  };

  // Alt+↑ / ⌘+↑ — parent folder (My Drive + Trash), like Explorer / Finder
  onMount(() => {
    const onKey = (e: KeyboardEvent) => {
      if (isTypingInField(e.target)) return;
      if (listNavBlocked()) return;
      const sec = section();
      if (sec !== 'drive' && sec !== 'trash') return;
      const parentKey =
        (e.altKey && !e.metaKey && !e.ctrlKey && e.key === 'ArrowUp') ||
        (e.metaKey && !e.altKey && !e.ctrlKey && e.key === 'ArrowUp');
      if (!parentKey) return;
      e.preventDefault();
      if (sec === 'drive') {
        if (folderPath().length <= 1) return;
        goToParentFolder();
      } else {
        if (trashFolderPath().length <= 1) return;
        goToParentTrashFolder();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  });

  // Reset trash navigation when leaving trash section
  createEffect(() => {
    if (section() !== 'trash') {
      setTrashCurrentFolder(null);
      setTrashFolderPath([{ id: null, uid: null, name: 'Trash' }]);
    }
  });

  // Handle file upload (optional targetFolderId = upload into that folder; else current folder)
  const handleUpload = async (fileList: FileList, targetFolderId?: string | null) => {
    const keys = getCurrentKeys();
    if (!keys) {
      toast.error('Please login again - keys not found');
      return;
    }

    const parentId = targetFolderId !== undefined ? targetFolderId : currentFolder();

    for (const file of Array.from(fileList)) {
      try {
        setUploadProgress(`Reading ${file.name}...`);

        // Read file
        const arrayBuffer = await file.arrayBuffer();

        setUploadProgress(`Calculating hash ${file.name}...`);
        
        // Calculate hash of original file (before encryption) for VirusTotal scanning
        const { calculateFileHash } = await import('../../lib/crypto');
        const fileHash = await calculateFileHash(arrayBuffer);

        setUploadProgress(`Encrypting ${file.name}...`);

        // Encrypt file
        const { encrypted, key, iv } = await encryptFile(arrayBuffer);

        // Wrap key with user's public key
        const publicKey = await importEncryptionPublicKey(keys.encryptionPublicKey);
        const wrappedKey = await wrapKey(key, publicKey);

        setUploadProgress(`Uploading ${file.name}...`);

        // Upload
        await api.uploadFile(
          file,
          encrypted,
          wrappedKey,
          arrayBufferToBase64(iv),
          fileHash,
          parentId || undefined
        );

        setUploadProgress(null);
        loadFiles();
        await refreshStorage();
      } catch (error: any) {
        logger.error('Upload failed:', error);
        if (error?.data?.quotaExceeded) {
          toast.error(error.message); // e.g. "Storage quota exceeded. You have X bytes remaining."
        } else if (error?.data?.malwareDetected) {
          toast.error(`Upload blocked: ${error.message}`);
        } else {
          toast.error(`Failed to upload ${file.name}: ${error.message}`);
        }
        setUploadProgress(null);
      }
    }
  };

  // Handle download
  const handleDownload = async (file: FileItem) => {
    const keys = getCurrentKeys();
    if (!keys) {
      toast.error('Please login again - keys not found');
      return;
    }

    if (pendingBlobSave()) {
      toast.warning('Finish saving the current file or cancel first.');
      return;
    }

    try {
      setUploadProgress(`Downloading ${file.filename}...`);

      // Download encrypted file
      const { data, encryptedKey, iv } = await api.downloadFile(file.id);

      setUploadProgress(`Decrypting ${file.filename}...`);

      // Unwrap key
      const privateKey = await importEncryptionPrivateKey(keys.encryptionPrivateKey);
      const fileKey = await unwrapKey(encryptedKey, privateKey);

      // Decrypt file
      const decrypted = await decryptFile(data, fileKey, base64ToUint8Array(iv));

      const mimeType = getMimeType(file.filename);
      const blob = new Blob([decrypted], { type: mimeType });

      // Mobile: programmatic download after async work often fails (lost user activation).
      if (prefersExplicitSaveStep()) {
        setPendingBlobSave({ blob, filename: file.filename });
      } else {
        await saveBlobToDevice(blob, file.filename);
      }

      setUploadProgress(null);
    } catch (error: any) {
      logger.error('Download failed:', error);
      toast.error(`Failed to download: ${error.message}`);
      setUploadProgress(null);
    }
  };

  // Handle open/preview file
  async function handleOpen(file: FileItem) {
    const keys = getCurrentKeys();
    if (!keys) {
      toast.error('Please login again - keys not found');
      return;
    }

    try {
      setUploadProgress(`Opening ${file.filename}...`);

      // Download encrypted file
      const { data, encryptedKey, iv } = await api.downloadFile(file.id);

      // Unwrap key
      const privateKey = await importEncryptionPrivateKey(keys.encryptionPrivateKey);
      const fileKey = await unwrapKey(encryptedKey, privateKey);

      // Decrypt file
      const decrypted = await decryptFile(data, fileKey, base64ToUint8Array(iv));

      // Create blob URL for preview
      const mimeType = getMimeType(file.filename);
      const blob = new Blob([decrypted], { type: mimeType });
      const url = URL.createObjectURL(blob);

      setPreviewFile({ url, filename: file.filename, mimeType, fileUid: file.uid });
      // Update URL with file UID
      if (file.uid) {
        const href = hrefWithCurrentSearch(`/f/${file.uid}`);
        if (props.replaceHref) props.replaceHref(href);
        else window.history.replaceState({}, '', href);
      }
      setUploadProgress(null);
    } catch (error: any) {
      logger.error('Open failed:', error);
      toast.error(`Failed to open: ${error.message}`);
      setUploadProgress(null);
    }
  }

  const scrollListRowIntoView = (idx: number) => {
    queueMicrotask(() => {
      document.getElementById(`sv-list-row-${idx}`)?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    });
  };

  function activateFileRow(file: FileItem) {
    if (file.isFolder) {
      if (section() === 'trash') {
        navigateIntoTrashFolder(file);
        return;
      }
      if (section() !== 'drive') {
        toast.info(
          'Open shared folders from My Drive if you own them, or use the top search to find a file by name.'
        );
        return;
      }
      navigateToFolder(file.id, file.filename, file.uid);
      return;
    }
    if (section() !== 'trash' && isPreviewable(file.filename)) {
      void handleOpen(file);
    }
  }

  const handleListRegionKeyDown = (e: KeyboardEvent) => {
    if (listNavBlocked()) return;
    const files = filteredFiles();
    if (files.length === 0) return;

    let idx = listNavIndex();
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (idx === null) idx = 0;
      else idx = Math.min(files.length - 1, idx + 1);
      setListNavIndex(idx);
      scrollListRowIntoView(idx);
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (idx === null) idx = files.length - 1;
      else idx = Math.max(0, idx - 1);
      setListNavIndex(idx);
      scrollListRowIntoView(idx);
      return;
    }
    if (e.key === 'Home' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      setListNavIndex(0);
      scrollListRowIntoView(0);
      return;
    }
    if (e.key === 'End' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      setListNavIndex(files.length - 1);
      scrollListRowIntoView(files.length - 1);
      return;
    }
    if (e.key === 'Enter' && idx !== null) {
      e.preventDefault();
      const file = files[idx];
      if (file) activateFileRow(file);
      return;
    }
    if (e.key === 'Escape' && idx !== null) {
      e.preventDefault();
      setListNavIndex(null);
    }
  };

  // Close preview
  const closePreview = () => {
    const preview = previewFile();
    if (preview) {
      URL.revokeObjectURL(preview.url);
    }
    setPreviewFile(null);
    // Reset URL to current folder
    const folderUid = currentFolderUid();
    const href = folderUid
      ? hrefWithCurrentSearch(`/f/${folderUid}`)
      : hrefWithCurrentSearch(ROUTES.drive);
    if (props.replaceHref) props.replaceHref(href);
    else window.history.replaceState({}, '', href);
  };

  // Copy UID link to clipboard
  const copyUIDLink = async (file: FileItem) => {
    if (!file.uid) {
      toast.error('UID not available for this file');
      return;
    }

    const keys = getCurrentKeys();
    if (!keys) {
      toast.error('Please login again - keys not found');
      return;
    }

    try {
      // Download to get encryption info
      const { encryptedKey, iv } = await api.downloadFile(file.id);

      // Unwrap key
      const privateKey = await importEncryptionPrivateKey(keys.encryptionPrivateKey);
      const fileKey = await unwrapKey(encryptedKey, privateKey);

      // Export raw key to base64
      const rawKey = await crypto.subtle.exportKey('raw', fileKey);
      const keyBase64 = arrayBufferToBase64(rawKey);

      // Build URL with key and IV in fragment
      const baseUrl = window.location.origin;
      const url = `${baseUrl}/f/${file.uid}#${keyBase64}:${iv}`;

      await navigator.clipboard.writeText(url);
      toast.success('Link copied to clipboard!');
    } catch (error: any) {
      logger.error('Failed to copy UID link:', error);
      toast.error(`Failed to copy link: ${error.message}`);
    }
  };

  // Handle delete
  const handleDelete = async (file: FileItem) => {
    const confirmed = await openConfirm({
      title: 'Delete File',
      message: `Move "${file.filename}" to Trash? You can restore it later from Trash.`,
      confirmText: 'Move to Trash',
      type: 'danger',
    });
    if (!confirmed) return;

    try {
      await api.deleteFile(file.id);
      toast.success(`Moved "${file.filename}" to Trash`);
      loadFiles();
      await refreshStorage();
    } catch (error: any) {
      toast.error(`Failed to delete: ${error.message}`);
    }
  };

  const handleRestore = async (file: FileItem) => {
    const confirmed = await openConfirm({
      title: 'Restore item?',
      message: `Restore "${file.filename}" back to My Drive?`,
      confirmText: 'Restore',
      type: 'info',
    });
    if (!confirmed) return;

    try {
      await api.restoreFile(file.id);
      toast.success(`Restored "${file.filename}"`);
      loadFiles();
    } catch (error: any) {
      toast.error(`Failed to restore: ${error.message}`);
    }
  };

  const handlePermanentDelete = async (file: FileItem) => {
    const confirmed = await openConfirm({
      title: 'Delete permanently?',
      message: `Permanently delete "${file.filename}"? This cannot be undone.`,
      confirmText: 'Delete permanently',
      type: 'danger',
    });
    if (!confirmed) return;

    try {
      await api.deleteFile(file.id, true);
      toast.success(`Deleted "${file.filename}" permanently`);
      loadFiles();
      await refreshStorage();
    } catch (error: any) {
      toast.error(`Failed to delete permanently: ${error.message}`);
    }
  };

  const handleEmptyTrash = async () => {
    const confirmed = await openConfirm({
      title: 'Empty Trash?',
      message: 'Permanently delete everything in Trash? This cannot be undone.',
      confirmText: 'Empty Trash',
      type: 'danger',
    });
    if (!confirmed) return;

    try {
      const res = await api.emptyTrash();
      toast.success(`Trash emptied (${res.deletedCount} item(s) deleted)`);
      clearSelection();
      loadFiles();
      await refreshStorage();
    } catch (error: any) {
      toast.error(`Failed to empty trash: ${error.message}`);
    }
  };

  // Handle rename
  const openRenameModal = (file: FileItem) => {
    setRenameFile(file);
    setRenameName(file.filename);
  };

  const handleRename = async () => {
    const file = renameFile();
    if (!file || !renameName().trim()) return;

    try {
      await api.renameFile(file.id, renameName().trim());
      setRenameFile(null);
      setRenameName('');
      toast.success('File renamed successfully');
      loadFiles();
    } catch (error: any) {
      toast.error(`Failed to rename: ${error.message}`);
    }
  };

  // Handle move
  const openMoveModal = async (file: FileItem) => {
    try {
      const result = await api.getAllFolders();
      // Filter out the file itself if it's a folder (can't move into itself or descendants)
      const filteredFolders = result.folders.filter(f => f.id !== file.id);
      setAllFolders(filteredFolders);
      setMoveFile(file);
      setSelectedMoveTarget(file.parentId);
    } catch (error: any) {
      toast.error(`Failed to load folders: ${error.message}`);
    }
  };

  const handleMove = async () => {
    const file = moveFile();
    if (!file) return;

    try {
      await api.moveFile(file.id, selectedMoveTarget());
      setMoveFile(null);
      setAllFolders([]);
      toast.success('File moved successfully');
      loadFiles();
    } catch (error: any) {
      toast.error(`Failed to move: ${error.message}`);
    }
  };

  // Create folder
  const openCreateFolderModal = () => {
    setNewFolderName('');
    setShowCreateFolder(true);
  };

  const handleCreateFolder = async () => {
    const name = newFolderName().trim();
    if (!name) return;

    try {
      await api.createFolder(name, currentFolder() || undefined);
      toast.success('Folder created successfully');
      setShowCreateFolder(false);
      setNewFolderName('');
      loadFiles();
    } catch (error: any) {
      toast.error(`Failed to create folder: ${error.message}`);
    }
  };

  // Bulk selection handlers
  const toggleFileSelection = (fileId: string) => {
    const newSelected = new Set(selectedFiles());
    if (newSelected.has(fileId)) {
      newSelected.delete(fileId);
    } else {
      newSelected.add(fileId);
    }
    setSelectedFiles(newSelected);
  };

  const toggleSelectAll = () => {
    const visibleFiles = filteredFiles();
    if (selectedFiles().size === visibleFiles.length) {
      setSelectedFiles(new Set<string>());
    } else {
      setSelectedFiles(new Set(visibleFiles.map((f) => f.id)));
    }
  };

  const clearSelection = () => {
    setSelectedFiles(new Set<string>());
  };

  // Bulk delete
  const handleBulkDelete = async () => {
    const selected = selectedFiles();
    if (selected.size === 0) return;

    const confirmed = await openConfirm({
      title: 'Delete Multiple Files',
      message:
        section() === 'trash'
          ? `Permanently delete ${selected.size} item(s)? This cannot be undone.`
          : `Move ${selected.size} item(s) to Trash? You can restore them later from Trash.`,
      confirmText: section() === 'trash' ? 'Delete Permanently' : 'Move to Trash',
      type: 'danger',
    });
    if (!confirmed) return;

    let successCount = 0;
    let failCount = 0;

    for (const fileId of selected) {
      try {
        await api.deleteFile(fileId, section() === 'trash');
        successCount++;
      } catch (error) {
        failCount++;
      }
    }

    if (successCount > 0) {
      toast.success(
        section() === 'trash'
          ? `${successCount} item(s) deleted permanently`
          : `${successCount} item(s) moved to Trash`
      );
      if (section() !== 'shared') await refreshStorage();
    }
    if (failCount > 0) {
      toast.error(`Failed to delete ${failCount} item(s)`);
    }

    clearSelection();
    loadFiles();
  };

  const handleBulkRestore = async () => {
    const selected = selectedFiles();
    if (selected.size === 0) return;

    const confirmed = await openConfirm({
      title: 'Restore multiple items?',
      message: `Restore ${selected.size} item(s) back to My Drive?`,
      confirmText: 'Restore',
      type: 'info',
    });
    if (!confirmed) return;

    let successCount = 0;
    let failCount = 0;

    for (const fileId of selected) {
      try {
        await api.restoreFile(fileId);
        successCount++;
      } catch (_) {
        failCount++;
      }
    }

    if (successCount > 0) toast.success(`${successCount} item(s) restored`);
    if (failCount > 0) toast.error(`Failed to restore ${failCount} item(s)`);

    clearSelection();
    loadFiles();
  };

  // Bulk move
  const [bulkMoveOpen, setBulkMoveOpen] = createSignal(false);

  const openBulkMove = async () => {
    if (selectedFiles().size === 0) return;
    try {
      const result = await api.getAllFolders();
      // Filter out selected folders (can't move into themselves)
      const filteredFolders = result.folders.filter(f => !selectedFiles().has(f.id));
      setAllFolders(filteredFolders);
      setBulkMoveOpen(true);
      setSelectedMoveTarget(currentFolder());
    } catch (error: any) {
      toast.error(`Failed to load folders: ${error.message}`);
    }
  };

  const handleBulkMove = async () => {
    const selected = selectedFiles();
    if (selected.size === 0) return;

    let successCount = 0;
    let failCount = 0;

    for (const fileId of selected) {
      try {
        await api.moveFile(fileId, selectedMoveTarget());
        successCount++;
      } catch (error) {
        failCount++;
      }
    }

    if (successCount > 0) {
      toast.success(`${successCount} item(s) moved successfully`);
    }
    if (failCount > 0) {
      toast.error(`Failed to move ${failCount} item(s)`);
    }

    setBulkMoveOpen(false);
    clearSelection();
    loadFiles();
  };

  // Drag file to folder handlers
  const handleFileDragStart = (e: DragEvent, file: FileItem) => {
    setDraggedFile(file);
    e.dataTransfer!.effectAllowed = 'move';
    e.dataTransfer!.setData('text/plain', file.id);
  };

  const handleFileDragEnd = () => {
    setDraggedFile(null);
    setDropTargetFolder(null);
  };

  const handleFolderDragOver = (e: DragEvent, folderId: string) => {
    e.preventDefault();
    e.stopPropagation();
    const dragged = draggedFile();
    const hasExternalFiles = e.dataTransfer?.types?.includes('Files');
    // External files from OS: allow drop to upload into this folder
    if (hasExternalFiles) {
      e.dataTransfer!.dropEffect = 'copy';
      setDropTargetFolder(folderId);
      return;
    }
    // Internal drag (move existing file/folder): prevent dropping folder into itself
    if (dragged && dragged.id !== folderId) {
      e.dataTransfer!.dropEffect = 'move';
      setDropTargetFolder(folderId);
    }
  };

  const handleFolderDragLeave = (e: DragEvent) => {
    e.preventDefault();
    setDropTargetFolder(null);
  };

  const handleFolderDrop = async (e: DragEvent, folderId: string) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    setDropTargetFolder(null);

    // External files from OS: upload into this folder
    const files = e.dataTransfer?.files;
    if (files?.length) {
      handleUpload(files, folderId);
      return;
    }

    // Internal drag: move existing file/folder
    const file = draggedFile();
    if (!file) return;

    setDraggedFile(null);

    // Don't move to same parent
    if (file.parentId === folderId) return;
    
    // Don't move folder into itself
    if (file.id === folderId) {
      toast.error("Cannot move a folder into itself");
      return;
    }

    try {
      await api.moveFile(file.id, folderId);
      toast.success(`"${file.filename}" moved successfully`);
      loadFiles();
    } catch (error: any) {
      toast.error(`Failed to move: ${error.message}`);
    }
  };

  // Drag and drop (for file upload)
  const handleDragOver = (e: DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer?.files) {
      handleUpload(e.dataTransfer.files);
    }
  };

  return (
    <div class="pb-20">
      {/* Top bar: stacks on mobile */}
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 sm:gap-4 mb-4 sm:mb-6">
        <div class="min-w-0 flex-1 flex flex-col gap-1">
          <Show
            when={section() === 'drive'}
            fallback={
              <Show
                when={section() === 'trash'}
                fallback={
                  <div class="min-w-0">
                    <div class="flex items-center gap-2">
                      <h2 class="text-lg sm:text-xl font-semibold text-white">Shared with me</h2>
                    </div>
                    <p class="text-xs text-gray-500 mt-1 max-w-xl">
                      Tip: use the search bar to find a file by name. Folder trees you own are easiest to browse in{' '}
                      <button
                        type="button"
                        class="text-primary-400 hover:text-primary-300 underline"
                        onClick={() => props.navigate?.(hrefWithCurrentSearch(ROUTES.drive))}
                      >
                        My Drive
                      </button>
                      — click any folder in the path bar to jump out of deep nesting.
                    </p>
                  </div>
                }
              >
                <div class="flex items-start gap-2 min-w-0">
                  <Show when={trashFolderPath().length > 1}>
                    <button
                      type="button"
                      onClick={goToParentTrashFolder}
                      class="shrink-0 flex items-center gap-1.5 px-2.5 py-2 rounded-lg border border-gray-600 bg-gray-800/90 hover:bg-gray-700 text-gray-200 text-sm touch-target"
                      title="Up one level (Alt+↑ or ⌘+↑)"
                      aria-label="Up one folder"
                    >
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
                        <path
                          stroke-linecap="round"
                          stroke-linejoin="round"
                          stroke-width="2"
                          d="M5 10l7-7m0 0l7 7m-7-7v18"
                        />
                      </svg>
                      <span class="hidden sm:inline">Up</span>
                    </button>
                  </Show>
                  <div class="min-w-0 flex-1">
                    <Breadcrumb items={trashFolderPath()} onNavigate={navigateTrashUp} />
                  </div>
                </div>
              </Show>
            }
          >
            <div class="flex items-start gap-2 min-w-0">
              <Show when={folderPath().length > 1}>
                <button
                  type="button"
                  onClick={goToParentFolder}
                  class="shrink-0 flex items-center gap-1.5 px-2.5 py-2 rounded-lg border border-gray-600 bg-gray-800/90 hover:bg-gray-700 text-gray-200 text-sm touch-target"
                  title="Up one level (Alt+↑ or ⌘+↑)"
                  aria-label="Up one folder"
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M5 10l7-7m0 0l7 7m-7-7v18"
                    />
                  </svg>
                  <span class="hidden sm:inline">Up</span>
                </button>
              </Show>
              <div class="min-w-0 flex-1 pt-0.5">
                <Breadcrumb items={folderPath()} onNavigate={navigateUp} />
                <Show when={folderPath().length > 2}>
                  <p class="text-xs text-gray-500 mt-1 hidden sm:block">
                    Click an earlier folder in the path to jump back without opening each one.
                  </p>
                </Show>
              </div>
            </div>
          </Show>
        </div>

        <div class="flex items-center gap-2 sm:gap-3 shrink-0 flex-wrap">
          <NotificationCenter />
          
          <Show when={section() === 'drive'}>
            <button
              type="button"
              onClick={openCreateFolderModal}
              class="px-3 py-2 sm:px-4 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm flex items-center gap-2 touch-target sm:min-h-0"
              title="New Folder"
              aria-label="New folder"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 13h6m-3-3v6m-9 1V7a2 2 0 012-2h6l2 2h6a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z" />
              </svg>
              <span class="hidden sm:inline">New Folder</span>
            </button>

            <label class="px-3 py-2 sm:px-4 bg-primary-600 hover:bg-primary-700 rounded-lg text-sm cursor-pointer flex items-center gap-2 touch-target sm:min-h-0" aria-label="Upload files">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
              </svg>
              Upload
              <input
                type="file"
                multiple
                accept="*/*"
                class="hidden"
                onChange={(e) => e.target.files && handleUpload(e.target.files)}
              />
            </label>
          </Show>

          <Show when={section() === 'trash' && files().length > 0}>
            <button
              type="button"
              onClick={handleEmptyTrash}
              class="px-3 py-2 sm:px-4 bg-red-600/90 hover:bg-red-600 rounded-lg text-sm flex items-center gap-2 text-white touch-target sm:min-h-0"
              title="Empty Trash"
              aria-label="Empty trash"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
              <span class="hidden sm:inline">Empty Trash</span>
            </button>
          </Show>
        </div>
      </div>

      {/* Filters */}
      <div class="mb-4 flex flex-wrap items-center gap-2 sm:gap-3">

          {/* Filter by Type */}
          <select
            value={filterType()}
            onChange={(e) => setFilterType(e.currentTarget.value as any)}
            class="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 min-w-0"
          >
            <option value="all">All Types</option>
            <option value="folders">📁 Folders</option>
            <option value="images">🖼️ Images</option>
            <option value="documents">📄 Documents</option>
            <option value="videos">🎬 Videos</option>
            <option value="audio">🎵 Audio</option>
          </select>

          {/* Sort By */}
          <select
            value={sortBy()}
            onChange={(e) => setSortBy(e.currentTarget.value as any)}
            class="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            <option value="name">Sort by Name</option>
            <option value="date">Sort by Date</option>
            <option value="size">Sort by Size</option>
          </select>

          {/* Sort Order Toggle */}
          <button
            type="button"
            onClick={() => setSortOrder(sortOrder() === 'asc' ? 'desc' : 'asc')}
            class="p-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
            title={sortOrder() === 'asc' ? 'Ascending' : 'Descending'}
            aria-label={sortOrder() === 'asc' ? 'Sort ascending' : 'Sort descending'}
          >
            <Show when={sortOrder() === 'asc'} fallback={
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4h13M3 8h9m-9 4h9m5-4v12m0 0l-4-4m4 4l4-4" />
              </svg>
            }>
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4h13M3 8h9m-9 4h6m4 0l4-4m0 0l4 4m-4-4v12" />
              </svg>
            </Show>
          </button>

          {/* Results count */}
          <Show when={searchQuery() || filterType() !== 'all'}>
            <span class="text-gray-400 text-sm">
              {filteredFiles().length} result(s)
            </span>
          </Show>
      </div>

      <Show when={section() === 'drive' && searchQuery().trim()}>
        <p class="text-xs text-gray-500 mb-3">
          Searching names across your whole My Drive, including inside nested folders.
        </p>
      </Show>

      <Show when={loadError() && !isLoading()}>
        <div class="mb-4 bg-red-900/20 border border-red-800/60 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <p class="text-sm text-red-200">{loadError()}</p>
          <button
            type="button"
            onClick={() => setLoadRetryNonce((n) => n + 1)}
            class="shrink-0 px-4 py-2 rounded-lg bg-gray-700 hover:bg-gray-600 text-white text-sm"
          >
            Retry
          </button>
        </div>
      </Show>

      <Show when={section() === 'trash' && trashCurrentFolder() === null && !loadError()}>
        <div class="mb-4 rounded-xl border border-amber-800/50 bg-amber-950/30 px-4 py-3 text-sm text-amber-100/90">
          Items in Trash are permanently removed after{' '}
          <span class="font-medium text-amber-50">{TRASH_RETENTION_DAYS}</span> days. Restore anything you still need
          before then.
        </div>
      </Show>

      {/* Bulk Actions Bar */}
      <Show when={selectedFiles().size > 0}>
        <div class="mb-4 bg-primary-600/20 border border-primary-500 rounded-lg p-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div class="flex items-center gap-3 min-w-0">
            <span class="text-primary-300 font-medium truncate">
              {selectedFiles().size} item(s) selected
            </span>
            <button
              onClick={clearSelection}
              class="text-primary-400 hover:text-primary-300 text-sm underline shrink-0"
            >
              Clear selection
            </button>
          </div>
          <div class="flex items-center gap-2 flex-wrap">
            <Show when={section() === 'drive'}>
              <button
                onClick={openBulkMove}
                class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm flex items-center gap-2 text-white"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
                </svg>
                Move
              </button>
            </Show>

            <Show when={section() === 'trash'}>
              <button
                onClick={handleBulkRestore}
                class="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 rounded-lg text-sm flex items-center gap-2 text-white"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 12a8 8 0 018-8v4l3-3-3-3v4a10 10 0 00-9.95 9H4zm16 0a8 8 0 01-8 8v-4l-3 3 3 3v-4a10 10 0 009.95-9H20z" />
                </svg>
                Restore
              </button>
            </Show>

            <button
              onClick={handleBulkDelete}
              class="px-3 py-1.5 bg-red-600 hover:bg-red-700 rounded-lg text-sm flex items-center gap-2 text-white"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
              {section() === 'trash' ? 'Delete permanently' : 'Move to Trash'}
            </button>
          </div>
        </div>
      </Show>

      <Show when={section() === 'drive' && !loadError()}>
        {(() => {
          const u = user();
          if (!u) return null;
          const pct = Math.min(100, Math.round((u.storageUsed / Math.max(1, u.storageQuota)) * 100));
          if (pct < 80) return null;
          const danger = pct >= 90;
          return (
            <div
              class={`mb-4 rounded-xl px-4 py-3 text-sm border ${
                danger
                  ? 'bg-red-500/10 border-red-500/30 text-red-200'
                  : 'bg-amber-500/10 border-amber-500/30 text-amber-100'
              }`}
              role="status"
            >
              <div class="font-semibold">{danger ? 'Storage almost full' : 'Storage running low'}</div>
              <div class="opacity-90">
                You are using <span class="font-medium">{pct}%</span> of your quota. Consider deleting or moving large files to
                Trash.
              </div>
            </div>
          );
        })()}
      </Show>

      {/* Upload progress */}
      <Show when={uploadProgress()}>
        <div class="mb-6 bg-primary-500/20 border border-primary-500 rounded-lg p-4 flex items-center gap-3">
          <svg class="animate-spin h-5 w-5 text-primary-500" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none" />
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
          </svg>
          <span class="text-primary-300">{uploadProgress()}</span>
        </div>
      </Show>

      {/* Drop zone / File list */}
      <div class="relative">
        <div
          class={section() === 'drive' ? `drop-zone ${isDragging() ? 'dragover' : ''}` : 'rounded-xl'}
          onDragOver={section() === 'drive' ? handleDragOver : undefined}
          onDragLeave={section() === 'drive' ? handleDragLeave : undefined}
          onDrop={section() === 'drive' ? handleDrop : undefined}
        >
          <Show when={isLoading()}>
            <SkeletonDashboard />
          </Show>

        {/* Empty state - no files at all */}
        <Show when={!isLoading() && !loadError() && trashLevelFiles().length === 0}>
          <div class="py-12 text-center max-w-lg mx-auto px-2">
            <svg class="w-16 h-16 mx-auto text-gray-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden>
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
            </svg>
            <Show
              when={section() === 'drive'}
              fallback={
                <div class="space-y-3">
                  <Show
                    when={section() === 'shared'}
                    fallback={
                      <div class="space-y-2">
                        <p class="text-gray-300 font-medium">
                          {trashCurrentFolder() !== null ? 'This folder is empty.' : 'Trash is empty.'}
                        </p>
                        <Show when={section() === 'trash' && trashCurrentFolder() === null}>
                          <p class="text-gray-500 text-sm">
                            Deleted items are removed for good after {TRASH_RETENTION_DAYS} days.
                          </p>
                        </Show>
                        <Show when={section() === 'trash' && trashCurrentFolder() === null}>
                          <button
                            type="button"
                            onClick={() => props.navigate?.(hrefWithCurrentSearch(ROUTES.drive))}
                            class="inline-flex items-center justify-center px-4 py-2 rounded-lg bg-primary-600 hover:bg-primary-700 text-white text-sm font-medium"
                          >
                            Go to My Drive
                          </button>
                        </Show>
                      </div>
                    }
                  >
                    <p class="text-gray-300">Nothing shared with you yet.</p>
                    <p class="text-gray-500 text-sm">
                      When someone shares a file or folder, it will appear here. You still decrypt it with your own keys.
                    </p>
                    <button
                      type="button"
                      onClick={() => props.navigate?.(hrefWithCurrentSearch(ROUTES.drive))}
                      class="inline-flex items-center justify-center px-4 py-2 rounded-lg bg-gray-700 hover:bg-gray-600 text-white text-sm"
                    >
                      Back to My Drive
                    </button>
                  </Show>
                </div>
              }
            >
              <p class="text-gray-400 mb-2">Drag and drop files here</p>
              <p class="text-gray-500 text-sm mb-4">or use Upload above</p>
              <button
                type="button"
                onClick={() => props.navigate?.(hrefWithCurrentSearch(ROUTES.home))}
                class="text-primary-400 hover:text-primary-300 text-sm underline"
              >
                View suggestions on Home
              </button>
            </Show>
          </div>
        </Show>

        {/* No search/filter results */}
        <Show when={!isLoading() && !loadError() && trashLevelFiles().length > 0 && filteredFiles().length === 0}>
          <div class="py-12 text-center">
            <svg class="w-16 h-16 mx-auto text-gray-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <p class="text-gray-400 mb-2">No matching files found</p>
            <p class="text-gray-500 text-sm">Try adjusting your search or filter criteria</p>
            <button
              onClick={() => {
                setSearchQuery('');
                setFilterType('all');
                props.clearVaultSearch?.();
              }}
              class="mt-4 text-primary-400 hover:text-primary-300 text-sm"
            >
              Clear filters
            </button>
          </div>
        </Show>

        <Show when={!isLoading() && !loadError() && filteredFiles().length > 0}>
          <div
            class="rounded-lg border border-gray-700 bg-gray-900/20 outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary-500/90"
            tabIndex={0}
            role="region"
            aria-label="Files and folders. Use arrow keys to move, Enter to open."
            onKeyDown={handleListRegionKeyDown}
            onFocus={() => {
              if (listNavBlocked()) return;
              const n = filteredFiles().length;
              if (n > 0 && listNavIndex() === null) setListNavIndex(0);
            }}
            onBlur={(e) => {
              const next = e.relatedTarget as Node | null;
              if (next && e.currentTarget.contains(next)) return;
              setListNavIndex(null);
            }}
          >
            <div class="overflow-x-auto -mx-px">
              <table class="w-full min-w-[520px] table-fixed">
                <thead class="bg-gray-800">
                  <tr>
                    <th class="w-10 px-4 py-3">
                      <input
                        type="checkbox"
                        checked={selectedFiles().size === filteredFiles().length && filteredFiles().length > 0}
                        onChange={toggleSelectAll}
                        class="w-4 h-4 rounded border-gray-600 bg-gray-700 text-primary-500 focus:ring-primary-500 focus:ring-offset-gray-800 cursor-pointer"
                        aria-label="Select all items"
                      />
                    </th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase w-[min(40%,280px)] min-w-0">Name</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase w-24 whitespace-nowrap">Size</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase min-w-[8.5rem] whitespace-nowrap">
                      {section() === 'trash' ? 'Removed' : 'Date'}
                    </th>
                    <th class="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase w-24 whitespace-nowrap">Actions</th>
                  </tr>
              </thead>
              <tbody class="divide-y divide-gray-700">
                <For each={filteredFiles()}>
                  {(file, index) => (
                    <tr 
                      id={`sv-list-row-${index()}`}
                      class={`file-item ${selectedFiles().has(file.id) ? 'bg-primary-500/10' : ''} ${
                        file.isFolder && dropTargetFolder() === file.id ? 'bg-blue-500/20 ring-2 ring-blue-500' : ''
                      } ${listNavIndex() === index() ? 'bg-primary-500/15 ring-1 ring-inset ring-primary-500/45' : ''}`}
                      draggable={true}
                      onDragStart={(e) => handleFileDragStart(e, file)}
                      onDragEnd={handleFileDragEnd}
                      onDragOver={(e) => file.isFolder && draggedFile()?.id !== file.id && handleFolderDragOver(e, file.id)}
                      onDragLeave={(e) => file.isFolder && handleFolderDragLeave(e)}
                      onDrop={(e) => file.isFolder && handleFolderDrop(e, file.id)}
                    >
                      <td class="w-10 px-4 py-3">
                        <input
                          type="checkbox"
                          checked={selectedFiles().has(file.id)}
                          onChange={() => toggleFileSelection(file.id)}
                          class="w-4 h-4 rounded border-gray-600 bg-gray-700 text-primary-500 focus:ring-primary-500 focus:ring-offset-gray-800 cursor-pointer"
                          onClick={(e) => e.stopPropagation()}
                          aria-label={`Select ${file.filename}`}
                        />
                      </td>
                      <td class="px-4 py-3 min-w-0">
                        <div class="flex items-center gap-3 min-w-0">
                          {file.isFolder ? (
                            <svg class="w-5 h-5 text-yellow-500 flex-shrink-0 cursor-grab" fill="currentColor" viewBox="0 0 20 20">
                              <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
                            </svg>
                          ) : (
                            <svg class="w-5 h-5 text-gray-400 flex-shrink-0 cursor-grab" fill="currentColor" viewBox="0 0 20 20">
                              <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clip-rule="evenodd" />
                            </svg>
                          )}
                          {/* File/Folder name with click to preview for files */}
                          {file.isFolder ? (
                            <button
                              type="button"
                              onClick={() => {
                                setListNavIndex(index());
                                activateFileRow(file);
                              }}
                              class="text-white hover:text-primary-400 text-left"
                            >
                              {file.filename}
                              <Show when={(file as any).owner}>
                                <div class="text-xs text-gray-500 mt-0.5">
                                  Shared by {(file as any).owner}
                                </div>
                              </Show>
                            </button>
                          ) : (
                            <button
                              type="button"
                              class={`text-left min-w-0 ${
                                section() === 'trash'
                                  ? 'text-gray-400 cursor-default'
                                  : `text-white ${isPreviewable(file.filename) ? 'hover:text-primary-400' : ''}`
                              }`}
                              disabled={section() === 'trash'}
                              onClick={() => {
                                setListNavIndex(index());
                                if (section() !== 'trash' && isPreviewable(file.filename)) void handleOpen(file);
                              }}
                              title={
                                section() === 'trash'
                                  ? 'Preview is not available in Trash'
                                  : isPreviewable(file.filename)
                                    ? 'Click to preview'
                                    : ''
                              }
                            >
                              {file.filename}
                              <Show when={(file as any).owner}>
                                <div class="text-xs text-gray-500 mt-0.5">
                                  Shared by {(file as any).owner}
                                </div>
                              </Show>
                            </button>
                          )}
                        </div>
                      </td>
                      <td class="px-4 py-3 text-gray-400 text-sm whitespace-nowrap tabular-nums">
                        {formatSize(file.fileSize, { zero: 'dash' })}
                      </td>
                      <td class="px-4 py-3 text-gray-400 text-sm min-w-0">
                        <div class="whitespace-nowrap" title={formatAbsolute(file.createdAt)}>
                          {formatRelative(file.createdAt)}
                        </div>
                        <Show when={section() === 'trash' && file.deletedAt}>
                          <div class="text-xs text-gray-500 mt-0.5">
                            Deletes in {daysUntilTrashPurge(file.deletedAt!)}d
                          </div>
                        </Show>
                      </td>
                      <td class="px-4 py-3 text-right">
                        <div class="relative action-menu-container">
                          <button
                            type="button"
                            id={`file-actions-trigger-${file.id}`}
                            aria-label={`Actions for ${file.filename}`}
                            aria-haspopup="menu"
                            aria-expanded={openMenuId() === file.id}
                            aria-controls={openMenuId() === file.id ? `action-menu-${file.id}` : undefined}
                            onClick={(e) => {
                              e.stopPropagation();
                              if (openMenuId() === file.id) {
                                closeActionMenu();
                              } else {
                                const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
                                const menuW = 192;
                                const pad = 8;
                                let left = rect.right - menuW;
                                left = Math.max(pad, Math.min(left, window.innerWidth - menuW - pad));
                                setMenuPosition({ 
                                  top: rect.bottom + 4, 
                                  left
                                });
                                setOpenMenuId(file.id);
                              }
                            }}
                            class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
                          >
                            <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                              <path d="M10 6a2 2 0 110-4 2 2 0 010 4zM10 12a2 2 0 110-4 2 2 0 010 4zM10 18a2 2 0 110-4 2 2 0 010 4z" />
                            </svg>
                          </button>
                        </div>
                      </td>
                    </tr>
                  )}
                </For>
              </tbody>
            </table>
            </div>
          </div>
        </Show>
      </div>
      <Show when={props.searchLoading}>
        <div class="absolute inset-0 z-10 flex items-center justify-center bg-gray-900/55 backdrop-blur-[1px] rounded-xl pointer-events-none min-h-[120px]">
          <div class="flex flex-col items-center gap-2">
            <div class="animate-spin rounded-full h-10 w-10 border-2 border-primary-400 border-t-transparent" />
            <p class="text-sm text-gray-300">Searching…</p>
          </div>
        </div>
      </Show>
      </div>

      {/* Fixed Position Action Menu (Portal-like) */}
      <Show when={openMenuId() && menuPosition()}>
        {(() => {
          const file = files().find(f => f.id === openMenuId());
          if (!file) return null;
          const pos = menuPosition()!;
          return (
            <div 
              id={`action-menu-${file.id}`}
              role="menu"
              aria-labelledby={`file-actions-trigger-${file.id}`}
              class="fixed w-48 max-w-[calc(100vw-1rem)] bg-gray-800 border border-gray-700 rounded-lg shadow-xl z-50 action-menu-container"
              style={{ top: `${pos.top}px`, left: `${pos.left}px` }}
            >
              {!file.isFolder && isPreviewable(file.filename) && (
                <button
                  onClick={() => { handleOpen(file); closeActionMenu(); }}
                  class="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2 rounded-t-lg"
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                  </svg>
                  Open/Preview
                </button>
              )}

              {section() === 'trash' && (
                <>
                  <button
                    onClick={() => { handleRestore(file); closeActionMenu(); }}
                    class="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2 rounded-t-lg"
                  >
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 12a8 8 0 018-8v4l3-3-3-3v4a10 10 0 00-9.95 9H4zm16 0a8 8 0 01-8 8v-4l-3 3 3 3v-4a10 10 0 009.95-9H20z" />
                    </svg>
                    Restore
                  </button>
                  <button
                    onClick={() => { handlePermanentDelete(file); closeActionMenu(); }}
                    class="w-full px-4 py-2 text-left text-sm text-red-400 hover:bg-gray-700 flex items-center gap-2 rounded-b-lg"
                  >
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                    Delete permanently
                  </button>
                </>
              )}

              <Show when={section() === 'drive'}>
                <button
                  onClick={() => { openRenameModal(file); closeActionMenu(); }}
                  class="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2"
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                  </svg>
                  Rename
                </button>
                <button
                  onClick={() => { openMoveModal(file); closeActionMenu(); }}
                  class="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2"
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
                  </svg>
                  Move
                </button>
                <button
                  onClick={() => { setShareFile(file); closeActionMenu(); }}
                  class="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2"
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" />
                  </svg>
                  Share
                </button>
                {!file.isFolder && file.uid && (
                  <button
                    onClick={() => { copyUIDLink(file); closeActionMenu(); }}
                    class="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2"
                  >
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                    </svg>
                    Copy Direct Link
                  </button>
                )}
              </Show>
              {section() !== 'trash' && !file.isFolder && (
                <button
                  type="button"
                  disabled={!!pendingBlobSave()}
                  onClick={() => { handleDownload(file); closeActionMenu(); }}
                  class="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:bg-transparent"
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                  </svg>
                  Download
                </button>
              )}
              <Show when={section() === 'drive'}>
                <button
                  onClick={() => { handleDelete(file); closeActionMenu(); }}
                  class="w-full px-4 py-2 text-left text-sm text-red-400 hover:bg-gray-700 flex items-center gap-2 rounded-b-lg"
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                  Delete
                </button>
              </Show>
            </div>
          );
        })()}
      </Show>

      {/* Preview Modal */}
      <Show when={previewFile()}>
        <div
          class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-2 sm:p-4 sv-modal-overlay"
          onClick={closePreview}
        >
          <div
            class="bg-gray-800 rounded-xl max-w-5xl max-h-[calc(100vh-2rem)] w-full overflow-hidden sv-modal-panel"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div class="flex items-center justify-between px-4 py-3 border-b border-gray-700">
              <h3 class="text-lg font-medium text-white truncate">{previewFile()?.filename}</h3>
              <button
                onClick={closePreview}
                class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            
            {/* Modal Content */}
            <div class="p-4 overflow-auto max-h-[calc(90vh-60px)]">
              {/* Image Preview */}
              <Show when={previewFile()?.mimeType.startsWith('image/')}>
                <img 
                  src={previewFile()?.url} 
                  alt={previewFile()?.filename}
                  class="max-w-full max-h-[70vh] mx-auto rounded-lg"
                />
              </Show>
              
              {/* Video Preview */}
              <Show when={previewFile()?.mimeType.startsWith('video/')}>
                <video 
                  src={previewFile()?.url} 
                  controls 
                  class="max-w-full max-h-[70vh] mx-auto rounded-lg"
                />
              </Show>
              
              {/* Audio Preview */}
              <Show when={previewFile()?.mimeType.startsWith('audio/')}>
                <div class="flex flex-col items-center gap-4 py-8">
                  <svg class="w-24 h-24 text-gray-500" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M12 3v10.55c-.59-.34-1.27-.55-2-.55-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4V7h4V3h-6z"/>
                  </svg>
                  <audio src={previewFile()?.url} controls class="w-full max-w-md" />
                </div>
              </Show>
              
              {/* PDF Preview */}
              <Show when={previewFile()?.mimeType === 'application/pdf'}>
                <iframe 
                  src={previewFile()?.url} 
                  class="w-full h-[70vh] rounded-lg bg-white"
                />
              </Show>
              
              {/* CSV Preview */}
              <Show when={previewFile()?.mimeType === 'text/csv'}>
                <CsvPreview url={previewFile()!.url} />
              </Show>
              
              {/* Excel Preview */}
              <Show when={previewFile()?.mimeType.includes('spreadsheet') || previewFile()?.mimeType.includes('excel')}>
                <ExcelPreview url={previewFile()!.url} />
              </Show>
              
              {/* Word Preview */}
              <Show when={previewFile()?.mimeType.includes('wordprocessingml') || previewFile()?.mimeType === 'application/msword'}>
                <WordPreview url={previewFile()!.url} />
              </Show>
              
              {/* Text/Code Preview */}
              <Show when={
                (previewFile()?.mimeType.startsWith('text/') && previewFile()?.mimeType !== 'text/csv') || 
                previewFile()?.mimeType === 'application/json'
              }>
                <DashboardTextPreview url={previewFile()!.url} />
              </Show>
            </div>
          </div>
        </div>
      </Show>

      {/* Share Modal */}
      <Show when={shareFile()}>
        <ShareModal 
          file={shareFile()!} 
          onClose={() => setShareFile(null)} 
        />
      </Show>

      {/* Rename Modal */}
      <Show when={renameFile()}>
        <div
          class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4 sv-modal-overlay"
          onClick={() => setRenameFile(null)}
        >
          <div
            class="bg-gray-800 rounded-xl max-w-md w-full overflow-hidden sv-modal-panel"
            onClick={(e) => e.stopPropagation()}
          >
            <div class="flex items-center justify-between px-6 py-4 border-b border-gray-700">
              <h3 class="text-lg font-medium text-white">Rename</h3>
              <button
                onClick={() => setRenameFile(null)}
                class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div class="p-6">
              <label class="block text-sm text-gray-400 mb-2">New name</label>
              <input
                type="text"
                value={renameName()}
                onInput={(e) => setRenameName(e.currentTarget.value)}
                class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
                onKeyDown={(e) => e.key === 'Enter' && handleRename()}
              />
              <div class="flex justify-end gap-3 mt-6">
                <button
                  onClick={() => setRenameFile(null)}
                  class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-300"
                >
                  Cancel
                </button>
                <button
                  onClick={handleRename}
                  class="px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg text-white"
                >
                  Rename
                </button>
              </div>
            </div>
          </div>
        </div>
      </Show>

      {/* Create Folder Modal */}
      <Show when={showCreateFolder()}>
        <div
          class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4 sv-modal-overlay"
          onClick={() => setShowCreateFolder(false)}
        >
          <div
            class="bg-gray-800 rounded-xl max-w-md w-full overflow-hidden sv-modal-panel"
            onClick={(e) => e.stopPropagation()}
          >
            <div class="flex items-center justify-between px-6 py-4 border-b border-gray-700">
              <h3 class="text-lg font-medium text-white">Create New Folder</h3>
              <button
                onClick={() => setShowCreateFolder(false)}
                class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div class="p-6">
              <label class="block text-sm text-gray-400 mb-2">Folder name</label>
              <input
                type="text"
                value={newFolderName()}
                onInput={(e) => setNewFolderName(e.currentTarget.value)}
                placeholder="Enter folder name..."
                class="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
                onKeyDown={(e) => e.key === 'Enter' && handleCreateFolder()}
                autofocus
              />
              <div class="flex justify-end gap-3 mt-6">
                <button
                  onClick={() => setShowCreateFolder(false)}
                  class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-300"
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreateFolder}
                  disabled={!newFolderName().trim()}
                  class="px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg text-white disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Create Folder
                </button>
              </div>
            </div>
          </div>
        </div>
      </Show>

      {/* Move Modal */}
      <Show when={moveFile()}>
        <div
          class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4 sv-modal-overlay"
          onClick={() => setMoveFile(null)}
        >
          <div
            class="bg-gray-800 rounded-xl max-w-md w-full overflow-hidden sv-modal-panel"
            onClick={(e) => e.stopPropagation()}
          >
            <div class="flex items-center justify-between px-6 py-4 border-b border-gray-700">
              <h3 class="text-lg font-medium text-white">Move to...</h3>
              <button
                onClick={() => setMoveFile(null)}
                class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div class="p-6 max-h-96 overflow-y-auto">
              <p class="text-sm text-gray-400 mb-4">Select destination folder for "{moveFile()?.filename}"</p>
              
              {/* Root option */}
              <button
                onClick={() => setSelectedMoveTarget(null)}
                class={`w-full flex items-center gap-3 px-4 py-3 rounded-lg mb-2 ${
                  selectedMoveTarget() === null ? 'bg-primary-600' : 'bg-gray-700 hover:bg-gray-600'
                }`}
              >
                <svg class="w-5 h-5 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M10.707 2.293a1 1 0 00-1.414 0l-7 7a1 1 0 001.414 1.414L4 10.414V17a1 1 0 001 1h2a1 1 0 001-1v-2a1 1 0 011-1h2a1 1 0 011 1v2a1 1 0 001 1h2a1 1 0 001-1v-6.586l.293.293a1 1 0 001.414-1.414l-7-7z" />
                </svg>
                <span class="text-white">Root (My Files)</span>
              </button>
              
              {/* Folders */}
              <For each={allFolders()}>
                {(folder) => (
                  <button
                    onClick={() => setSelectedMoveTarget(folder.id)}
                    class={`w-full flex items-center gap-3 px-4 py-3 rounded-lg mb-2 ${
                      selectedMoveTarget() === folder.id ? 'bg-primary-600' : 'bg-gray-700 hover:bg-gray-600'
                    }`}
                  >
                    <svg class="w-5 h-5 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
                      <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
                    </svg>
                    <span class="text-white">{folder.filename}</span>
                  </button>
                )}
              </For>
              
              {allFolders().length === 0 && (
                <p class="text-gray-500 text-center py-4">No folders available</p>
              )}
            </div>
            <div class="flex justify-end gap-3 px-6 py-4 border-t border-gray-700">
              <button
                onClick={() => setMoveFile(null)}
                class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-300"
              >
                Cancel
              </button>
              <button
                onClick={handleMove}
                class="px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg text-white"
              >
                Move Here
              </button>
            </div>
          </div>
        </div>
      </Show>

      {/* Bulk Move Modal */}
      <Show when={bulkMoveOpen()}>
        <div
          class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4 sv-modal-overlay"
          onClick={() => setBulkMoveOpen(false)}
        >
          <div
            class="bg-gray-800 rounded-xl max-w-md w-full overflow-hidden sv-modal-panel"
            onClick={(e) => e.stopPropagation()}
          >
            <div class="flex items-center justify-between px-6 py-4 border-b border-gray-700">
              <h3 class="text-lg font-medium text-white">Move {selectedFiles().size} item(s) to...</h3>
              <button
                onClick={() => setBulkMoveOpen(false)}
                class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div class="p-6 max-h-96 overflow-y-auto">
              <p class="text-sm text-gray-400 mb-4">Select destination folder</p>
              
              {/* Root option */}
              <button
                onClick={() => setSelectedMoveTarget(null)}
                class={`w-full flex items-center gap-3 px-4 py-3 rounded-lg mb-2 ${
                  selectedMoveTarget() === null ? 'bg-primary-600' : 'bg-gray-700 hover:bg-gray-600'
                }`}
              >
                <svg class="w-5 h-5 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M10.707 2.293a1 1 0 00-1.414 0l-7 7a1 1 0 001.414 1.414L4 10.414V17a1 1 0 001 1h2a1 1 0 001-1v-2a1 1 0 011-1h2a1 1 0 011 1v2a1 1 0 001 1h2a1 1 0 001-1v-6.586l.293.293a1 1 0 001.414-1.414l-7-7z" />
                </svg>
                <span class="text-white">Root (My Files)</span>
              </button>
              
              {/* Folders */}
              <For each={allFolders()}>
                {(folder) => (
                  <button
                    onClick={() => setSelectedMoveTarget(folder.id)}
                    class={`w-full flex items-center gap-3 px-4 py-3 rounded-lg mb-2 ${
                      selectedMoveTarget() === folder.id ? 'bg-primary-600' : 'bg-gray-700 hover:bg-gray-600'
                    }`}
                  >
                    <svg class="w-5 h-5 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
                      <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
                    </svg>
                    <span class="text-white">{folder.filename}</span>
                  </button>
                )}
              </For>
              
              {allFolders().length === 0 && (
                <p class="text-gray-500 text-center py-4">No folders available</p>
              )}
            </div>
            <div class="flex justify-end gap-3 px-6 py-4 border-t border-gray-700">
              <button
                onClick={() => setBulkMoveOpen(false)}
                class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-gray-300"
              >
                Cancel
              </button>
              <button
                onClick={handleBulkMove}
                class="px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg text-white"
              >
                Move Here
              </button>
            </div>
          </div>
        </div>
      </Show>

      <BlobSavePrompt
        pending={pendingBlobSave()}
        onClose={() => setPendingBlobSave(null)}
      />
    </div>
  );
}
