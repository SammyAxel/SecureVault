import { createSignal, createEffect, For, Show } from 'solid-js';
import { useAuth } from '../stores/auth.jsx';
import * as api from '../lib/api';
import type { FileItem } from '../lib/api';
import ShareModal from './ShareModal';
import NotificationCenter from './NotificationCenter';
import Breadcrumb from './Breadcrumb';
import { toast } from '../stores/toast';
import { openConfirm } from '../stores/confirm';
import { CsvPreview, ExcelPreview, WordPreview, getPreviewMimeType, isPreviewableFile, getFileExtension } from './FilePreview';
import { SkeletonDashboard } from './Skeleton';
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
} from '../lib/crypto';

// Helper to get MIME type from filename
function getMimeType(filename: string): string {
  return getPreviewMimeType(filename);
}

function isPreviewable(filename: string): boolean {
  return isPreviewableFile(filename);
}

interface DashboardProps {
  navigate?: (path: string) => void;
}

export default function Dashboard(props: DashboardProps) {
  const { user } = useAuth();
  const [files, setFiles] = createSignal<FileItem[]>([]);
  const [currentFolder, setCurrentFolder] = createSignal<string | null>(null);
  const [currentFolderUid, setCurrentFolderUid] = createSignal<string | null>(null);
  const [folderPath, setFolderPath] = createSignal<Array<{ id: string | null; uid: string | null; name: string }>>([{ id: null, uid: null, name: 'My Files' }]);
  const [isLoading, setIsLoading] = createSignal(false);
  const [isDragging, setIsDragging] = createSignal(false);
  const [uploadProgress, setUploadProgress] = createSignal<string | null>(null);
  
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

  // File type detection helpers
  const getFileCategory = (filename: string, isFolder: boolean): string => {
    if (isFolder) return 'folders';
    const ext = filename.split('.').pop()?.toLowerCase() || '';
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

  // Filtered and sorted files
  const filteredFiles = () => {
    let result = files();

    // Apply search
    const query = searchQuery().toLowerCase().trim();
    if (query) {
      result = result.filter(f => f.filename.toLowerCase().includes(query));
    }

    // Apply filter
    const filter = filterType();
    if (filter !== 'all') {
      result = result.filter(f => getFileCategory(f.filename, f.isFolder) === filter);
    }

    // Apply sort
    const sort = sortBy();
    const order = sortOrder();
    result = [...result].sort((a, b) => {
      let comparison = 0;
      
      // Folders first
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
  };

  // Load files
  const loadFiles = async () => {
    setIsLoading(true);
    try {
      const result = await api.listFiles(currentFolder() || undefined);
      setFiles(result.files);
    } catch (error) {
      console.error('Failed to load files:', error);
    } finally {
      setIsLoading(false);
    }
  };

  createEffect(() => {
    loadFiles();
  });

  // Close menu when clicking outside
  createEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (openMenuId() && !target.closest('.action-menu-container')) {
        setOpenMenuId(null);
        setMenuPosition(null);
      }
    };
    document.addEventListener('click', handleClickOutside);
    return () => document.removeEventListener('click', handleClickOutside);
  });

  // Navigate to folder (in dashboard, use FileViewer for UID-based navigation)
  const navigateToFolder = (folderId: string | null, folderName: string, folderUid?: string | null) => {
    if (folderId === null) {
      setFolderPath([{ id: null, uid: null, name: 'My Files' }]);
      setCurrentFolderUid(null);
      // Update URL to root
      if (props.navigate) {
        window.history.replaceState({}, '', '/');
      }
    } else {
      setFolderPath([...folderPath(), { id: folderId, uid: folderUid || null, name: folderName }]);
      setCurrentFolderUid(folderUid || null);
      // Update URL with folder UID
      if (props.navigate && folderUid) {
        window.history.replaceState({}, '', `/f/${folderUid}`);
      }
    }
    setCurrentFolder(folderId);
  };

  const navigateUp = (index: number) => {
    const newPath = folderPath().slice(0, index + 1);
    setFolderPath(newPath);
    const lastItem = newPath[newPath.length - 1];
    setCurrentFolder(lastItem.id);
    setCurrentFolderUid(lastItem.uid);
    // Update URL
    if (props.navigate) {
      if (lastItem.uid) {
        window.history.replaceState({}, '', `/f/${lastItem.uid}`);
      } else {
        window.history.replaceState({}, '', '/');
      }
    }
  };

  // Handle file upload
  const handleUpload = async (fileList: FileList) => {
    const keys = getCurrentKeys();
    if (!keys) {
      toast.error('Please login again - keys not found');
      return;
    }

    for (const file of Array.from(fileList)) {
      try {
        setUploadProgress(`Reading ${file.name}...`);

        // Read file
        const arrayBuffer = await file.arrayBuffer();

        setUploadProgress(`Calculating hash ${file.name}...`);
        
        // Calculate hash of original file (before encryption) for VirusTotal scanning
        const { calculateFileHash } = await import('../lib/crypto');
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
          currentFolder() || undefined
        );

        setUploadProgress(null);
        loadFiles();
      } catch (error: any) {
        console.error('Upload failed:', error);
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

      // Download
      const mimeType = getMimeType(file.filename);
      const blob = new Blob([decrypted], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setUploadProgress(null);
    } catch (error: any) {
      console.error('Download failed:', error);
      toast.error(`Failed to download: ${error.message}`);
      setUploadProgress(null);
    }
  };

  // Handle open/preview file
  const handleOpen = async (file: FileItem) => {
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
      if (props.navigate && file.uid) {
        window.history.replaceState({}, '', `/f/${file.uid}`);
      }
      setUploadProgress(null);
    } catch (error: any) {
      console.error('Open failed:', error);
      toast.error(`Failed to open: ${error.message}`);
      setUploadProgress(null);
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
    if (props.navigate) {
      const folderUid = currentFolderUid();
      if (folderUid) {
        window.history.replaceState({}, '', `/f/${folderUid}`);
      } else {
        window.history.replaceState({}, '', '/');
      }
    }
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
      console.error('Failed to copy UID link:', error);
      toast.error(`Failed to copy link: ${error.message}`);
    }
  };

  // Handle delete
  const handleDelete = async (file: FileItem) => {
    const confirmed = await openConfirm({
      title: 'Delete File',
      message: `Permanently delete "${file.filename}"? This cannot be undone.`,
      confirmText: 'Delete',
      type: 'danger',
    });
    if (!confirmed) return;

    try {
      await api.deleteFile(file.id);
      toast.success(`"${file.filename}" deleted successfully`);
      loadFiles();
    } catch (error: any) {
      toast.error(`Failed to delete: ${error.message}`);
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
      setSelectedFiles(new Set());
    } else {
      setSelectedFiles(new Set(visibleFiles.map(f => f.id)));
    }
  };

  const clearSelection = () => {
    setSelectedFiles(new Set());
  };

  // Bulk delete
  const handleBulkDelete = async () => {
    const selected = selectedFiles();
    if (selected.size === 0) return;

    const confirmed = await openConfirm({
      title: 'Delete Multiple Files',
      message: `Permanently delete ${selected.size} item(s)? This cannot be undone.`,
      confirmText: 'Delete All',
      type: 'danger',
    });
    if (!confirmed) return;

    let successCount = 0;
    let failCount = 0;

    for (const fileId of selected) {
      try {
        await api.deleteFile(fileId);
        successCount++;
      } catch (error) {
        failCount++;
      }
    }

    if (successCount > 0) {
      toast.success(`${successCount} item(s) deleted successfully`);
    }
    if (failCount > 0) {
      toast.error(`Failed to delete ${failCount} item(s)`);
    }

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
    // Prevent dropping folder into itself
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
    
    const file = draggedFile();
    if (!file) return;

    setDraggedFile(null);
    setDropTargetFolder(null);

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

  // Format file size
  const formatSize = (bytes: number) => {
    if (bytes === 0) return '—';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  // Storage usage
  const storagePercent = () => {
    const u = user();
    if (!u) return 0;
    return Math.round((u.storageUsed / u.storageQuota) * 100);
  };

  return (
    <div class="pb-20">
      {/* Top bar */}
      <div class="flex items-center justify-between mb-6">
        <div class="flex items-center gap-4">
          {/* Breadcrumb */}
          <Breadcrumb items={folderPath()} onNavigate={navigateUp} />
        </div>

        <div class="flex items-center gap-3">
          <NotificationCenter />
          
          <button
            onClick={openCreateFolderModal}
            class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm flex items-center gap-2"
          >
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 13h6m-3-3v6m-9 1V7a2 2 0 012-2h6l2 2h6a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z" />
            </svg>
            New Folder
          </button>

          <label class="px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg text-sm cursor-pointer flex items-center gap-2">
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
        </div>
      </div>

      {/* Storage indicator */}
      <div class="mb-6 bg-gray-800 rounded-lg p-4">
        <div class="flex items-center justify-between mb-2">
          <span class="text-sm text-gray-400">Storage Used</span>
          <span class="text-sm text-white">
            {formatSize(user()?.storageUsed || 0)} / {formatSize(user()?.storageQuota || 0)}
          </span>
        </div>
        <div class="w-full bg-gray-700 rounded-full h-2">
          <div
            class="bg-primary-500 h-2 rounded-full transition-all"
            style={{ width: `${storagePercent()}%` }}
          />
        </div>
      </div>

      {/* Search & Filter Bar */}
      <div class="mb-4 flex flex-wrap items-center gap-3">
        {/* Search Input */}
        <div class="relative flex-1 min-w-[200px]">
          <svg class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            placeholder="Search files..."
            value={searchQuery()}
            onInput={(e) => setSearchQuery(e.currentTarget.value)}
            class="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
          />
          <Show when={searchQuery()}>
            <button
              onClick={() => setSearchQuery('')}
              class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </Show>
        </div>

        {/* Filter by Type */}
        <select
          value={filterType()}
          onChange={(e) => setFilterType(e.currentTarget.value as any)}
          class="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-primary-500"
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
          onClick={() => setSortOrder(sortOrder() === 'asc' ? 'desc' : 'asc')}
          class="p-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
          title={sortOrder() === 'asc' ? 'Ascending' : 'Descending'}
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

      {/* Bulk Actions Bar */}
      <Show when={selectedFiles().size > 0}>
        <div class="mb-4 bg-primary-600/20 border border-primary-500 rounded-lg p-3 flex items-center justify-between">
          <div class="flex items-center gap-3">
            <span class="text-primary-300 font-medium">
              {selectedFiles().size} item(s) selected
            </span>
            <button
              onClick={clearSelection}
              class="text-primary-400 hover:text-primary-300 text-sm underline"
            >
              Clear selection
            </button>
          </div>
          <div class="flex items-center gap-2">
            <button
              onClick={openBulkMove}
              class="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm flex items-center gap-2 text-white"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
              </svg>
              Move
            </button>
            <button
              onClick={handleBulkDelete}
              class="px-3 py-1.5 bg-red-600 hover:bg-red-700 rounded-lg text-sm flex items-center gap-2 text-white"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
              Delete
            </button>
          </div>
        </div>
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
      <div
        class={`drop-zone ${isDragging() ? 'dragover' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        <Show when={isLoading()}>
          <SkeletonDashboard />
        </Show>

        {/* Empty state - no files at all */}
        <Show when={!isLoading() && files().length === 0}>
          <div class="py-12 text-center">
            <svg class="w-16 h-16 mx-auto text-gray-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
            </svg>
            <p class="text-gray-400 mb-2">Drag and drop files here</p>
            <p class="text-gray-500 text-sm">or click Upload button above</p>
          </div>
        </Show>

        {/* No search/filter results */}
        <Show when={!isLoading() && files().length > 0 && filteredFiles().length === 0}>
          <div class="py-12 text-center">
            <svg class="w-16 h-16 mx-auto text-gray-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            <p class="text-gray-400 mb-2">No matching files found</p>
            <p class="text-gray-500 text-sm">Try adjusting your search or filter criteria</p>
            <button
              onClick={() => { setSearchQuery(''); setFilterType('all'); }}
              class="mt-4 text-primary-400 hover:text-primary-300 text-sm"
            >
              Clear filters
            </button>
          </div>
        </Show>

        <Show when={!isLoading() && filteredFiles().length > 0}>
          <div class="rounded-lg border border-gray-700">
            <div class="overflow-x-auto">
              <table class="w-full">
                <thead class="bg-gray-800">
                  <tr>
                    <th class="w-10 px-4 py-3">
                      <input
                        type="checkbox"
                        checked={selectedFiles().size === filteredFiles().length && filteredFiles().length > 0}
                        onChange={toggleSelectAll}
                        class="w-4 h-4 rounded border-gray-600 bg-gray-700 text-primary-500 focus:ring-primary-500 focus:ring-offset-gray-800 cursor-pointer"
                      />
                    </th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Name</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Size</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Date</th>
                    <th class="px-4 py-3 text-right text-xs font-medium text-gray-400 uppercase">Actions</th>
                  </tr>
              </thead>
              <tbody class="divide-y divide-gray-700">
                <For each={filteredFiles()}>
                  {(file) => (
                    <tr 
                      class={`file-item ${selectedFiles().has(file.id) ? 'bg-primary-500/10' : ''} ${
                        file.isFolder && dropTargetFolder() === file.id ? 'bg-blue-500/20 ring-2 ring-blue-500' : ''
                      }`}
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
                        />
                      </td>
                      <td class="px-4 py-3">
                        <div class="flex items-center gap-3">
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
                              onClick={() => navigateToFolder(file.id, file.filename, file.uid)}
                              class="text-white hover:text-primary-400"
                            >
                              {file.filename}
                            </button>
                          ) : (
                            <span 
                              class={`text-white ${isPreviewable(file.filename) ? 'cursor-pointer hover:text-primary-400' : ''}`}
                              onClick={() => isPreviewable(file.filename) && handleOpen(file)}
                              title={isPreviewable(file.filename) ? 'Click to preview' : ''}
                            >
                              {file.filename}
                            </span>
                          )}
                        </div>
                      </td>
                      <td class="px-4 py-3 text-gray-400 text-sm">
                        {formatSize(file.fileSize)}
                      </td>
                      <td class="px-4 py-3 text-gray-400 text-sm">
                        {new Date(file.createdAt).toLocaleDateString()}
                      </td>
                      <td class="px-4 py-3 text-right">
                        <div class="relative action-menu-container">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              if (openMenuId() === file.id) {
                                setOpenMenuId(null);
                                setMenuPosition(null);
                              } else {
                                const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
                                setMenuPosition({ 
                                  top: rect.bottom + 4, 
                                  left: rect.right - 192 // 192px = w-48
                                });
                                setOpenMenuId(file.id);
                              }
                            }}
                            class="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
                            title="Actions"
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

      {/* Fixed Position Action Menu (Portal-like) */}
      <Show when={openMenuId() && menuPosition()}>
        {(() => {
          const file = files().find(f => f.id === openMenuId());
          if (!file) return null;
          const pos = menuPosition()!;
          return (
            <div 
              class="fixed w-48 bg-gray-800 border border-gray-700 rounded-lg shadow-xl z-50 action-menu-container"
              style={{ top: `${pos.top}px`, left: `${pos.left}px` }}
            >
              {!file.isFolder && isPreviewable(file.filename) && (
                <button
                  onClick={() => { handleOpen(file); setOpenMenuId(null); setMenuPosition(null); }}
                  class="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2 rounded-t-lg"
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                  </svg>
                  Open/Preview
                </button>
              )}
              <button
                onClick={() => { openRenameModal(file); setOpenMenuId(null); setMenuPosition(null); }}
                class="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                </svg>
                Rename
              </button>
              <button
                onClick={() => { openMoveModal(file); setOpenMenuId(null); setMenuPosition(null); }}
                class="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
                </svg>
                Move
              </button>
              <button
                onClick={() => { setShareFile(file); setOpenMenuId(null); setMenuPosition(null); }}
                class="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" />
                </svg>
                Share
              </button>
              {!file.isFolder && file.uid && (
                <button
                  onClick={() => { copyUIDLink(file); setOpenMenuId(null); setMenuPosition(null); }}
                  class="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2"
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                  </svg>
                  Copy Direct Link
                </button>
              )}
              {!file.isFolder && (
                <button
                  onClick={() => { handleDownload(file); setOpenMenuId(null); setMenuPosition(null); }}
                  class="w-full px-4 py-2 text-left text-sm text-gray-300 hover:bg-gray-700 flex items-center gap-2"
                >
                  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                  </svg>
                  Download
                </button>
              )}
              <button
                onClick={() => { handleDelete(file); setOpenMenuId(null); setMenuPosition(null); }}
                class="w-full px-4 py-2 text-left text-sm text-red-400 hover:bg-gray-700 flex items-center gap-2 rounded-b-lg"
              >
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
                Delete
              </button>
            </div>
          );
        })()}
      </Show>

      {/* Preview Modal */}
      <Show when={previewFile()}>
        <div class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4" onClick={closePreview}>
          <div class="bg-gray-800 rounded-xl max-w-5xl max-h-[90vh] w-full overflow-hidden" onClick={(e) => e.stopPropagation()}>
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
                <TextPreview url={previewFile()!.url} />
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
        <div class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4" onClick={() => setRenameFile(null)}>
          <div class="bg-gray-800 rounded-xl max-w-md w-full overflow-hidden" onClick={(e) => e.stopPropagation()}>
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
        <div class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4" onClick={() => setShowCreateFolder(false)}>
          <div class="bg-gray-800 rounded-xl max-w-md w-full overflow-hidden" onClick={(e) => e.stopPropagation()}>
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
        <div class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4" onClick={() => setMoveFile(null)}>
          <div class="bg-gray-800 rounded-xl max-w-md w-full overflow-hidden" onClick={(e) => e.stopPropagation()}>
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
        <div class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4" onClick={() => setBulkMoveOpen(false)}>
          <div class="bg-gray-800 rounded-xl max-w-md w-full overflow-hidden" onClick={(e) => e.stopPropagation()}>
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
    </div>
  );
}

// Text preview component
function TextPreview(props: { url: string }) {
  const [content, setContent] = createSignal<string>('Loading...');
  
  createEffect(async () => {
    try {
      const response = await fetch(props.url);
      const text = await response.text();
      setContent(text);
    } catch {
      setContent('Failed to load text content');
    }
  });
  
  return (
    <pre class="bg-gray-900 p-4 rounded-lg overflow-auto max-h-[70vh] text-sm text-gray-300 font-mono whitespace-pre-wrap">
      {content()}
    </pre>
  );
}
