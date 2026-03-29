import { createSignal, createEffect, Show, For, lazy, Suspense } from 'solid-js';
import { getFileExtension } from '../lib/files';
import { logger } from '../lib/logger';
import { awaitMinElapsed, MIN_CONTENT_LOAD_MS } from '../lib/motion';

const ExcelPreviewLazy = lazy(() =>
  import('./FilePreviewExcel').then((m) => ({ default: m.ExcelPreview }))
);
const WordPreviewLazy = lazy(() =>
  import('./FilePreviewWord').then((m) => ({ default: m.WordPreview }))
);

function PreviewChunkFallback() {
  return (
    <div class="flex items-center justify-center p-8 bg-gray-900 rounded-lg">
      <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500" />
    </div>
  );
}

export function ExcelPreview(props: { url: string }) {
  return (
    <Suspense fallback={<PreviewChunkFallback />}>
      <ExcelPreviewLazy {...props} />
    </Suspense>
  );
}

export function WordPreview(props: { url: string }) {
  return (
    <Suspense fallback={<PreviewChunkFallback />}>
      <WordPreviewLazy {...props} />
    </Suspense>
  );
}

// ============ CSV Preview ============
export function CsvPreview(props: { url: string }) {
  const [data, setData] = createSignal<string[][]>([]);
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);

  createEffect(async () => {
    const started = Date.now();
    try {
      setLoading(true);
      const response = await fetch(props.url);
      const text = await response.text();
      
      // Parse CSV
      const rows = parseCSV(text);
      setData(rows);
    } catch (err) {
      setError('Failed to load CSV');
      logger.error(err);
    } finally {
      await awaitMinElapsed(started, MIN_CONTENT_LOAD_MS);
      setLoading(false);
    }
  });

  return (
    <div class="overflow-auto max-h-[70vh] bg-gray-900 rounded-lg">
      <Show when={loading()}>
        <div class="flex items-center justify-center p-8">
          <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
        </div>
      </Show>
      
      <Show when={error()}>
        <div class="text-red-400 p-4">{error()}</div>
      </Show>
      
      <Show when={!loading() && !error() && data().length > 0}>
        <table class="min-w-full text-sm text-gray-300">
          <thead class="bg-gray-800 sticky top-0">
            <tr>
              <For each={data()[0]}>
                {(cell) => (
                  <th class="px-3 py-2 text-left font-medium text-gray-200 border-b border-gray-700">
                    {cell}
                  </th>
                )}
              </For>
            </tr>
          </thead>
          <tbody>
            <For each={data().slice(1)}>
              {(row, rowIndex) => (
                <tr class={rowIndex() % 2 === 0 ? 'bg-gray-850' : 'bg-gray-900'}>
                  <For each={row}>
                    {(cell) => (
                      <td class="px-3 py-2 border-b border-gray-800 whitespace-nowrap">
                        {cell}
                      </td>
                    )}
                  </For>
                </tr>
              )}
            </For>
          </tbody>
        </table>
      </Show>
    </div>
  );
}

// ============ Text Preview ============
export function TextPreview(props: { url: string; filename: string }) {
  const [content, setContent] = createSignal<string>('');
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);

  createEffect(async () => {
    const started = Date.now();
    try {
      setLoading(true);
      const response = await fetch(props.url);
      const text = await response.text();
      setContent(text);
    } catch (err) {
      setError('Failed to load file');
      logger.error(err);
    } finally {
      await awaitMinElapsed(started, MIN_CONTENT_LOAD_MS);
      setLoading(false);
    }
  });

  // Determine if content is JSON for pretty printing
  const isJson = () => getFileExtension(props.filename) === 'json';

  const displayContent = () => {
    if (isJson()) {
      try {
        const parsed = JSON.parse(content());
        return JSON.stringify(parsed, null, 2);
      } catch {
        return content();
      }
    }
    return content();
  };

  return (
    <div class="overflow-auto max-h-[80vh] bg-gray-100 py-8">
      <Show when={loading()}>
        <div class="flex items-center justify-center p-8">
          <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
        </div>
      </Show>
      
      <Show when={error()}>
        <div class="bg-white max-w-5xl w-full mx-auto shadow-xl rounded-sm p-12">
          <div class="text-red-600">{error()}</div>
        </div>
      </Show>
      
      <Show when={!loading() && !error()}>
        <div class="bg-white max-w-5xl w-full mx-auto shadow-xl rounded-sm p-12">
          <pre class="whitespace-pre-wrap break-words font-mono text-sm text-gray-900 leading-relaxed">
            <code>{displayContent()}</code>
          </pre>
        </div>
      </Show>
    </div>
  );
}

// ============ CSV Parser Helper ============
function parseCSV(text: string): string[][] {
  const rows: string[][] = [];
  let currentRow: string[] = [];
  let currentCell = '';
  let inQuotes = false;
  
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    const nextChar = text[i + 1];
    
    if (inQuotes) {
      if (char === '"' && nextChar === '"') {
        // Escaped quote
        currentCell += '"';
        i++; // Skip next quote
      } else if (char === '"') {
        // End of quoted field
        inQuotes = false;
      } else {
        currentCell += char;
      }
    } else {
      if (char === '"') {
        // Start of quoted field
        inQuotes = true;
      } else if (char === ',') {
        // End of cell
        currentRow.push(currentCell.trim());
        currentCell = '';
      } else if (char === '\n' || (char === '\r' && nextChar === '\n')) {
        // End of row
        currentRow.push(currentCell.trim());
        if (currentRow.some(cell => cell !== '')) {
          rows.push(currentRow);
        }
        currentRow = [];
        currentCell = '';
        if (char === '\r') i++; // Skip \n after \r
      } else if (char !== '\r') {
        currentCell += char;
      }
    }
  }
  
  // Handle last row
  if (currentCell || currentRow.length > 0) {
    currentRow.push(currentCell.trim());
    if (currentRow.some(cell => cell !== '')) {
      rows.push(currentRow);
    }
  }
  
  return rows;
}

// ============ MIME type helpers ============
export function getPreviewMimeType(filename: string): string {
  const ext = getFileExtension(filename);
  const mimeTypes: Record<string, string> = {
    // Images
    'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png',
    'gif': 'image/gif', 'webp': 'image/webp', 'svg': 'image/svg+xml', 'bmp': 'image/bmp',
    // Video
    'mp4': 'video/mp4', 'webm': 'video/webm', 'ogg': 'video/ogg', 'mov': 'video/quicktime',
    // Audio
    'mp3': 'audio/mpeg', 'wav': 'audio/wav', 'flac': 'audio/flac', 'm4a': 'audio/mp4',
    // Documents
    'pdf': 'application/pdf',
    'csv': 'text/csv',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'xls': 'application/vnd.ms-excel',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'doc': 'application/msword',
    // Text
    'txt': 'text/plain', 'md': 'text/markdown', 'json': 'application/json',
    'js': 'text/javascript', 'ts': 'text/typescript', 'html': 'text/html',
    'css': 'text/css', 'py': 'text/x-python', 'xml': 'text/xml',
    'yaml': 'text/yaml', 'yml': 'text/yaml', 'ini': 'text/plain',
    'log': 'text/plain', 'sh': 'text/x-shellscript', 'sql': 'text/x-sql',
  };
  return mimeTypes[ext] || 'application/octet-stream';
}

export function isPreviewableFile(filename: string): boolean {
  const ext = getFileExtension(filename);
  const previewable = [
    // Images
    'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp',
    // Video
    'mp4', 'webm', 'ogg', 'mov',
    // Audio
    'mp3', 'wav', 'flac', 'm4a',
    // Documents
    'pdf', 'csv', 'xlsx', 'xls', 'docx',
    // Text/Code
    'txt', 'md', 'json', 'js', 'ts', 'html', 'css', 'py', 'xml', 
    'yaml', 'yml', 'ini', 'log', 'sh', 'sql'
  ];
  return previewable.includes(ext);
}

export { getFileExtension } from '../lib/files';
