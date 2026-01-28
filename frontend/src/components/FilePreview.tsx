import { createSignal, createEffect, Show, For } from 'solid-js';
import * as XLSX from 'xlsx';
import mammoth from 'mammoth';

// ============ CSV Preview ============
export function CsvPreview(props: { url: string }) {
  const [data, setData] = createSignal<string[][]>([]);
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);

  createEffect(async () => {
    try {
      setLoading(true);
      const response = await fetch(props.url);
      const text = await response.text();
      
      // Parse CSV
      const rows = parseCSV(text);
      setData(rows);
    } catch (err) {
      setError('Failed to load CSV');
      console.error(err);
    } finally {
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

// ============ Excel Preview ============
export function ExcelPreview(props: { url: string }) {
  const [sheets, setSheets] = createSignal<{ name: string; data: string[][] }[]>([]);
  const [activeSheet, setActiveSheet] = createSignal(0);
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);

  createEffect(async () => {
    try {
      setLoading(true);
      const response = await fetch(props.url);
      const arrayBuffer = await response.arrayBuffer();
      
      // Parse Excel
      const workbook = XLSX.read(arrayBuffer, { type: 'array' });
      const parsedSheets = workbook.SheetNames.map((name: string) => {
        const sheet = workbook.Sheets[name];
        const data = XLSX.utils.sheet_to_json<string[]>(sheet, { header: 1 });
        return { name, data: data as string[][] };
      });
      
      setSheets(parsedSheets);
    } catch (err) {
      setError('Failed to load Excel file');
      console.error(err);
    } finally {
      setLoading(false);
    }
  });

  const currentSheet = () => sheets()[activeSheet()]?.data || [];

  return (
    <div class="bg-gray-900 rounded-lg overflow-hidden">
      <Show when={loading()}>
        <div class="flex items-center justify-center p-8">
          <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
        </div>
      </Show>
      
      <Show when={error()}>
        <div class="text-red-400 p-4">{error()}</div>
      </Show>
      
      <Show when={!loading() && !error() && sheets().length > 0}>
        {/* Sheet tabs */}
        <Show when={sheets().length > 1}>
          <div class="flex gap-1 p-2 bg-gray-800 overflow-x-auto">
            <For each={sheets()}>
              {(sheet, index) => (
                <button
                  onClick={() => setActiveSheet(index())}
                  class={`px-3 py-1 rounded text-sm whitespace-nowrap ${
                    activeSheet() === index()
                      ? 'bg-primary-600 text-white'
                      : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  {sheet.name}
                </button>
              )}
            </For>
          </div>
        </Show>
        
        {/* Sheet content */}
        <div class="overflow-auto max-h-[60vh]">
          <table class="min-w-full text-sm text-gray-300">
            <tbody>
              <For each={currentSheet()}>
                {(row, rowIndex) => (
                  <tr class={rowIndex() === 0 ? 'bg-gray-800 font-medium' : rowIndex() % 2 === 0 ? 'bg-gray-850' : 'bg-gray-900'}>
                    <For each={row}>
                      {(cell) => (
                        <td class="px-3 py-2 border border-gray-700 whitespace-nowrap">
                          {cell ?? ''}
                        </td>
                      )}
                    </For>
                  </tr>
                )}
              </For>
            </tbody>
          </table>
        </div>
      </Show>
    </div>
  );
}

// ============ Word Preview ============
export function WordPreview(props: { url: string }) {
  const [html, setHtml] = createSignal<string>('');
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);

  createEffect(async () => {
    try {
      setLoading(true);
      const response = await fetch(props.url);
      const arrayBuffer = await response.arrayBuffer();
      
      // Convert Word to HTML
      const result = await mammoth.convertToHtml({ arrayBuffer });
      setHtml(result.value);
      
      if (result.messages.length > 0) {
        console.warn('Mammoth warnings:', result.messages);
      }
    } catch (err) {
      setError('Failed to load Word document');
      console.error(err);
    } finally {
      setLoading(false);
    }
  });

  return (
    <div class="bg-white rounded-lg overflow-hidden">
      <Show when={loading()}>
        <div class="flex items-center justify-center p-8 bg-gray-900">
          <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-500"></div>
        </div>
      </Show>
      
      <Show when={error()}>
        <div class="text-red-400 p-4 bg-gray-900">{error()}</div>
      </Show>
      
      <Show when={!loading() && !error()}>
        <div 
          class="p-6 max-h-[70vh] overflow-auto prose prose-sm max-w-none text-gray-900"
          innerHTML={html()}
        />
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
  const ext = filename.split('.').pop()?.toLowerCase() || '';
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
  const ext = filename.split('.').pop()?.toLowerCase() || '';
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

export function getFileExtension(filename: string): string {
  return filename.split('.').pop()?.toLowerCase() || '';
}
