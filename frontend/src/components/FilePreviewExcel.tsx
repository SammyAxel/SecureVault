import { createSignal, createEffect, Show, For } from 'solid-js';
import * as XLSX from 'xlsx';
import { awaitMinElapsed, MIN_CONTENT_LOAD_MS } from '../lib/motion';
import { logger } from '../lib/logger';

export function ExcelPreview(props: { url: string }) {
  const [sheets, setSheets] = createSignal<{ name: string; data: string[][] }[]>([]);
  const [activeSheet, setActiveSheet] = createSignal(0);
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);

  createEffect(async () => {
    const started = Date.now();
    try {
      setLoading(true);
      const response = await fetch(props.url);
      const arrayBuffer = await response.arrayBuffer();

      const workbook = XLSX.read(arrayBuffer, { type: 'array' });
      const parsedSheets = workbook.SheetNames.map((name: string) => {
        const sheet = workbook.Sheets[name];
        const data = XLSX.utils.sheet_to_json<string[]>(sheet, { header: 1 });
        return { name, data: data as string[][] };
      });

      setSheets(parsedSheets);
    } catch (err) {
      setError('Failed to load Excel file');
      logger.error(err);
    } finally {
      await awaitMinElapsed(started, MIN_CONTENT_LOAD_MS);
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
        <Show when={sheets().length > 1}>
          <div class="flex gap-1 p-2 bg-gray-800 overflow-x-auto">
            <For each={sheets()}>
              {(sheet, index) => (
                <button
                  type="button"
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

        <div class="overflow-auto max-h-[60vh]">
          <table class="min-w-full text-sm text-gray-300">
            <tbody>
              <For each={currentSheet()}>
                {(row, rowIndex) => (
                  <tr
                    class={
                      rowIndex() === 0
                        ? 'bg-gray-800 font-medium'
                        : rowIndex() % 2 === 0
                          ? 'bg-gray-800/80'
                          : 'bg-gray-900'
                    }
                  >
                    <For each={row}>
                      {(cell) => (
                        <td class="px-3 py-2 border border-gray-700 whitespace-nowrap">{cell ?? ''}</td>
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
