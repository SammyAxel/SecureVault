import { createSignal, createEffect, Show } from 'solid-js';
import mammoth from 'mammoth';
import { awaitMinElapsed, MIN_CONTENT_LOAD_MS } from '../lib/motion';
import { logger } from '../lib/logger';

export function WordPreview(props: { url: string }) {
  const [html, setHtml] = createSignal<string>('');
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(true);

  createEffect(async () => {
    const started = Date.now();
    try {
      setLoading(true);
      const response = await fetch(props.url);
      const arrayBuffer = await response.arrayBuffer();

      const result = await mammoth.convertToHtml({ arrayBuffer });
      setHtml(result.value);

      if (result.messages.length > 0) {
        logger.warn('Mammoth warnings:', result.messages);
      }
    } catch (err) {
      setError('Failed to load Word document');
      logger.error(err);
    } finally {
      await awaitMinElapsed(started, MIN_CONTENT_LOAD_MS);
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
