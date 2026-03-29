import { createSignal, createEffect } from 'solid-js';

/** Plain-text preview for dashboard modal (authenticated blob URL). */
export default function DashboardTextPreview(props: { url: string }) {
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
