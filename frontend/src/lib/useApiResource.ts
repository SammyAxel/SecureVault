import { createResource, type ResourceReturn, type ResourceOptions } from 'solid-js';

/**
 * Thin wrapper around SolidJS `createResource` for API calls.
 *
 * Usage:
 *   const [data, { refetch, mutate }] = useApiResource(() => api.listFiles());
 *   <Show when={!data.loading} fallback={<Spinner />}>
 *     <Show when={!data.error} fallback={<ErrorBanner error={data.error} />}>
 *       <FileList files={data()!.files} />
 *     </Show>
 *   </Show>
 *
 * Benefits over manual createSignal + createEffect:
 *  - Built-in `loading`, `error`, `latest` semantics
 *  - Deduplication of in-flight requests
 *  - `refetch()` triggers a fresh load
 *  - `mutate()` for optimistic updates
 *
 * Migration path: replace the manual isLoading/loadError/data signals
 * in components like Home, Dashboard, Profile with this hook.
 */
export function useApiResource<T>(
  fetcher: () => Promise<T>,
  options?: ResourceOptions<T>
): ResourceReturn<T> {
  return createResource(fetcher, options);
}

/**
 * Variant with a reactive source key that re-fetches when the key changes.
 *
 * Usage:
 *   const [data] = useApiResourceKeyed(
 *     () => parentId(),         // re-fetches when parentId changes
 *     (pid) => api.listFiles(pid)
 *   );
 */
export function useApiResourceKeyed<K, T>(
  source: () => K | false | null | undefined,
  fetcher: (key: K) => Promise<T>,
  options?: ResourceOptions<T>
): ResourceReturn<T> {
  return createResource(source, fetcher, options);
}
