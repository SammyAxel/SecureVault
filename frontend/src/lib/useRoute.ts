import { createSignal, createEffect } from 'solid-js';

export function syncLocationToSignals(
  setPath: (p: string) => void,
  setSearch: (s: string) => void,
  href: string
) {
  const url = new URL(href, window.location.origin);
  setPath(url.pathname);
  setSearch(url.search);
}

/** Pathname + `location.search`; `navigate` / `replacePath` keep signals in sync with `history`. */
export function useRoute() {
  const [path, setPath] = createSignal(window.location.pathname);
  const [locationSearch, setLocationSearch] = createSignal(window.location.search);

  createEffect(() => {
    const handlePopState = () => {
      setPath(window.location.pathname);
      setLocationSearch(window.location.search);
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  });

  const navigate = (newHref: string) => {
    window.history.pushState({}, '', newHref);
    syncLocationToSignals(setPath, setLocationSearch, newHref);
  };

  const replacePath = (newHref: string) => {
    window.history.replaceState({}, '', newHref);
    syncLocationToSignals(setPath, setLocationSearch, newHref);
  };

  return { path, locationSearch, navigate, replacePath };
}
