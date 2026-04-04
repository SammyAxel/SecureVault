/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_DEMO?: string;
  readonly VITE_SURVEY_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
