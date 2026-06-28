/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_REQUIRE_ADMIN_AUTH?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

declare module '*.css';
