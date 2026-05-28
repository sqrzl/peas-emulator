# Peas Admin UI

An Askr admin console for the Peas emulator storage administration API.

## Quick Start

```bash
npm install
npm run gen      # Generate src/adapters/api.g.ts from ../public/openapi.yml
npm run type-check
npm run lint
npm run dev      # Start dev server at http://localhost:5173
npm run build    # Build for production
npm run preview  # Preview production build
npm test         # Run tests with Vitest
```

## Routes

- `/auth` and `/auth/login` for sign-in
- `/auth/logout` for sign-out
- `/app` for the bucket table
- `/app/buckets/{bucketName}` for the blob table in a bucket
- `/app/buckets/{bucketName}/blobs/{blobKey}` for blob details

## UI Scope

The UI intentionally stays small:

- login
- logout
- bucket list with add-bucket dialog
- blob list with add-blob dialog
- blob details

Everything uses Askr theme and UI primitives only. There is no app-specific CSS
layer in this version.

## Data Flow

- `src/features/auth/admin-session.ts` owns session resolution and auth helpers.
- `src/features/buckets/buckets.query.ts` loads and creates buckets.
- `src/features/objects/objects.query.ts` loads blob metadata and uploads blob content.
- `src/adapters/api.g.ts` remains generated from `../public/openapi.yml`.

## API Boundary

`../public/openapi.yml` is the source of truth. Run `npm run gen` after a
contract change. Pages and features use the configured generated adapter and do
not construct endpoint URLs or call global `fetch`.
