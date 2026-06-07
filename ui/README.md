# PEAS Admin UI

An Askr admin console for the PEAS storage administration API.

The UI stays intentionally small: sign in, search buckets, create/delete
buckets, browse folder-like blob keys, upload/delete blobs, view blob metadata,
and download blob content.

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

- `/login` for sign-in
- `/logout` for sign-out
- `/admin/buckets` for the bucket table
- `/admin/buckets/{bucketName}` for a bucket root
- `/admin/buckets/{bucketName}/{path}` for folder-like bucket paths
- `/admin/buckets/{bucketName}/blob/{blobId}` for blob details

## UI Scope

Everything uses Askr theme and UI primitives as the base. Local CSS is limited
to PEAS-owned `data-peas-slot` polish for layout and storage-specific sizing.

## Data Flow

- `src/features/auth/admin-session.ts` owns session resolution and auth helpers.
- `src/features/buckets/buckets.query.ts` loads and creates buckets.
- `src/features/objects/objects.query.ts` loads blob metadata and uploads blob content.
- `src/adapters/api.g.ts` remains generated from `../public/openapi.yml`.

## API Boundary

`../public/openapi.yml` is the source of truth. Run `npm run gen` after a
contract change. Pages and features use the configured generated adapter and do
not construct endpoint URLs or call global `fetch`.
