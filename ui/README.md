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

## Project Structure

```
src/
|-- main.tsx                         # SPA boot and route manifest
|-- pages/
|   |-- _routes.tsx                  # Top-level route branches
|   |-- _layout.tsx                  # Theme provider and app root
|   |-- auth/                        # Guest login and independent logout route
|   `-- app/                         # Authenticated branch routes and layout
|-- components/shared/               # App-local wrappers around theme primitives
|-- features/                        # Auth, bucket, object, and dashboard workflows
|-- adapters/api.g.ts                # Generated endpoint transport surface
|-- adapters/index.ts                # Configured FetchClient and generated adapter
|-- shared/                          # Cross-cutting helpers and navigation data
`-- styles/                          # App-specific CSS on top of theme tokens
```

## Core Patterns

Routes live in `src/pages`, shells live in `_layout.tsx`, reusable UI lives in
`src/components/shared`, business workflows live in `src/features`, and adapter
code lives in `src/adapters`.

```tsx
// src/pages/_routes.tsx
import { fallback, group, registerRoutes } from '@askrjs/askr/router';
import RootLayout from './_layout';
import NotFoundPage from './not-found';
import AppLayout from './app/_layout';
import { registerAppRoutes } from './app/_routes';
import AuthLayout from './auth/_layout';
import { registerGuestRoutes } from './auth/_routes';
import { resolveAdminSession } from '../features/auth/admin-session';

registerRoutes(
  () => {
    group({ layout: RootLayout }, () => {
      group({ layout: AuthLayout, auth: 'guest' }, () => {
        registerGuestRoutes();
      });
      group({ layout: AppLayout, auth: true }, () => {
        registerAppRoutes();
      });
      fallback(NotFoundPage);
    });
  },
  { auth: { resolve: resolveAdminSession, loginPath: '/auth' } }
);
```

The template uses focused theme entrypoints such as `@askrjs/themes/layouts`,
`@askrjs/themes/surfaces`, `@askrjs/themes/controls`, and
`@askrjs/themes/shells`. Add app-local components only when they compose those
primitives into a product concept.

Async reads are owned by route or container components with `resource()` and
delegated through feature/adapters:

```tsx
const operations = resource(({ signal }) => loadOperations({ signal }), []);
```

Cancellation is preserved through generated calls, while loading/error/value
states stay visible in route components.

## What This Template Includes

- Guest login, protected application routes, and generated session resolution
- Theme provider, top navbar, cards, badges, buttons, empty states, and layout primitives
- A stripped-down overview with live bucket totals and recent bucket rows
- Bucket CRUD, versioning controls, object content and metadata upload,
  downloads, tags, and paginated versions
- A transport/session view reporting the API path and resolved session mode

## API Boundary

`../public/openapi.yml` is the source of truth. Run `npm run gen` after a
contract change. Pages and features use the configured generated adapter and do
not construct endpoint URLs or call global `fetch`.
