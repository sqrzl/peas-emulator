# ui - SPA Template

A route-first Askr SPA built with `@askrjs/askr`, `@askrjs/ui`, `@askrjs/themes`, and `@askrjs/charts`.

## Quick Start

```bash
npm install
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
|   |-- public/                      # Guest branch routes and layout
|   `-- app/                         # Authenticated branch routes and layout
|-- components/shared/               # App-local wrappers around theme primitives
|-- features/operations/             # Product workflow queries and mutations
|-- adapters/                        # API clients and transport adapters
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
import PublicLayout from './public/_layout';
import { registerPublicRoutes } from './public/_routes';

registerRoutes(() => {
  group({ layout: RootLayout }, () => {
    group({ layout: PublicLayout }, () => {
      registerPublicRoutes();
    });
    group({ layout: AppLayout }, () => {
      registerAppRoutes();
    });
    fallback(NotFoundPage);
  });
});
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

Cancellation belongs in adapters, loading/error/value states stay visible in the
route, and event-sourced consistency states should be modeled explicitly.

## What This Template Includes

- Public and authenticated route branches with separate layout shells
- Theme provider, header/nav/sidebar, cards, badges, buttons, empty states, and layout primitives
- A dashboard with async loading, charts, projection lag, and explicit refresh
- Feature and adapter boundaries for data ownership
- Tests that protect the route-first structure and cancellation behavior

## Next Steps

1. Replace the mock operations adapter with your generated API client.
2. Add route metadata for real auth and loader policies.
3. Keep new screens route-first and compose solved UI through `@askrjs/themes`.
