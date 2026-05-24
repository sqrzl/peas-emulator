# ui

Client-side SPA built with Askr, askr-ui, askr-themes, and askr-charts.

## Commands

```bash
npm run dev        # Vite dev server with HMR (port 5173)
npm run build      # Production build to dist/
npm run preview    # Serve production build locally
npm test           # Vitest (jsdom)
npm run type-check # tsc --noEmit
npm run lint       # ESLint
npm run fmt        # Prettier
```

## Architecture

- **Routing:** `src/main.tsx` imports `src/pages/_routes.tsx`, then boots `createSPA()` with the route manifest. Route branches live under `src/pages/public` and `src/pages/app`.
- **Layouts:** `_layout.tsx` files own shells. The root layout owns `ThemeProvider`; branch layouts own public nav or authenticated sidebar chrome.
- **UI:** Prefer `@askrjs/themes/layouts`, `surfaces`, `controls`, `shells`, `navs`, and `feedback` before writing local components. Use app-local components only for product concepts such as `MetricCard` and `StatusBadge`.
- **State:** `const [value, setValue] = state(initial)`. Read with `value()`, update with `setValue(...)`. Use `derive()` for computed values and `resource()` for async data.
- **Data:** Route/container components own resources; `src/features` owns product workflows; `src/adapters` owns API clients, transports, abort handling, and generated clients.
- **Consistency:** Event-sourced screens should expose pending writes, projection lag, stale data, retries, and manual refresh instead of hiding everything behind one loading state.
- **Styling:** Import the theme once in `src/styles.css`. App CSS should use `--ak-*` tokens and `[data-slot]` hooks from solved primitives.
- **Charts:** Import chart components from `@askrjs/charts/components`; chart CSS is loaded from `@askrjs/charts/default`.
- **Vite plugin:** `askr()` from `@askrjs/vite` handles JSX transform. Do not add manual esbuild JSX config.

## File Structure

```
src/
  main.tsx
  pages/
    _routes.tsx
    _layout.tsx
    public/
    app/
  components/shared/
  features/
  adapters/
  shared/
  styles/
tests/
```

## Conventions

- Keep routes thin and route-first.
- Keep shell chrome in layouts, not leaf pages.
- Keep business logic out of `src/pages`.
- Use `Link` and `navigate` from `@askrjs/askr/router`.
- Use headless `@askrjs/ui/*` for behavior primitives and `@askrjs/themes/*` for composed visual surfaces.
- Avoid hardcoded color systems, custom component catalogs, and React habits like effect-driven data loading.
