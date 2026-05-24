# Askr Builder Brief

- App name: ui
- Template: spa
- Selection mode: explicit
- Selection reason: Template 'spa' was provided explicitly on the command line.

## Prompt

No app prompt was provided. This project was scaffolded from explicit CLI arguments.

## Capabilities

- Agent workflows
- Dashboards and charts
- Design system and theming
- Routing and layouts

## Inspect First In This Scaffold

- AGENTS.md
- src/main.tsx
- src/pages/\_routes.tsx
- src/pages/public/\_routes.tsx
- src/pages/app/\_layout.tsx

## Skill Execution Order

### Start here

- askr-agent-execution - Read the repo in the right order and validate narrowly.
- askr-mental-model - Choose native Askr primitives and reject React-shaped defaults.
- askr-project-structure - Place routes, features, shared helpers, and adapters predictably.
- askr-routing-layouts - Keep one obvious route tree, shell boundary, and navigation path.
- askr-runtime-reactivity - Apply state(), derive(), selector(), and For with stable call order.

### Pull in next when the task needs it

- askr-error-loading-empty - Represent loading, empty, stale, retry, and pending-write truthfully.
- askr-agent-workflows - Model runs, approvals, timelines, and audit-friendly states.
- askr-dashboard-charts - Add charts without bypassing route, state, or theming conventions.
- askr-theming - Apply the theme layer, tokens, and shell primitives before custom styling.

### Finish with validation

- askr-testing-determinism - Finish with the narrowest executable check for the changed contract.

## All Recommended Skills

- askr-agent-execution
- askr-mental-model
- askr-project-structure
- askr-routing-layouts
- askr-runtime-reactivity
- askr-error-loading-empty
- askr-agent-workflows
- askr-dashboard-charts
- askr-theming
- askr-testing-determinism

## Golden Examples In This Scaffold

- src/pages/public/home.tsx
- src/pages/app/admin-home.tsx
- src/features/operations/operations.query.ts

## Guardrails

- Keep the route-first file structure so new features land where builders expect them.
- Use state(), derive(), resource(), and selector() for reactive state and derived views.
- Use For for keyed or dynamic list rendering instead of ad hoc array mapping.
- Keep adapters, queries, and mutations outside page files so data boundaries stay deterministic.
- Model loading, empty, error, and success states explicitly and keep them testable.

## Suggested builder prompts

- Add an agent run detail screen with prompt, timeline, approvals, and artifact history.
- Connect dashboard metrics through adapters and queries while preserving loading, empty, and error states.
- Use the bundled Askr skills before adding new features so generated code stays idiomatic.
