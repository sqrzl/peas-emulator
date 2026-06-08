# askr themes bug: ThemeToggle icon props desync after toggling

## Summary

Using `ThemeToggle` with `darkIcon` and `lightIcon` can render the wrong icon after one or more
toggles. The theme itself changes, but the displayed icon can become stale or inverted.

## Impact

- Header/theme controls provide incorrect visual state.
- Users cannot trust the icon to represent current theme mode.

## Environment

- `@askrjs/askr`: `0.0.41`
- `@askrjs/themes`: `0.0.6`
- `@askrjs/ui`: `0.0.7`
- App usage: `ui/src/pages/app/_layout.tsx`

## Reproduction

```tsx
<ThemeToggle
  aria-label="Toggle theme"
  darkIcon={<MoonIcon aria-hidden="true" />}
  lightIcon={<SunIcon aria-hidden="true" />}
/>
```

1. Load page with default light theme.
2. Click toggle to switch to dark.
3. Click toggle again to switch to light.
4. Repeat toggle a few times.

Observed:
- Theme state and `data-theme` change correctly.
- Icon can become inconsistent with current theme.

Expected:
- Displayed icon always matches current theme deterministically.

## Notes

- A render-callback child on `ThemeToggle` can keep icons in sync, but this is a workaround, not
  the intended API path.

---

# askr ui bug: DialogTitle and AlertDialogTitle mutate state during render

## Summary

Rendering `DialogTitle` or `AlertDialogTitle` inside an open `Dialog`/`AlertDialog` can throw:

```text
[Askr] state.set() cannot be called during component render.
```

The stack points to the title ref registration path:

```text
Object.setTitleNode node_modules/@askrjs/ui/dist/components/dialog/dialog-root.js
setNode node_modules/@askrjs/ui/dist/components/dialog/dialog-title.js
applyRef node_modules/@askrjs/askr/dist/renderer/dom.js
```

## Impact

- Dialogs fail to open in tests.
- Form fields inside the dialog are never mounted, so create/upload flows break.
- Confirmation dialogs fail before the confirmation copy is visible.

## Environment

- `@askrjs/askr`: `0.0.41`
- `@askrjs/ui`: `0.0.7`
- App usage:
  - `ui/src/components/storage/bucket-modal.tsx`
  - `ui/src/components/storage/blob-modal.tsx`
  - `ui/src/components/storage/bucket-delete-dialog.tsx`
  - `ui/src/components/storage/blob-delete-dialog.tsx`

## Reproduction

```tsx
<Dialog open={true}>
  <DialogPortal>
    <DialogOverlay />
    <DialogContent>
      <DialogTitle>Add bucket</DialogTitle>
    </DialogContent>
  </DialogPortal>
</Dialog>
```

Observed:

- During render, `DialogTitle` registers its node through the dialog root.
- That registration calls Askr state setter code while rendering.
- Askr throws the render mutation guard error.

Expected:

- Title/description node registration should not mutate Askr state during render.
- Dialog title primitives should be usable inside an open dialog without tripping the actor-model guard.

## Notes

- Peas continues to use `Dialog`, `AlertDialog`, overlays, portals, and content primitives.
- Peas keeps plain heading/paragraph copy inside dialog content until the title registration path is fixed.

---

# askr ui bug: centered dialogs can overflow narrow viewports

## Summary

Centered `DialogContent` can overflow the right edge on narrow viewports when Askr's centered
overlay positioning clamps the left offset to the viewport padding without reducing the dialog
width to fit the remaining space.

## Impact

- Mobile dialogs can sit a few pixels offscreen even when their theme `max-inline-size` is smaller
  than the viewport.
- This creates a visible horizontal overhang on storage create/upload/delete dialogs.

## Environment

- `@askrjs/askr`: `0.0.41`
- `@askrjs/themes`: `0.0.6`
- `@askrjs/ui`: `0.0.7`
- App usage:
  - `ui/src/components/storage/bucket-modal.tsx`
  - `ui/src/components/storage/blob-modal.tsx`
  - `ui/src/components/storage/bucket-delete-dialog.tsx`
  - `ui/src/components/storage/blob-delete-dialog.tsx`

## Reproduction

1. Open Peas at `http://127.0.0.1:5173/admin/buckets/visual-empty/docs/api`.
2. Set the viewport to `390 x 844`.
3. Open the `Add blob` dialog.
4. Inspect the content bounding box.

Observed:

- `window.innerWidth` is `390`.
- `DialogContent` computes to `left: 20px`, `width: 374px`, `right: -4px`.
- The dialog content's bounding rect is `{ left: 20, right: 394, width: 374 }`.

Expected:

- A centered dialog should remain fully inside the viewport padding.
- Either the left offset should be clamped lower when the dialog width is too large, or the dialog
  width should be capped at `viewportWidth - (2 * viewportPadding)`.

## Notes

- Peas does not override Askr `data-slot="dialog-content"` or clone dialog primitives to hide this.
- The issue appears to come from `applyCenteredPosition`, where `maxLeft` can collapse to the
  same value as `viewportPadding` while the content width remains larger than the padded viewport.

---

# askr themes bug: Inline ignores align and justify props

## Summary

`Inline` renders `data-slot="inline"` with `data-align` and `data-justify` attributes, but the
default theme utilities that apply `align-items` and `justify-content` only target
`data-slot="flex"` and `data-slot="block"`. Static `Flex` alignment can also compute to `normal`
because the later coverage stylesheet reapplies `align-items: var(--ak-align-items-initial)` and
`justify-content: var(--ak-justify-content-initial)` for `[data-align]`/`[data-justify]` without
those CSS variables being set by the static prop path.

## Impact

- Header action rows using `Inline align="center"` can stretch buttons to nearby content height.
- Search/action rows using `Inline align="end"` do not align controls to the input baseline.
- `Inline justify="between"` does not distribute page title/action groups.
- `Flex align="start"` and `Flex justify="between"` can show the same computed `normal` values
  when provided as static token props.

## Environment

- `@askrjs/themes`: `0.0.6`
- App usage:
  - `ui/src/components/storage/storage-page-header.tsx`
  - `ui/src/components/storage/storage-search-form.tsx`
  - `ui/src/components/storage/bucket-table.tsx`
  - `ui/src/components/storage/blob-table.tsx`
  - `ui/src/components/storage/cursor-pagination.tsx`
  - `ui/src/components/storage/data-table-section.tsx`

## Reproduction

```tsx
<Inline justify="between" align="center" gap="3" wrap="wrap">
  <h1>Buckets</h1>
  <Button>Add bucket</Button>
</Inline>
```

Observed:

- DOM includes `data-slot="inline" data-align="initial:center" data-justify="initial:between"`.
- Computed styles remain `align-items: normal` and `justify-content: normal`.
- The same computed result appears with `Flex` when the DOM has
  `data-slot="flex" data-align="initial:center"`.

Expected:

- `Inline` should receive the same covered alignment and justification behavior as `Flex`, or
  render a slot covered by the default theme utility selectors.
- Static `Flex` token props should not be overwritten by coverage rules that depend on unset CSS
  variables.

## Notes

- Peas uses exported `Flex` with Askr's responsive prop form for alignment-sensitive rows until
  static alignment coverage is fixed.
