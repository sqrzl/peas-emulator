# askr ui bug: centered dialogs can overflow narrow viewports

## Summary

Centered `DialogContent` can overflow the right edge on narrow viewports when Askr's centered overlay
positioning clamps `left` to viewport padding even when content width is near or above the padded
viewport width.

## Impact

- Mobile dialogs can sit a few pixels offscreen even when their theme `max-inline-size` is smaller than
  the viewport.
- This creates a visible horizontal overhang on storage create/upload/delete dialogs.

## Environment

- `@askrjs/askr`: `0.0.42`
- `@askrjs/themes`: `0.0.7`
- `@askrjs/ui`: `0.0.9`
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
- `DialogContent` computes to `left: 20px`, `width: 374px`, `right: 394px`.
- The dialog content's bounding rect is `{ left: 20, right: 394, width: 374 }`.

Expected:

- A centered dialog should remain fully inside viewport padding.
- Either `left` should be clamped lower when dialog width is too large, or the dialog width should be
  capped at `viewportWidth - (2 * viewportPadding)`.

## Notes

- `@askrjs/ui/dist/components/_internal/overlay.js` still computes centered position using:
  - `left: clamp((viewportWidth - contentRect.width) / 2, viewportPadding, maxLeft)`
  - `maxLeft: Math.max(viewportPadding, viewportWidth - contentRect.width - viewportPadding)`
- For wide content, `maxLeft` collapses to `viewportPadding`, so `left` remains at padding and the dialog
  can overhang.
