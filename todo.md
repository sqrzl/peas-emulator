# TODO

- [x] Implement multipart upload completion (`POST ?uploadId`), abort, and list uploads.
- [x] Add multi-object delete (`POST ?delete`).
- [x] Fix bucket versioning status reporting (reflect enabled/suspended in GET ?versioning and list/get bucket).
- [x] Improve copy-object handling (respect metadata/copy headers minimally) or document limitation.
- [x] Tagging parity: accept `x-amz-tagging` on PUT/copy and validate basic constraints.
- [x] Document remaining unsupported S3/Wasabi features.

Remaining gaps to call out:
- Lifecycle rules are stored but not enforced.
- Advanced copy semantics (range, conditionals) still absent.
- ACLs/policies are implemented for common workflows but still simplified in advanced cases.
- Compatibility hardening is still needed for mutation-path CORS coverage, XML ACL request variants, and broader interop edge-case validation.
