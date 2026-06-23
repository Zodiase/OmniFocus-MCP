# Tag Deletion Notes

These notes track issue #1: adding a guarded way to remove OmniFocus tags.

## Goal

The write-mode smoke test left one test tag behind:

```text
TEST-write-smoke-2026-06-23T06-29-58-260Z
```

The server already supports `create_tag` and `list_tags`, but did not expose a tag deletion tool. Removing tags should use the same destructive-operation boundary as task/project removal.

## Implemented Behavior

Added `remove_tag`:

- accepts `id` or exact `name`
- prefers `id` when both are provided
- falls back to `name` if ID lookup fails
- is classified as `dangerous`
- requires `OMNIFOCUS_MCP_MODE=dangerous`
- requires a valid exact `dangerousGrant`
- supports `OMNIFOCUS_MCP_DANGEROUS_DRY_RUN=1`
- appends the standard `dangerousAction` audit payload on dry-run and real execution

## Local Verification

Unit tests cover:

- AppleScript generation for remove-by-ID and remove-by-name
- name fallback when both ID and name are provided
- missing identifier validation
- AppleScript string escaping
- policy classification as dangerous
- blocked write-mode access
- missing-grant blocking in dangerous mode
- dry-run grant verification that skips the handler and returns `dangerousAction.executed: false`

Commands run:

```sh
npm test -- src/tools/primitives/removeTag.test.ts src/tools/policy.test.ts
npm test
npm run build
```

Results:

```text
15 test files passed
261 tests passed
build passed
```

## Live Cleanup

Pending. Before deleting the remaining `TEST-write-smoke-*` tag, use the backup checklist in `backups.md`, then run `remove_tag` with a fresh exact grant.
