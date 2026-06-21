# Perforce → Lore migration: patch plan

Context handoff from an earlier Claude session. This file is the full brief —
no prior conversation is needed to act on it.

## Goal

Enable a Perforce → Lore history migration that preserves, per commit:

- the original P4 changelist number (already supported via `LORE_P4_CHANGELIST`)
- the original P4 submission **timestamp** (not currently supported)
- the original P4 **submitter** as `created-by` / `committed-by` (not currently supported)

The user evaluated three options and chose **option B**: patch Lore itself so
the importer can run against a custom build. The driver script will then loop
over `p4 changes` and call `lore commit` with the new env vars set.

## How Lore models commit metadata (orientation)

Defined in `lore-revision/src/metadata.rs`:

```
message, timestamp, created-by, committed-by, reviewed-by, merged-by,
branch, p4-changelist, restored-from, cherry-picked-from, reverted-from,
change-request, fast-forward-merge
```

All commit metadata is assembled in **`prepare_commit_metadata`** in
`lore-revision/src/commit.rs` (function starts at line 2887 as of the
clone this plan was written against). Today that function:

- sets `timestamp` from `util::time::timestamp()` (always "now")
- sets `created-by` / `committed-by` from
  `execution_context().user_id().await` (always the running identity)
- already reads `LORE_P4_CHANGELIST` from the env and, if non-empty, writes it
  to the `p4-changelist` metadata key

There are **no CLI flags** to override author or date on `lore commit` /
`lore revision commit` / `lore revision amend`. That's why a code change is
needed.

`CommitError` is defined inline in the same file at line 177 using the
`#[error_set]` macro — adding a new variant is a one-liner.

## The patch

Three env vars, all `LORE_P4_`-prefixed to match the existing
`LORE_P4_CHANGELIST` convention. All are opt-in: absence preserves
upstream behavior, so the patched binary is safe to use day-to-day.

| Env var              | Effect                                              | Source in P4                       |
| -------------------- | --------------------------------------------------- | ---------------------------------- |
| `LORE_P4_CHANGELIST` | sets `p4-changelist` metadata (already implemented) | the CL number                      |
| `LORE_P4_TIMESTAMP`  | overrides `timestamp` (u64 unix **seconds**)        | `p4 -ztag describe -s <CL>` `time` |
| `LORE_P4_USER`       | overrides both `created-by` and `committed-by`      | `p4 -ztag describe -s <CL>` `user` |

A single `LORE_P4_USER` fills both `created-by` and `committed-by` because P4
has one submitter per change; if a future need arises we can split it then.

> **Timestamp unit:** `LORE_P4_TIMESTAMP` is unix **seconds** (the unit of P4's
> `describe` `time` field). Lore stores the `timestamp` metadata key in
> **milliseconds** (`util::time::timestamp()` returns `timestamp_millis()`), so
> the patch multiplies the value by 1000 internally. Pass the raw P4 `time`
> value as-is — do **not** pre-convert. (An early draft fed seconds straight
> into the millisecond field and produced 1970-era dates.)

### As-implemented (deviates from the original sketch below)

Two corrections were made versus the first-draft diff:

1. **No dedicated `CommitError::InvalidP4Timestamp` variant.** This crate uses
   strict error forwarding (`#[error_set]` + `.forward::<T>()`): adding a
   variant to `CommitError` forces ~16 downstream error sets that forward a
   `CommitError` (`MergeError`, etc.) to also declare it. To keep the surface
   tiny, the malformed-timestamp case reuses the existing `InvalidArguments`
   variant with a descriptive `reason`.
2. **Seconds → milliseconds conversion** (see note above), with `checked_mul`
   so an absurd value is rejected rather than silently overflowing.

The timestamp parsing lives in a small pure helper, `resolve_p4_timestamp`,
so it is unit-testable without a repository fixture. `use std::str::FromStr;`
was already imported. The final shape:

```rust
fn resolve_p4_timestamp(
    raw: Option<&str>,
    fallback: impl FnOnce() -> u64,
) -> Result<u64, CommitError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => {
            let seconds = u64::from_str(s).map_err(|_| invalid_p4_timestamp(s))?;
            seconds.checked_mul(1000).ok_or_else(|| invalid_p4_timestamp(s))
        }
        None => Ok(fallback()),
    }
}
```

```diff
@@ pub async fn prepare_commit_metadata(
     // Set metadata for revision, overwriting any existing value
-    let commit_timestamp = util::time::timestamp();
-    let commit_user = execution_context().user_id().await;
+    // P4 import overrides — all opt-in. Absence preserves upstream behavior.
+    let commit_timestamp = resolve_p4_timestamp(
+        std::env::var("LORE_P4_TIMESTAMP").ok().as_deref(),
+        util::time::timestamp,
+    )?;
+    let p4_user = std::env::var("LORE_P4_USER").unwrap_or_default();
+    let commit_user = if !p4_user.is_empty() {
+        p4_user
+    } else {
+        execution_context().user_id().await
+    };
     let commit_changelist = std::env::var("LORE_P4_CHANGELIST").unwrap_or_default();
```

The existing `MissingIdentity` branch downstream stays unchanged — setting
`LORE_P4_USER` makes `commit_user` non-empty, which already satisfies the
identity check without further plumbing.

### Verification (done — all green)

- `cargo build --release -p lore-client --bin lore` — the `lore` binary is
  produced by the `lore-client` crate (`[[bin]] name = "lore"`).
- Smoke test (throwaway `--offline` repo; new files need `lore stage . --scan`):
  with all three env vars set, `lore commit` / `lore history` /
  `lore revision metadata get` confirmed `timestamp` (→ `Tue, 14 Nov 2023
  22:13:20 +0000` for `1700000000`), `created-by`, `committed-by`, and
  `p4-changelist` all reflect the injected values.
- Empty case: no env vars → timestamp is "now", no changelist, commit normal.
- Malformed case: `LORE_P4_TIMESTAMP=garbage` → rejected with
  `invalid arguments: LORE_P4_TIMESTAMP is not a valid u64 unix timestamp
  (seconds): 'garbage'`, commit fails.
- Unit tests: `resolve_p4_timestamp` covered for absent / empty / valid /
  malformed / overflow paths in `commit::tests` (all pass).
- Suggested tests live alongside `commit.rs` — search the file for
  `#[cfg(test)]` and add coverage for the three env-var paths plus the
  malformed-timestamp error.

## Migration driver (separate, runs against the patched binary)

Not part of the patch — sketch only. Goes in whatever import tool the user
ends up writing.

```bash
for CL in $(p4 changes -s submitted -e $LAST_CL //depot/... | awk '{print $2}' | sort -n); do
  eval "$(p4 -ztag -F 'export %user%=%user%; export %time%=%time%; export %desc%=%desc%' describe -s $CL)"
  p4 sync //depot/...@$CL
  lore stage . --scan   # --scan: p4 writes files externally, so walk + mark dirty + stage
  LORE_P4_CHANGELIST=$CL \
  LORE_P4_USER="$user" \
  LORE_P4_TIMESTAMP="$time" \
    lore commit "$desc"
done
```

Branch handling (P4 streams/branches → `lore branch`) is out of scope for
the patch; the driver loop above is single-branch.

## Out of scope for this patch

- CLI flags (`--date`, `--author`) on `lore commit`. Env vars are enough for
  the import use case and keep the patch surface tiny. Can be added later if
  there's a non-import reason to want them.
- Splitting `LORE_P4_USER` into separate created-by / committed-by vars.
- Anything in the migration driver itself.
