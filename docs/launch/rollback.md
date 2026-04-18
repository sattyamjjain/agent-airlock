# Launch-day rollback plan

## When to roll back

Roll back to v0.4.1 if **any** of the following happens in the first
48 hours after posting:

1. A first-week bug in `agent-airlock` 0.5.0 blocks a legitimate tool
   call that worked on 0.4.1, and the fix will take more than 4 hours.
2. `pip install agent-airlock==0.5.0` fails in a way that leaks secrets
   (env vars, token paths) into a traceback visible on PyPI or HN
   comments.
3. A new CVE is disclosed against a downstream dep (`pydantic`, `mcp`,
   `fastmcp`, `e2b`, `anthropic`) that changes our threat-model claims.
4. CI goes red on main and we don't have a clean forward-fix within
   2 hours.

## Rollback procedure

### Step 1 — yank the bad release from PyPI

```bash
# Only yank, do NOT delete — yank preserves resolver semantics.
pip install --upgrade twine
twine yank agent-airlock --version 0.5.0
```

This blocks new installs from resolving to 0.5.0 without breaking
existing pins.

### Step 2 — revert the main branch to the v0.4.1 commit

```bash
git fetch origin
git tag v0.4.1-last-good-pre-rollback  # safety marker
git push origin v0.4.1-last-good-pre-rollback
git revert <first-bad-sha>..<last-bad-sha> --no-edit
# or, if the revert is messy:
git reset --hard v0.4.1 && git push --force-with-lease origin main
```

`--force-with-lease` (not plain `--force`) stops if someone pushed
while you were composing the rollback.

### Step 3 — ship the forward-fix as 0.5.1

```bash
# Separate branch, separate PR, separate review. No silent republish.
git switch -c fix/v0.5.0-rollback-forward-fix
# ... make the fix ...
# bump pyproject.toml + __init__.py to 0.5.1
# write the [0.5.1] CHANGELOG entry naming the yanked 0.5.0
```

### Step 4 — update the outside world

- Pin comment on the HN thread explaining the yank + linking to 0.5.1
- Reddit threads: edit top comment with the same pointer
- X thread: reply to the top tweet (do NOT delete the original)
- Discord announcement in `#releases`
- Update GitHub Release page for v0.5.0 to mark it yanked and link
  the replacement

## Pre-commit safety markers

Before publishing 0.5.0, tag the **last known good** revision so we
have a no-arg rollback target:

```bash
git tag v0.4.1-pre-april-2026 <commit-sha>
git push origin v0.4.1-pre-april-2026
```

(This tag already exists — see the roadmap-phase-0 work.)

## Incident comms template

> **Heads-up:** we yanked `agent-airlock==0.5.0` at HH:MM UTC because
> of <single-sentence summary>. The fix is tracked in
> https://github.com/sattyamjjain/agent-airlock/issues/<N> and will
> ship as 0.5.1 within <timeframe>.
>
> If you've already installed 0.5.0, pin to 0.4.1 until the forward-fix
> lands: `pip install 'agent-airlock==0.4.1'`.
>
> Sorry for the disruption — this is why we yank, not hide. Full
> postmortem will go up at `/blog/postmortems/0-5-0.md` within 7 days.

## Post-rollback obligations

Within 7 days of a rollback:

1. Write a public postmortem at `/blog/postmortems/<version>.md` with
   5 Whys + remediation tasks tracked in GitHub issues.
2. Add a new regression test that would have caught the class of bug.
3. Update this rollback doc if the procedure itself had friction.
