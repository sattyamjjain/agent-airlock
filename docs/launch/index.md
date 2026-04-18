# Launch hub

Artifacts for the v0.5.0 "April 2026" launch. Everything here is prep —
none of it ships to end users at runtime.

- [**Readiness checklist**](readiness-checklist.md) — hard go/no-go list
  per the roadmap (#6). Tick every box before the HN post goes up.
- [**Launch-day FAQ**](faq.md) — drafted answers for the questions we
  expect from HN / Reddit / security Twitter.
- [**Rollback plan**](rollback.md) — what to do if something goes
  sideways in the first 48 hours after publishing.
- [**NVD MCP-CVE watcher (sample)**](nvd-mcp-watcher.yml.sample) —
  GitHub Actions workflow that auto-files CVE rule-request issues for
  newly-disclosed MCP-adjacent CVEs. Sample file; a maintainer with
  `workflow` scope must copy it into `.github/workflows/` to enable.

## Why a launch hub?

The April 2026 roadmap (#6) §Phase-4 is explicit that a launch is a
separate, human-driven deliverable. It calls for a
"launch-readiness PR" that bundles the demo GIF, CVE regression suite
state, release tag, FAQ, and rollback plan into a single review
artifact.

This folder IS that bundle.
