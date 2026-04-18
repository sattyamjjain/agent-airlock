# Launch-readiness checklist — v0.5.0 "April 2026"

Per the April 2026 roadmap (#6), do NOT post to HN/Reddit/X until every
checkbox below is either ticked or explicitly waived in the PR that
references this page.

## Code / release

- [ ] All Phase 1 PRs merged to `main` (1.1 SDK rename, 1.2 MCP
      2025-11-25, 1.3 CVE suite, 1.4 presets, 1.5 Managed backend stub,
      1.6 A2A middleware, 1.7 Model Armor, 1.8 deep-analysis bug triage)
- [ ] `pyproject.toml` version bumped to `0.5.0`
      (see [#17](https://github.com/sattyamjjain/agent-airlock/pull/17))
- [ ] `src/agent_airlock/__init__.py` `__version__` matches
- [ ] `CHANGELOG.md` `[0.5.0]` heading with a one-paragraph summary
- [ ] `CI` green on main for the commit being tagged
- [ ] `git tag v0.5.0 -a -m "..."` + `git push origin v0.5.0`
- [ ] Release notes posted to GitHub Releases (matches CHANGELOG body)
- [ ] `twine upload dist/*` succeeded
- [ ] `pip install agent-airlock==0.5.0` works from a clean env

## Docs

- [ ] README hero/quickstart up to date
- [ ] `docs/cves/index.md` auto-generated and in-sync with `tests/cves/`
      (CI gate runs `scripts/gen_cve_catalog.py --check`)
- [ ] `docs/observability/semconv.md` present with stable-attribute
      contract
- [ ] `CODE_OF_CONDUCT.md`, `SECURITY.md`, `CONTRIBUTING.md`, issue
      templates present
- [ ] `.claude-plugin/{plugin,marketplace}.json` point at 0.5.0
- [ ] `docs/launch/faq.md` drafted (this folder)
- [ ] `docs/launch/rollback.md` drafted (this folder)

## Artifacts

- [ ] Demo GIF at `docs/media/blocked-cve.gif` (60 s screencast)
- [ ] Hero image at `docs/media/hero.png`
- [ ] Coverage badge + test count badge updated

## Security hygiene

- [ ] Latest `bandit -r src/agent_airlock/` → 0 issues
- [ ] `pip install --quiet safety && safety check` reviewed
      (deprecation warnings OK, CVEs are not)
- [ ] SBOM generated and uploaded as a CI artifact
- [ ] PGP key fingerprint in `SECURITY.md` matches the key used to sign
      the release tag

## Go / no-go

- [ ] **Launch day is a Tuesday**, not a Friday
- [ ] Launch-readiness PR approved by the maintainer
- [ ] Rollback plan reviewed (see `rollback.md`)
- [ ] Maintainer available to watch HN comments for 4 hours after post

## External submissions (not blocking launch, but schedule)

- [ ] PR opened against `anthropics/claude-plugins-official`
- [ ] Submission form filed at `claudemarketplaces.com/submit`
- [ ] `aitmpl.com` outreach via Discord
- [ ] `buildwithclaude.com` submission form filed
- [ ] 10 DMs drafted (simonw, swyx, karpathy, Theo, 6 security devs) —
      NOT sent until after HN post lands on the front page
- [ ] 8-tweet X thread drafted
- [ ] `/r/ClaudeAI`, `/r/LocalLLaMA`, `/r/netsec` post drafts reviewed
