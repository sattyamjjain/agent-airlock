# The 90-Day Launch Playbook — Open-Source AI Dev Tools (2026)

Cross-repo growth playbook shared by `agent-airlock`, `agent-audit-kit`, and `Verdict`. The consumer app `whyCantWeHaveAnAgentForThis` has its own (different) playbook — see its ROADMAP.

Grounded in the arXiv peer-reviewed analysis of 138 AI-tool HN launches (2511.04453, Nov 2025) and case studies of 15 projects that went from <100 to 1 k+ / 10 k+ stars (Aider, Cline, Continue, OpenHands, FastMCP, browser-use, Semgrep, Trivy, Gitleaks, Nuclei, screenshot-to-code, Roo, Kilo, Stagehand, CrewAI).

---

## 1. Quantitative baseline you should internalize

From the peer-reviewed HN data:

- Average star gain after HN front-page exposure: **+121 in 24 h, +189 in 48 h, +289 in 7 days.**
- Best posting window: **12:00–17:00 UTC (≈ 8 am–1 pm US Eastern).** Gap between optimal and suboptimal hours: ~200 stars.
- The literal "Show HN:" prefix shows **no statistical advantage** after controlling for time-of-day and content. Use plain URL + factual title.
- Tuesday–Thursday outperforms Monday/Friday for front-page longevity (UNVERIFIED consensus, but aligned with reply patterns).

**Target:** a clean HN front-page run for each of the three dev-tool repos gets each to ~300 stars passively. The next 700 stars come from distribution work in weeks 2–12.

---

## 2. The pattern of 10 k+ projects (separators from 1 k)

From the case-study analysis:

1. **Launch-week news-cycle hook.** OpenHands was "the open-source Devin" during the Cognition news wave. browser-use 5× downloads in a week when Manus tweeted about them. Cline rode the Claude 3.5 Sonnet release. FastMCP rode MCP itself to 10 k in 6 weeks.
2. **Ecosystem co-distribution.** Cline lives in VS Code Marketplace — every install is a star candidate. Verdict will live in the Claude plugin marketplace. agent-audit-kit's GitHub Action is its marketplace.
3. **Demo content.** A 20-second loopable GIF at the top of the README that makes sense with sound off. A 90–180 s Loom for depth.
4. **Own a leaderboard.** Aider publishes the Polyglot leaderboard; every LLM vendor links back on launch day. This is the single highest-leverage tactic in the data. Equivalents for this portfolio: agent-airlock owns AgentDojo/PINT/AgentHarm numbers for MCP middleware; agent-audit-kit owns the **MCP Security Index** (weekly grades of 10 k public MCP servers); Verdict owns the **State of Claude Code Skills Quality** monthly report.
5. **Community flywheel.** Continue had 11 k Discord before 30 k stars. Nuclei paid $50–$250 bounties per community-written template → 12 k templates, 8 k Discord.
6. **Naming.** 1–2 syllables + matching domain.
7. **Response SLA.** Issues answered in <24 h for the first 60 days, <72 h thereafter. 10 k projects respond fast; 1 k projects don't.

---

## 3. The 90-day timeline (per repo)

### Weeks 1–2 — Foundation (pre-launch T-90 to T-76)

**README v2:**
- Title + one-line tagline
- Hero GIF (20 s, loopable, no sound)
- Install command (one line)
- 3 usage examples
- Feature list (max 10 bullets)
- Badges: CI, PyPI/npm, license, Discord
- "Why" section (the news-cycle hook)

**Domain + one-pager:**
- Buy the matching domain (`airlock.dev`, `aak.report`, `verdict.dev` / `getverdict.com`)
- Single-page Vercel landing: same GIF + CTA to GitHub

**Housekeeping:**
- CHANGELOG.md (Keep-a-Changelog format, semver)
- Issue templates (bug, feature, question)
- CONTRIBUTING.md
- 5–10 "good first issue" labeled issues
- Empty Discord ready, link in README
- Signed release artifacts (Sigstore for Python, npm provenance for TS)

### Weeks 3–4 — Seed content (T-76 to T-62)

- Record 90–180 s Loom demo (screen-share with voiceover; no edits)
- Upload to YouTube unlisted
- Write 3 technical blog posts (benchmarks, case studies, a "why we built this" post)
- Draft launch-week posts for HN, `/r/ClaudeAI`, `/r/LocalLLaMA`, `/r/netsec` — not published yet
- Run 10 benchmark comparisons against competitors; lock numbers
- Fix top 5 real-user bugs from small-circle feedback

### Weeks 5–6 — Quiet launch (T-62 to T-48)

- Publish to PyPI / npm / VS Code Marketplace / Claude plugin marketplace. **Get distribution surface presence before the HN post** so new arrivals can install instantly.
- Share in 3–5 small Discords/Slacks you're already in for honest feedback, not stars
- Collect 2–3 friendly quotes to lead with on launch
- Fix the top issues from week-5 feedback

### Weeks 7–8 — Loud launch week (T-48 to T-34)

**Day 1, Tuesday, 13:00 UTC:**
- HN submission. Title factual, not hype. URL points at the **blog post with the news-cycle hook** (not the README, which is one click away).
- Post your own first comment within 15 minutes with motivation + Loom link.
- **Stay on HN for 4 hours**, respond to every comment. Single biggest determinant of front-page longevity.
- 60 minutes later: post an 8-tweet X thread. Tweet 1 is the GIF + problem statement. Tweets 2–6 are features with sub-GIFs. Final tweet is the repo link. @-mention 1–2 people who've tweeted about the problem in the last 30 days (warm, not cold).

**Day 2:**
- `/r/LocalLLaMA` (688 k) or `/r/ClaudeAI` (747 k) — whichever fits the repo best (`agent-airlock` → both; `agent-audit-kit` → `/r/netsec` + `/r/LocalLLaMA`; `Verdict` → `/r/ClaudeAI`).
- 90/10 rule: your account history should be mostly non-promotional comments.
- Screenshot-lead format, link in comments.

**Day 3:**
- Product Hunt optional (only worth it for Verdict among the three dev tools).

**Day 4:**
- Dev.to cross-post of the strongest blog post. Better than Medium in 2026 due to ChatGPT / Perplexity citation preference.

**Day 5:**
- Short thread summarizing "What I learned launching this" with updated stats. Second HN-adjacent spike.

### Weeks 9–12 — Sustained drumbeat (T-34 onward)

- **Weekly release cadence.** Aider releases nearly weekly. Cline went 5 k → 40 k with relentless releases. Every release is an excuse for a tweet.
- **One long blog post per 2 weeks.** Benchmarks, case studies, CVE write-ups, postmortems — content that earns backlinks.
- **One podcast pitch per week** (Changelog accepts cold pitches via form; Latent Space requires warm intro via Discord first; ThePrimeagen / Theo / Fireship cover organic viral content, don't cold-pitch).
- **Answer every GitHub issue within 24 h** for the first 60 days.
- **Reply to every tweet mentioning the repo.** Manually.
- Month-2 second-wave launch hook: a benchmark update, a major version, or a new integration.

---

## 4. Distribution channel deep-dive

### Hacker News
- **When:** Tuesday–Thursday, 12:00–17:00 UTC.
- **How:** Plain URL + factual title. No "Show HN:" unless literally demo. Comment on own post in first 15 min.
- **Stay in thread for 4 hours** responding to comments. This is the single biggest retention lever.
- **Pre-coordinate 5–10 upvotes** in first 30 min from your existing network. Standard practice; not a violation.
- **Expected outcome:** +121 stars in 24 h, +289 in 7 days on a successful front-page run.

### Reddit
- `/r/LocalLLaMA` (688 k) — loves local-first tools + privacy angles. Fits all three security tools and Verdict's "no LLM required" angle.
- `/r/ClaudeAI` (747 k) — dominant subreddit for Claude tooling. **Verdict's highest-leverage channel.**
- `/r/netsec` — agent-audit-kit fit.
- `/r/MachineLearning` (3 M) — high karma req, hostile to self-promo. Skip on launch; use for benchmark-heavy follow-up only.
- `/r/programming` (7 M) — hostile to self-promo. Use via third-party writeups.
- Post format: problem statement + code snippet + "here's what I learned" + screenshot. Link in comments.

### Twitter / X
- **Threads beat singles.** swyx's smol-developer thread = 1.5 M views; Gregor Zunic's browser-use update = 2.4 M views.
- 5–8 tweets. Tweet 1 must stand alone with the GIF.
- @-mention 1–2 people who've tweeted about your problem in the last 30 days (warm, not cold).
- Re-post thread fragments as standalone posts weekly.

### Product Hunt
- **Worth it** for consumer-feel tools (v0, Cursor, Kilo — Kilo hit #1 Product of the Day and raised $8 M seed).
- **Not worth it** for niche security scanners unless you have a landing page + demo video at consumer-app polish.
- Portfolio split: `whyCantWeHaveAnAgentForThis` = strong PH candidate. `Verdict` = medium. `agent-airlock` / `agent-audit-kit` = skip, focus HN.

### Podcasts / YouTube
- **Latent Space (swyx + alessio)** — does not take cold pitches. Path: become known in their Discord first, then warm intro.
- **Changelog** — accepts form pitches; AI infra is regular topic.
- **Fireship** — covers organic trends only, don't pitch.
- **ThePrimeagen / Theo** — same.
- **Lesson:** podcasts are a *consequence* of HN/Twitter success, not a *cause*. Don't pitch until after a first HN front page.

### Dev.to vs Medium in 2026
- Dev.to: still strong for technical posts with code; better for ChatGPT / Perplexity citations (10× referral traffic vs a year earlier per 2026 SEO reports).
- Medium: paywall hurts technical posts. Skip unless already published there.

### Conferences / in-person
- **BlackHat Arsenal / DEF CON AI Village / RSAC** — agent-airlock and agent-audit-kit CVE corpuses make strong abstracts.
- **KubeCon AI + OpenTelemetry sessions** — agent-airlock's OTel integration is relevant.
- **PyCon / NodeConf / JSConf** — broader dev audiences; secondary priority.

---

## 5. The Top-1% checklist (1 k vs 10 k separators)

| Trait | 1 k-star median | 10 k+ pattern |
|---|---|---|
| Hero demo | static screenshot | **20 s loopable GIF or YouTube at top of README** |
| Demo video length | none or 5+ min | **90–180 s Loom/YouTube**, one-take, problem→fix |
| README length | 200 or 2,000 lines | **300–700 lines**, scannable, examples-first |
| Integration surface at launch | 1 (your CLI) | **2–3** (CLI + VS Code + one SDK) |
| Issue SLA | days–weeks | **<24 h for first 60 days**, <72 h ongoing |
| Release cadence | monthly or random | **weekly or bi-weekly**, visible CHANGELOG |
| "Good first issue" count | 0–1 | **5–15 tagged**, triaged monthly |
| Discord members before 10 k stars | 0 or <200 | **>1,000 engaged** |
| Own-medium content | none | **weekly technical blog, monthly benchmark** |
| Ecosystem plug-in | standalone | **Claude Code / VS Code / OpenRouter / MCP ecosystem** |
| News-cycle hook at launch | generic | **explicit tie** ("uses new Claude 4.7" / "open-source answer to X") |
| Benchmark ownership | none | **you own a leaderboard vendors link to** (Aider pattern) |
| HN response | delayed | **author replies to every comment for 4 hours** |
| Naming | long/descriptive | **1–2 syllables**, matching domain |

---

## 6. Shared portfolio-level tactic

Because all three dev-tool repos are by the same author and thematically adjacent, they should **cross-promote explicitly**:

- Each README has a "Sibling projects" section with one-line summaries of the other two + links.
- A shared `github.com/<user>` org-level profile README that tells the story: "static scan (audit-kit) → runtime enforce (airlock) → output-quality (Verdict) → built while doing (whyCant)."
- A single blog (airlock.dev blog, for example) that hosts all three projects' technical posts.
- Cross-link in every launch post: "If you liked this, you'll also like [sibling]."
- Shared Discord with channels per project. Reduces per-project moderation overhead.
- Shared Twitter presence — a single account posting updates for all three. Or tie into the author's personal account.

The four repos are already a coherent stack in design; making the story visible in distribution materials is pure upside.

---

## 7. Launch order (recommendation)

Launch in this order over weeks 7–10:

1. **Verdict first.** White space is clearest, distribution friction is lowest (Claude plugin marketplace), fastest expected path to 1 k. Launching first proves the playbook and generates proof-of-work for the other two.
2. **agent-airlock second.** Benefits from Verdict's traction (cross-promote). News-cycle hook on the 30-CVE corpus is still live.
3. **agent-audit-kit third.** Requires the MCP Security Index scan (longer prep). Coordinated CVE disclosures benefit from having airlock's runtime defense in the same story.

`whyCantWeHaveAnAgentForThis` runs on a different timeline (consumer app, Product Hunt + TikTok, not HN). Launch it **after** Verdict has cleared HN so that portfolio credibility is visible when the TechCrunch / Insider writeups happen.

---

## 8. What to measure at the portfolio level

| Metric | 30-day | 90-day | 1-year |
|---|---|---|---|
| Combined GitHub stars across 3 dev-tools | 750 | 6,500 | 33,000 |
| Combined PyPI + npm downloads / month | 5,000 | 70,000 | 850,000 |
| HN front-page appearances | 2 | 5 | 15 |
| Podcast episodes featuring a repo | 0 | 2 | 10 |
| Conference talks given | 0 | 1 accepted | 4 |
| Combined Discord members | 150 | 1,000 | 7,000 |
| Named design partners | 3 | 15 | 50 |
| OWASP / standards-body citations | 0 | 2 | 8 |

---

## 9. What *not* to do (portfolio-level)

- **Don't launch all four simultaneously.** Splits attention; each launch cannibalizes the others' HN slot. Space by 2–3 weeks.
- **Don't skip Discord.** Every 10 k-star project has one by 2 k stars.
- **Don't over-invest in dev.to / Medium.** Primary content lives on your own domain (backlinks + SEO). Cross-post to dev.to only.
- **Don't answer HN comments after hour 4.** Diminishing returns; your time is better on the thread on Day 2 elsewhere.
- **Don't pitch Latent Space / Fireship cold.** Wait for organic traction.
- **Don't sell anything in month 1.** Stars over MRR in the opening phase; the commercial wedge (compliance evidence, Airlock Studio pro tier, Verdict team digests) comes after distribution is real.

---

## 10. The closing note

The four repos are **already a coherent stack**. What's missing is distribution work, not engineering work — and the research above shows the playbook is mechanical enough that a disciplined 12-week execution gets all three dev-tool repos past 1 k stars with moderate-to-high confidence, and gives `whyCantWeHaveAnAgentForThis` a real shot at the 100 k-monthly-visit tier.

The single highest-leverage next action is to **clean up whyCant's credentials this hour**, then spend the rest of the week on Verdict's v1.1 polish for a Week 7 launch.
