# Launch draft — "I re-ran my contract-checker against Docker's MCP Gateway"

Status: **DRAFT** for review. Two versions below: Hacker News and r/LocalLLaMA. First
person, real numbers, every caveat kept in. Not a Show HN (this isn't "look at my new
tool" — it's "I measured two layers people keep conflating"). Lead with the measurement,
link the repo once, answer every reply.

Market context to weave in (both posts):
- Gartner projects roughly **75% of API gateways will ship native MCP support by 2026** —
  so "the gateway already handles it" is about to be the default objection.
- The **MCP spec went final on 2026-07-28** — auth/transport got a lot more rigorous
  (OAuth resource-server mandate, header integrity). That's exactly the layer a gateway
  owns. It says nothing about validating the argument payload a model produces.

---

## A. Hacker News

**Title** (the framing; HN caps titles at 80 chars, so use the short one and put the full
line in the first sentence):

- Intended framing: *I re-ran my agent contract-checker against Docker's native MCP Gateway; here's the exact payload class each blocks*
- Fits-in-80 version to actually submit: **I re-ran my tool-call contract-checker against Docker's native MCP Gateway**

**URL:** https://github.com/sattyamjjain/agent-airlock

**First comment** (post as author right away — this is what carries the thread):

> I maintain a small MIT library that type-checks the arguments an AI agent passes to a
> tool, in-process, at the function boundary. Docker shipped a native MCP Gateway, and the
> obvious question landed in my inbox a few times: doesn't the gateway already do this? So
> I stopped guessing and measured it.
>
> Same 12 malformed tool-call payloads + 3 benign controls, pushed through both a live
> Docker MCP Gateway v2.0.1 and through my library. The gateway side is a real MCP
> `tools/call` sent through the running gateway to an echo backend that does no validation
> of its own, so I can see whether the gateway forwarded the payload or rejected it.
>
> Result (2026-07-16): the gateway forwarded 12/12 to the backend. My contract layer
> blocked 12/12. Both were clean on the 3 benign controls, so this isn't the gateway being
> broken — it forwards everything, because per-argument validation isn't the layer it works
> at.
>
> The 12 classes, and what caught each on my side:
> - `amount="100"` (string for an int field) - strict Pydantic, no coercion
> - `amount=-1` (type-valid int, violates a declared `amount>0`) - the declared constraint
> - `force=True` (argument the tool never declared) - ghost-arg block
> - `path="../../../../etc/passwd"` - path validator
> - `url="http://169.254.169.254/..."` and `file:///etc/shadow` - URL validator
> - eval/exec, `/bin/sh -c ...`, `LD_PRELOAD=...`, `${JWT_SECRET}` in a URL, a triple-quote
>   codegen breakout - the argument-guard chain
> - an over-privileged tool picked when a low-priv one was enough - deny-by-default policy
>
> Here's the part I want to be honest about, because the gateway is not doing nothing. Its
> own logs during the run show it scanning args and responses for known secret values,
> running the server with `no-new-privileges`, and applying cpu/memory caps. There are
> whole threat classes where the gateway is the right tool and my library adds nothing:
> auth and transport (the 2026-07-28 MCP final spec makes this stricter, and it's the
> gateway's job), container isolation and egress, exfiltration of a real stored secret
> value, and server-image signature checks. If those are your risks, a gateway may be
> enough on its own.
>
> The gap it doesn't cover is the argument contract: the payload the model actually
> produced. That's the 12/12.
>
> Two caveats before anyone quotes the number. It's my own corpus, so read it as a
> coverage/regression baseline, not an adaptive-attacker score — a novel payload outside a
> guard's pattern can get past my side too. And the `amount=-1` block only happens because
> the tool declares `amount>0`; a bare `amount: int` would pass it. The contract layer
> enforces the contract you write, it doesn't invent one.
>
> Reproduce (no Docker needed, it replays the recorded gateway measurement):
> `python -m benchmarks.vs_gateway`. The harness to re-measure the gateway live is in the
> repo. With Gartner projecting ~75% of gateways shipping MCP by 2026, "the gateway covers
> it" is about to be the reflexive answer, so I'd rather have the measured split than an
> argument. Curious where people think the line actually sits, and where my corpus is thin.

**Timing:** weekday ~13:00-15:00 UTC. Be around for the first two hours to reply.

---

## B. r/LocalLLaMA

**Title:**

> I re-ran my agent contract-checker against Docker's native MCP Gateway; here's the exact payload class each blocks

**Body:**

> If you run agents locally you've probably wired up a few MCP servers, and you may have
> seen the native gateways showing up (Docker's MCP Gateway, plus the API gateways adding
> MCP — Gartner's line is ~75% of gateways ship MCP by 2026). I kept getting asked whether
> a gateway makes an in-process arg-validator pointless, so I measured it instead of
> arguing.
>
> Setup: one corpus of 12 malformed tool-call payloads + 3 benign controls, sent through
> both a live Docker MCP Gateway v2.0.1 and my library (agent-airlock, MIT). For the
> gateway I send a real MCP `tools/call` through it to an echo backend that validates
> nothing, so I can tell whether the gateway forwarded or blocked each one.
>
> Numbers (2026-07-16): gateway forwarded 12/12 to the backend, my contract layer blocked
> 12/12, both clean on the 3 benign ones. The classes: string-for-int (`amount="100"`),
> value-constraint (`amount=-1`), hallucinated arg (`force=True`), path traversal, SSRF to
> the metadata IP, `file://` read, eval/exec, subprocess injection, `LD_PRELOAD`,
> `${JWT_SECRET}` in a URL, codegen triple-quote breakout, and an over-privileged tool
> pick.
>
> The honest half: the gateway isn't failing, it's doing a different job. Its logs show it
> secret-scanning, sandboxing with `no-new-privileges`, capping resources. For auth,
> transport (the MCP spec went final 2026-07-28 and tightened exactly this), container
> isolation, real-secret exfil, and image signatures, the gateway is the right layer and my
> lib adds nothing. What it doesn't do is check the argument payload the model produced.
> That's the whole gap.
>
> Caveats: it's my own corpus (coverage baseline, not an adaptive-attacker score), and the
> `amount=-1` block needs the tool to actually declare `amount>0` — it enforces your
> contract, doesn't guess one.
>
> Repo + reproducible bench (`python -m benchmarks.vs_gateway`, no Docker required):
> https://github.com/sattyamjjain/agent-airlock . If you run local MCP servers, I'd like to
> know which of these you assumed the gateway already caught.

---

## Notes for you (not for publishing)

- **Lead with the measurement, not the tool.** Both audiences reward "I measured X" and
  punish "check out my project."
- **Keep both caveats in every version** (self-corpus + "you have to declare the
  contract"). Dropping them to look stronger is the fastest way to get called out, and
  they're true.
- **Don't paste the full 12/12 into the README as a hardcoded number** — it's linked and
  lives in `benchmarks/vs_gateway/RESULTS.md` so it can't go stale.
- **HN title length:** submit the 80-char version; the full framing goes in the first line
  of the comment.
- Full deep-dive to link if anyone wants the method + the "where the gateway is enough"
  table: `docs/benchmarks/mcp-gateway-payload-gap.md`.
