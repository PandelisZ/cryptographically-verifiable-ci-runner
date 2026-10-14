# Show HN playbook for vci

What Hacker News rewards, where that advice comes from, and how it applies to this project. The post text itself is in
[README-HN.md](README-HN.md).

## Where this advice comes from

| Source | What it is |
|---|---|
| [Show HN guidelines](https://news.ycombinator.com/showhn.html) | HN's own rules for Show HN posts |
| [Launch HN instructions](https://news.ycombinator.com/yli.html) | The HN team's guide to writing about a project for HN; applies to Show HN too |
| [HN guidelines](https://news.ycombinator.com/newsguidelines.html) | Site-wide rules (titles, no vote solicitation, no generated text) |
| YC launch playbook (Bookface) | "Launch early", "too abstract" is the most common partner feedback, HN works best when there is a tool people can try |
| Bookface post: *How to get your product to the HN front-page* (Layerform) | Title, README and repo tactics from a founder with repeated front pages |
| Bookface post: *How we got >1k points on HN* (Instant) | Essay for credibility, interactive demo, responsiveness in the thread |
| Bookface post: *How to Get #1 Trending on GitHub* (Sim.ai) | Show HN with the repo linked directly outperformed their Launch HN |
| Bookface post: *How Graphiti hit 20K stars* (Zep) | Product Hunt was a waste for a developer tool; HN and research credibility worked |

## The strategy, in one page

**1. Make it something people can try in two minutes.** Show HN is for things people can run. vci qualifies, but
only if a reader can go from the post to a skipped test without talking to anyone: `brew install`, `vci init`,
`vci run`, `vci plan`. No signup, no email, no landing page. The repo is the landing page.

**2. Lead with the problem, as a peer.** Write in the first person about why this exists and what was hard, the way
you would explain it to a former colleague over a drink. No marketing voice, no superlatives ("fastest", "first"),
no "we're going to be huge". Modest language is stronger on HN.

**3. The title is direct and specific, under 80 characters.** It says what the thing is and what it does, with a
technical detail, not a benefit. Good: "Show HN: vci – skip CI tests that were already run, with signed input
hashes". Bad: "Show HN: vci – cut your CI bill by 90%".

**4. Give technical details freely.** HN is insatiably curious. The audience will ask how dependencies are tracked,
what the trust model is, and how it fails. Answer those in the post before they are asked, and explain the jargon
(attestation, collector, base branch) on first use.

**5. Be cheerfully self-critical.** State the limits up front: a trusted key can lie, Rust has no runtime hook,
C extensions are invisible, the 90% number is a model. Critics are doing you a favour; the goal is to win the silent
majority, not the critic.

**6. Say how it makes money (or that it doesn't yet).** HN asks. "It's MIT; there is no company behind it yet; if
this is useful the hosted part would be X" is a fine answer.

**7. End with an open question.** Invite experiences: "How do you handle this today?", "What would make you trust
an agent's test run?"

**8. On the day: reply, reply, reply.** The thread falls off the page when the author is absent. Take breaks, but
not long ones. Find something to agree with in every objection before answering it. Never address people by
username. Never, under any circumstances, ask friends to upvote or to post booster comments; HN detects it and
buries the thread.

**9. Don't coordinate with anything else.** No press, no simultaneous Product Hunt (poor fit for dev tools anyway).
All you need is a free day.

**10. The README is the post.** Readers click the repo first. It needs the same voice, a GIF or screenshot in the
first screen, the two-minute try-it path, and the limits. Images make people decide to read.

## Title options (≤ 80 characters)

1. `Show HN: vci – skip CI tests that were already run locally, with signed proof`
2. `Show HN: vci – CI skips tests an agent already ran, verified by input hashes`
3. `Show HN: vci – signed, per-test attestations so CI can skip what you already ran`

Option 1 is the safest: concrete, no numbers, says what it does. Avoid the 90% figure in the title; it is a model,
and HN crops gratuitous numbers anyway.

## Before posting: checklist

- [ ] `brew install pandelisz/tap/vci` works on a clean macOS and Linux machine.
- [ ] The README's two-minute path works as written, from a fresh checkout, by someone who did not build it.
- [ ] The docs site, the action and the demo PRs all load; the demo PR links show the skips.
- [ ] Pricing / money question answered somewhere visible (README "Status" or the post).
- [ ] The HN account is a personal one, not the project name; contact email in the profile.
- [ ] A free day. Post in the morning US time, any weekday; weekends are slightly easier but smaller.
- [ ] Hard questions below rehearsed.

## Hard questions HN will ask, and honest answers

**"A signed claim is not proof. The signer can lie."** Correct, and the README says so. The signature proves who
claimed it; CI re-derives every hash itself, so the only way to cheat is to lie about the test result, and only a key
listed on the base branch can do that. Keep that list short, give agents their own keys with expiry, and keep full
runs on the default branch. Random re-execution in CI is the planned next step and is not built.

**"How is this different from Turborepo / Nx / Bazel remote caching?"** Those cache by hash of declared inputs and
trust whoever can write to the cache; Nx had CVE-2025-36852 for exactly that. vci records inputs by observing the
test at run time (file reads, probes, env, loaded packages), signs per unit with a per-person key, and verifies
against the base branch. There is no shared cache to poison; metadata alone never causes a skip.

**"Why git-meta instead of a server?"** No new infrastructure to run or trust: attestations are git objects on
`refs/meta/main`, pushed and fetched like code, readable with `git meta get`. Anyone with push access can delete
them, which only costs a skip.

**"What about tests that read something the collector can't see?"** Then it is not attested. Child processes,
network, C-level reads (SQLite in some cases, lxml, libvips), `ENV` enumeration: all refuse. Rust has no runtime
hook at all, so the cargo adapter uses a conservative rule (every file of the crate and its in-repo dependencies)
and is honest about being weaker.

**"90% is marketing."** It is a modelled figure for the case where the whole suite was attested before the push; the
chart says so and shows three cases with no saving. The measured number is the ~10 s verification step.

**"Flaky tests?"** A file with a failed, skipped or pending test is never attested. Flakiness that happens to pass
locally gets a skip once; it is the same test that would have passed in CI by luck.

**"Doesn't this just move the compute to the laptop?"** Yes, for tests that were going to be run locally anyway.
The point is not running them twice. Nothing is skipped that was not run.

**"How do you make money?"** Fill this in honestly before posting.

## Launch sequence for this project

1. Post the Show HN with the repo link in the title's URL (not the docs site): repos earn stars, and the README is
   the strongest page.
2. First comment, posted immediately: the text from [README-HN.md](README-HN.md), section "The Show HN text",
   which is the story, the technical details and the invitation. HN readers expect the author's comment.
3. Stay in the thread all day. Fix small things live (a confusing error, a missing flag) and say so in the thread;
   responsiveness is read as a signal of quality.
4. Afterwards, add a `## Discussion` link to the README and treat the thread's questions as the next docs pass.
