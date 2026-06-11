# Lantana — Future work

Tracked items that are intentionally not in v1.0.0 but worth doing later. Each entry is a self-contained brief: what, why, acceptance criteria, and effort estimate. Add new items at the bottom; mark done items struck-through rather than deleting (history is useful).

Effort key:
- **low** — single-PR change, ≤1 day focused work
- **medium** — multi-component change with CI/infra surface, 1–2 weeks focused work
- **high** — architectural shift, multiple weeks, may need design doc first

---

## Self-built honeypot images (Effort: medium)

**What.** Replace the upstream rolling tags `docker.io/cowrie/cowrie:latest` and `docker.io/dinotools/dionaea:nightly` with images built by our own CI from a pinned upstream git ref. Push to `ghcr.io/lopes/lantana-cowrie` and `ghcr.io/lopes/lantana-dionaea`. Quadlets point at the new registry + tag.

**Why.** Two incidents on 2026-06-08 → 2026-06-10 traced to upstream image rebases silently flowing into production: cowrie's in-image UID shifted 998 → 999, and dionaea's two-user runtime started racing the Quadlet's `,U` flag at every restart. Both surfaced through the runner-kill-blind-spot path — zero events looks identical to a quiet attack day from the pipeline's perspective, so detection took 4 and 7 days respectively. Full context in [CLAUDE.md](/CLAUDE.md) "Honeypot deployment discipline" and [docs/honeypots.md](/docs/honeypots.md) "Image sourcing strategy."

Owning the build pipeline removes three classes of risk:

1. **In-container UID/GID becomes a repo constant.** The Quadlet's `UserNS=keep-id:uid=999,gid=999` literal would no longer be coupled to an upstream user's whim — we'd set it in the Containerfile.
2. **Rebases happen on our schedule, in a PR, with CI tests.** No more silent overnight `podman pull`. The validation playbook can gate the merge.
3. **We can carry in-house patches.** The dionaea MSSQL version-string hardcoding and the SHA-512-vs-SHA-256 hashing limitation listed under [Known limitations](/docs/honeypots.md#known-limitations-v100) could move from "blocked on upstream" to "fixed at build time."

**Acceptance criteria.**

- `.github/workflows/build-cowrie.yml` and `.github/workflows/build-dionaea.yml` exist. Each:
  - Builds from a pinned `git ref` of the upstream source (referenced as a build-arg, not floating)
  - Tags the resulting image with the upstream ref's short SHA plus an `op_alpha`-style channel tag
  - Pushes to `ghcr.io/lopes/lantana-{cowrie,dionaea}` on `main` merges
  - Runs on a monthly schedule (`cron: '0 0 1 * *'`) AND on changes to `roles/cowrie/**` / `roles/dionaea/**` / the workflow file itself
- A rebuild produces a new image tag; bumping the tag in `roles/<honeypot>/templates/<honeypot>.container.j2` is the one-line PR that promotes it. Next deploy picks it up via Quadlet recreation.
- A post-build test job runs the validate-single-node playbook against the new image in a transient environment (a single-node deploy on a throwaway VM, GitHub-hosted runner with Podman, or `act`).
- The "image-UID coupling" bullets in CLAUDE.md change from "review on upstream rebase" to "controlled by `.github/workflows/build-<honeypot>.yml`."

**Why medium, not low.** The cowrie and dionaea Containerfiles are both upstream-public and ~50 lines each — translating to our own builds is mechanical. What pushes this to medium is the surrounding CI/CD: image registry setup, signed tag promotion, the test harness that catches "image builds but breaks the deploy", and the ongoing maintenance discipline (someone has to look at the monthly rebuild PR). Estimate 1–2 weeks focused.

**Why not high.** No architectural shift, no protocol-level work. The pipeline, the inventory model, and the Quadlet structure all stay the same. Only the image source and the build trigger change.

**Risks / open questions.**

- ghcr.io rate limits on anonymous pulls; if a clean deploy ever runs without GitHub auth, the image won't pull. Mitigation: the deploy is interactive (operator-driven), and we can mirror to a second registry if needed.
- Honoring upstream's intent: cowrie and dionaea ship under permissive licences, and the build is mechanical, but we should still credit upstream in the image labels and link back from `ghcr.io`'s package page.
- Synchronisation with upstream security advisories. Today we get them implicitly via `:latest`/`:nightly` — once we pin, we own the responsibility to watch upstream releases and bump the ref.
