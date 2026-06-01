# Contributing to Lantana

Thanks for considering a contribution. Lantana is an open, single-maintainer project. The rules below keep the bar high without making contribution painful: read the docs first, follow the standards CI already enforces, and don't leak operator-identifying values into a public repo.

> [!important]
> Before anything else, read the [Rules of Engagement](README.md#rules-of-engagement) in the README. Contributions that conflict with those rules — particularly Rule #1 (no offensive use) and Rule #6 (no infrastructure disclosure) — will be rejected regardless of code quality.

---

## 1. Before you contribute

Lantana is documentation-first. The docs are the spec; the code follows them. Skim the relevant ones before opening an issue or PR — most "is this a bug?" and "how do I…" questions are already answered there.

- **All contributors** — read [docs/architecture.md](docs/architecture.md) for the zoned model (honeywall / sensor / collector) and the deployment-mode distinction (single-node vs. multi-node).
- **Touching the pipeline (`pipeline/`)** — read [docs/pipeline.md](docs/pipeline.md), [docs/risk-scoring.md](docs/risk-scoring.md), and the **Pipeline fail-safe principles** + **Pipeline verification discipline** sections in [CLAUDE.md](CLAUDE.md). The six fail-safe principles are load-bearing — every defect that surfaced during op_alpha's first production run violated one of them.
- **Touching honeypot roles (`config/ansible/roles/cowrie/`, `config/ansible/roles/dionaea/`)** — read [docs/honeypots.md](docs/honeypots.md) and the **Honeypot deployment discipline** section in [CLAUDE.md](CLAUDE.md). Several Dionaea decisions are load-bearing; reverting them produces silent failures.
- **Touching Vector configs (`*.vector.yaml.j2`)** — read the **Vector deployment discipline** section in [CLAUDE.md](CLAUDE.md). A broken VRL fragment renders fine but crashloops Vector at runtime.
- **Touching deployment (`config/ansible/`)** — read [docs/setup.md](docs/setup.md) and [docs/validation.md](docs/validation.md).
- **Troubleshooting an existing problem** — check [docs/troubleshooting.md](docs/troubleshooting.md) first.
- **Unfamiliar terminology** — see [docs/glossary.md](docs/glossary.md).

### OPSEC: the rule that catches everyone the first time

Lantana's repo is public on GitHub. Anything committed under tracked paths (`README.md`, `docs/`, `config/ansible/` outside `inventories/op_*`, `scripts/`, `infra/`, `pipeline/`, code comments, commit messages, PR descriptions) is world-readable and search-indexable.

**Never commit real values for any of the following:**

- WAN IPv4 / IPv6 addresses, hostnames, MAC addresses, ASNs, domains.
- Server provider account IDs, SSH host fingerprints, API keys.

**Use reserved documentation ranges in every example:**

- IPv4 → RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`.
- IPv6 → RFC 3849: `2001:db8::/32`.
- Domains → RFC 2606: `example.com`, `example.org`, `example.net`.
- ASNs → RFC 5398: `64496–64511`, `65536–65551`.
- Hostnames → archetype-generic (`vps-01`, `sn-01`) — never the real production hostname.

Real values live only inside each operation's `config/ansible/inventories/op_<name>/group_vars/all/` directory, which is either gitignored or vault-encrypted. Heuristic: if an example IP isn't in an RFC documentation range, it's almost certainly real — most slips are commercial VPS/cloud allocations (OVH, Hetzner, DigitalOcean, Linode, AWS, GCP, Azure). When in doubt, ask before committing.

---

## 2. How to file an issue

- **Bugs** — use the *Bug report* template at [Issues → New Issue](../../issues/new/choose). Include the commit SHA, deployment mode, and scrubbed logs. Public.
- **Feature requests / RFEs** — use the *Feature request* template. Public.
- **Security vulnerabilities** — **never** open a public issue. GitHub Issues are world-readable from creation; there is no per-issue confidentiality flag. Use **GitHub Private Vulnerability Reporting** instead: [Security → Advisories → Report a vulnerability](../../security/advisories/new). Details in [SECURITY.md](SECURITY.md).

---

## 3. Development environment

| Stack | Setup |
|---|---|
| Python pipeline | `cd pipeline && uv sync --frozen --extra dev` — `--extra dev` is required because `pytest`, `ruff`, and `mypy` live in `[project.optional-dependencies.dev]`. Bare `uv sync --frozen` strips them. |
| Ansible | `pip install ansible ansible-lint`. Run from `config/ansible/`. |
| Shell | `shellcheck` from `apt` / `brew`. |
| Terraform | `terraform >= 1.15.5` (matches CI). |

Target OS for runtime is Debian 13. Local dev on macOS / other Linux distros is fine for everything except live-deploy testing.

---

## 4. Standards — must pass before opening a PR

The CI workflow (`.github/workflows/ci.yml`) gates every PR with four jobs. If you run their commands locally and they're clean, CI will be green.

### Python (pipeline/)

```bash
cd pipeline
uv run pytest -m "not integration"
uv run ruff check .
uv run mypy --strict src tests
```

Code requirements:

- **Python 3.13+** (Debian 13 native).
- **Pylance strict mode** — full type annotations on every function signature and return type. No `Any` escape hatches.
- **TDD** — write the test first, then the implementation. Every module has a corresponding test file mirroring the `src/` structure.
- **Functional style** — pure functions for data transforms, Pydantic models for structured data, push IO to the edges. Prefer Polars expression chains over imperative loops. Minimize side effects.
- **Boring, reliable tooling only** — Polars, httpx, Pydantic, tenacity, structlog, stix2, Streamlit, Plotly. No exotic or trendy dependencies — propose them in an issue first.
- **Fail-safe principles** — if you touch enrichment, normalisation, or transform code, the six principles in [CLAUDE.md](CLAUDE.md#pipeline-fail-safe-principles) are not optional. Skipping them is what produced 8 distinct defects in op_alpha's first production run.

### Ansible (config/ansible/)

```bash
cd config/ansible
ansible-lint playbooks roles tests
```

- Target OS is Debian 13 exclusively — no portability concessions.
- Jinja2 templates (`.j2`) generate nftables rules, Vector pipelines, Cowrie configs, SSH settings. Mind the **Vector deployment discipline** rule: every role that renders a Vector config must add a merged-tree `vector validate` task before restarting Vector.

### Shell (scripts/)

```bash
shellcheck scripts/*.sh
```

- Plain POSIX-compatible patterns, standard coreutils only. No exotic tools or fancy constructs. Readable and auditable.

### Terraform (infra/terraform/)

```bash
cd infra/terraform
terraform fmt -check -recursive .
cd environments/proxmox
terraform init -backend=false -input=false
terraform validate
```

---

## 5. PR workflow

1. Fork the repo, branch off `main`.
2. **One logical change per PR.** Bundle a related refactor with the feature when splitting would just be churn — but don't sneak unrelated cleanups into a feature PR.
3. **Commit messages**: short, imperative, lowercase. One line is usually enough; add a body only when the *why* isn't obvious. Conventional prefixes are encouraged but not required: `feat:`, `fix:`, `docs:`, `ci:`, `refactor:`, `test:`, `chore:`.
4. **Run the full CI command set locally** before pushing. CI must be green; failing CI = needs-work, maintainer review only after green.
5. **Update the docs** when you change behavior. If you touch a role's defaults, update the corresponding doc page. If you change a pipeline contract, update [docs/pipeline.md](docs/pipeline.md) and the relevant section in [CLAUDE.md](CLAUDE.md).
6. **Open the PR** against `main`. Fill out the PR template — what changed, why, how tested, OPSEC check.
7. Be patient. This is a single-maintainer project. Best-effort review within a week or two.

### What gets a PR rejected fast

- Operator-identifying values in tracked files (Rule #6 violation).
- New dependency in `pipeline/pyproject.toml` without an issue discussing the trade-off.
- Tests removed without explanation.
- `--no-verify`, broad `try/except`, retry loops hiding races, or other ways to paper over a root cause.
- Python code without type annotations.
- Code that violates a documented invariant in [CLAUDE.md](CLAUDE.md) without explicitly arguing why the invariant should change.

---

## 6. Code of Conduct

This project follows the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md). Report unacceptable behavior via [GitHub Private Vulnerability Reporting](../../security/advisories/new) — single-maintainer project, no separate moderation team.

---

## 7. License

Lantana is [MIT-licensed](LICENSE). By submitting a PR, you agree your contribution will be licensed under the same terms.
