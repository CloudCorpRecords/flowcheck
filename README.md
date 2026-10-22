# flowcheck

**The default GitHub token can write to your repo. Most workflows never check.**

Every GitHub Actions workflow runs with a GITHUB_TOKEN. Repos created with legacy settings give that token write access to nearly everything, and a workflow with no `permissions:` block inherits whatever the repo default is. Add the trigger shapes that check out pull request code inside a privileged context, secrets passed wholesale to reusable workflows, and caches written by PR runs and read back by release runs, and the workflow file itself becomes the attack surface. The 2025 tj-actions compromise showed how fast a trusted action can turn; "pwn request" write-ups have shown the same for `pull_request_target` checkouts of PR heads for years.

flowcheck audits every workflow in a repo for least-privilege problems, shows the evidence per file, job, and line, and emits a hardened permissions block per job, inferred from what the job's steps actually do, that you can paste in.

## Why this exists

GitHub Actions are the second largest confirmed open source supply-chain attack surface of the last year, behind only npm. The failures are rarely exotic: a missing permissions block, one `write-all`, a checkout of `${{ github.event.pull_request.head.sha }}` under `pull_request_target`, a self-hosted runner answering PR triggers. All of them are visible in the YAML, statically, before anything runs. flowcheck reads the YAML with a real parser (anchors, merge keys, and block scalars included), never executes anything in the scanned repo, and is callable by agents through MCP so the audit can run inside contribution and release workflows, not just by hand.

Sibling tools ask different questions: actionpin asks whether action refs are pinned to SHAs. flowcheck asks whether permissions and triggers are least-privilege. They share no code.

## What it checks

| rule | severity | what it means |
| --- | --- | --- |
| `FC-PERMS-WRITE-ALL` | critical (top level), high (job) | `permissions: write-all`, every scope writable by the token. |
| `FC-PR-HEAD-CHECKOUT` | critical | `pull_request_target`, `workflow_run`, or `issue_comment` trigger combined with a checkout whose ref points at the PR head. Privileged context, untrusted code. |
| `FC-NO-TOP-PERMISSIONS` | high or medium | No top-level `permissions:` block. Jobs inherit the repo default token, which is write-all on many repos. |
| `FC-JOB-GRANT-BROAD` | medium (high for `id-token`) | A job (or the top-level block it inherits) grants a write scope no step in the job needs, judged against the inferred needs. |
| `FC-SECRETS-INHERIT` | high or medium | A reusable workflow call passes `secrets: inherit`, handing every repo secret to the called workflow. |
| `FC-SELF-HOSTED-PR` | high | A `self-hosted` runner in a workflow with PR-reachable triggers. Fork code on your machine and your network. |
| `FC-SECRETS-ON-PR` | medium | Secret references in a `pull_request` workflow. Same-repo PR branches run with secrets before merge. |
| `FC-CACHE-POISON` | medium | A cache step under a PR trigger in a workflow that also has a privileged (write) consumer: a poisoned cache entry can execute inside a later privileged run. |
| `FC-ARTIFACT-WORKSPACE` | medium | `actions/upload-artifact` uploading the whole workspace (`path: .`, `**`, or no path), which routinely carries `.git`, config, and spilled secret material. |
| `FC-PERMS-READ-ALL` | low | `permissions: read-all` instead of an explicit scope list. |
| `FC-NO-TIMEOUT` | low | A job with no `timeout-minutes`. The platform default is 360 minutes. |
| `FC-NO-CONCURRENCY` | low | A deploy-shaped job (release, publish, image push, or an `environment`) with no concurrency guard at job or workflow level. |
| `FC-DISPATCH-INPUT-INJECTION` | low | A `workflow_dispatch` input interpolated directly into a `run` step, where free text becomes shell. |
| `FC-PARSE-ERROR` | medium | The workflow YAML does not parse cleanly. |

Verdict rules:

- **EXPOSED**: at least one critical or high finding. Exit code 1.
- **REVIEW**: only medium or low findings. Exit code 1.
- **HARDENED**: no findings. Exit code 0.
- **Usage errors** exit with code 2. A reader that closes the output pipe early makes the process exit 141, never 0.

## The hardened plan

For every job, flowcheck infers the least privilege its steps need:

| step shape | inferred grant |
| --- | --- |
| `actions/checkout` | `contents: read` |
| release creation (`gh release create`, `softprops/action-gh-release`) | `contents: write` |
| image push (`docker/build-push-action` with push, `docker push`, `buildx --push`) | `packages: write` |
| PR writes (`gh pr create`, `gh pr comment`, labeler, stale) | `pull-requests: write` |
| issue writes (`gh issue comment` and friends) | `issues: write` |
| Pages deploy (`actions/deploy-pages`) | `pages: write`, `id-token: write` |
| OIDC sign-in (AWS, Azure, Google auth actions, explicit OIDC use in scripts) | `id-token: write` |
| build provenance (`actions/attest-build-provenance`) | `attestations: write`, `id-token: write` |
| no token use at all | `permissions: {}` |

`audit` prints the plan next to the findings; `harden` prints the per-job blocks plus a top-level union block. Nothing is written to your files: the plan is output, you paste it.

## Usage

### CLI

```bash
# Audit the current repo
npx @reneturcios/flowcheck audit

# Audit another path, machine readable
npx @reneturcios/flowcheck audit ~/src/my-repo --json

# Just the hardening plan
npx @reneturcios/flowcheck harden ~/src/my-repo
```

Example output:

```text
flowcheck audit .: EXPOSED
  workflows: 2, jobs: 3, findings: 2 (critical: 1, high: 1, medium: 0, low: 0)
  [CRITICAL] .github/workflows/pr.yml:14 FC-PR-HEAD-CHECKOUT (job inspect) Privileged trigger context (pull_request_target) combined with a checkout of the PR head (...)
  [HIGH] .github/workflows/pr.yml:1 FC-NO-TOP-PERMISSIONS No top-level permissions block. ...
EXPOSED: at least one critical or high finding. ...
```

Auditing needs no credentials and no network. Estate caps are explicit, never silent: at most 500 workflow files per run and 2 MiB per file, and the report's `caps` field plus a note say when a cap was hit and what was not scanned.

### MCP server

Add to your MCP client config:

```json
{
  "mcpServers": {
    "flowcheck": {
      "command": "npx",
      "args": ["-y", "@reneturcios/flowcheck", "mcp"]
    }
  }
}
```

Tools: `audit_workflows(path)` returns the full audit report as JSON. `harden_plan(path)` returns the per-job hardened permissions blocks, the top-level union block, and the findings they answer.

## Limits, stated plainly

- Permission inference is heuristic. It recognizes the step shapes in the table above plus common `gh` CLI and script patterns. An unknown third-party action may need more (or less) than the plan suggests; the plan is a starting point a human reviews, not a proof.
- Broad-grant findings are calibrated for invisible consumers: when a job contains a step whose token use cannot be seen in the workflow file (an unknown third-party action, a local composite action, or an `actions/github-script` step, which is arbitrary JavaScript that often delegates to repo files), the finding is reported at low severity with that caveat instead of medium or high. flowcheck does not follow local composite action files or scripts a step delegates to in v0.1.0.
- The PR-head checkout rule needs an explicit ref expression pointing at the head (`pull_request.head`, `head_ref`, `workflow_run.head`). A checkout with no ref under `pull_request_target` checks out the base branch, which is the safe shape, and is not flagged. Indirect head checkouts assembled through env vars or outputs are not traced.
- Self-hosted detection sees the literal `self-hosted` label in `runs-on`; runner groups named without the label are not recognized.
- Reusable workflow jobs are planned from the call site only; the called workflow's own steps are a separate audit target.
- Matrix-generated jobs are audited as written, once, not per matrix combination.
- The secrets rule counts references under `pull_request`; it does not try to prove a specific secret reaches a specific step.
