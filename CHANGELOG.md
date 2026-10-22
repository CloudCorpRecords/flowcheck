# Changelog

## 0.1.0 (2026-10-22)

First release. Security Wave tranche 2.

- `flowcheck audit [path] [--json]`: least-privilege audit of every workflow under .github/workflows. Rules: missing top-level permissions, permissions: write-all, per-job grants broader than the inferred need, pull_request_target / workflow_run / issue_comment combined with a checkout of the PR head, secrets referenced under pull_request, secrets: inherit to reusable workflows, self-hosted runners on PR-reachable triggers, cache poisoning surface, whole-workspace artifact uploads, missing timeout-minutes, missing concurrency guards on deploy-shaped jobs, and workflow_dispatch inputs interpolated into run steps. Verdicts HARDENED / REVIEW / EXPOSED with file, job, and line evidence.
- `flowcheck harden [path] [--json]`: per-job hardened permissions blocks inferred from step types, plus a top-level union block. Output only; no files are written.
- MCP server (stdio) with audit_workflows and harden_plan tools.
- Real YAML parsing (the `yaml` package): anchors, merge keys, and block scalars are resolved, so steps and fields hidden behind them are audited like any other.
- Flush-aware emit contract from day one (FACTORY-NOTES): single write resolving in the stdout callback, process.exitCode, exit 141 on EPIPE, with spawned-CLI pipe regression tests over 200 KiB.
- Build-time validation fixed three calibration problems before publish, ledger P-150 (merge keys unresolved), P-151 (broad-grant severity on opaque action steps), and P-152 (local composite actions and github-script steps as opaque token consumers), each with regression tests.
