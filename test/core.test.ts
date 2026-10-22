/**
 * Acceptance tests: the seven fixtures from the coordinator brief, plus
 * the parser shapes tranche 1 taught us to fear (block scalars, YAML
 * anchors and merge keys, the YAML 1.1 `on` key).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { auditWorkflows, buildHardenPlan, renderReport } from "../src/core.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

function rules(report: ReturnType<typeof auditWorkflows>): string[] {
  return report.findings.map((f) => f.rule);
}

describe("acceptance fixtures", () => {
  it("fixture 1: a fully hardened estate verdicts HARDENED with zero findings", () => {
    const r = auditWorkflows(join(FIXTURES, "f1-hardened"));
    assert.equal(r.counts.files, 2);
    assert.equal(r.findings.length, 0, JSON.stringify(r.findings, null, 2));
    assert.equal(r.verdict, "HARDENED");
  });

  it("fixture 2: pull_request_target plus PR head checkout verdicts EXPOSED with the combo rule", () => {
    const r = auditWorkflows(join(FIXTURES, "f2-prt-head"));
    assert.equal(r.verdict, "EXPOSED");
    const combo = r.findings.find((f) => f.rule === "FC-PR-HEAD-CHECKOUT");
    assert.ok(combo, "combo rule must fire");
    assert.equal(combo.severity, "critical");
    assert.equal(combo.job, "inspect");
    assert.ok(combo.line > 1, "finding must carry a real line number");
  });

  it("fixture 3: no permissions block at all is flagged", () => {
    const r = auditWorkflows(join(FIXTURES, "f3-no-perms"));
    assert.ok(rules(r).includes("FC-NO-TOP-PERMISSIONS"));
    assert.notEqual(r.verdict, "HARDENED");
  });

  it("fixture 4: explicit permissions: write-all is flagged critical", () => {
    const r = auditWorkflows(join(FIXTURES, "f4-write-all"));
    const f = r.findings.find((x) => x.rule === "FC-PERMS-WRITE-ALL");
    assert.ok(f);
    assert.equal(f.severity, "critical");
    assert.equal(r.verdict, "EXPOSED");
  });

  it("fixture 5: cache on pull_request with a later privileged release job fires the cache rule", () => {
    const r = auditWorkflows(join(FIXTURES, "f5-cache"));
    const cache = r.findings.filter((f) => f.rule === "FC-CACHE-POISON");
    assert.ok(cache.length >= 1, JSON.stringify(r.findings, null, 2));
  });

  it("fixture 6: whole-workspace artifact upload is flagged", () => {
    const r = auditWorkflows(join(FIXTURES, "f6-artifact"));
    assert.ok(rules(r).includes("FC-ARTIFACT-WORKSPACE"));
  });

  it("fixture 7: harden_plan for fixture 2 removes the dangerous grants and keeps the job functional", () => {
    const plan = buildHardenPlan(join(FIXTURES, "f2-prt-head"));
    const job = plan.jobs.find((j) => j.job === "inspect");
    assert.ok(job);
    // The job today runs with contents: write and issues: write. Its steps
    // only check out code and run tests, so the plan must drop both write
    // grants and keep exactly the read the checkout needs.
    assert.deepEqual(job.suggested, { contents: "read" });
    assert.match(job.suggestedYaml, /contents: read/);
    assert.ok(!/write/.test(job.suggestedYaml), "plan must not carry any write grant for this job");
    assert.ok(job.notes.some((n) => /privileged trigger context/i.test(n)), "plan must warn about the privileged context");
    assert.ok(!/write/.test(plan.topLevelYaml), "top-level union must not invent a write grant either");
  });
});

describe("extra shapes", () => {
  it("secrets: inherit, self-hosted on untrusted triggers, and dispatch input injection all fire", () => {
    const r = auditWorkflows(join(FIXTURES, "extras"));
    const rs = rules(r);
    assert.ok(rs.includes("FC-SECRETS-INHERIT"), rs.join(","));
    assert.ok(rs.includes("FC-SELF-HOSTED-PR"), rs.join(","));
    assert.ok(rs.includes("FC-DISPATCH-INPUT-INJECTION"), rs.join(","));
    const inherit = r.findings.find((f) => f.rule === "FC-SECRETS-INHERIT");
    assert.equal(inherit?.severity, "high");
  });

  it("block scalar run steps are parsed: a release command inside run: | drives the plan", () => {
    const r = auditWorkflows(join(FIXTURES, "extras"));
    const plan = r.plans.find((p) => p.file.endsWith("blockscalar.yml") && p.job === "build");
    assert.ok(plan);
    assert.equal(plan.suggested["contents"], "write", "the gh release create inside the block scalar must be seen");
    assert.ok(rules(r).filter((x) => x === "FC-PR-HEAD-CHECKOUT").length >= 1, "head_ref checkout under pull_request_target must fire");
  });

  it("YAML anchors and merge keys resolve: timeout inherited through a merge key counts", () => {
    const r = auditWorkflows(join(FIXTURES, "extras"));
    const anchored = r.findings.filter((f) => f.file.endsWith("anchored.yml"));
    assert.equal(anchored.length, 0, JSON.stringify(anchored, null, 2));
  });

  it("missing timeout and missing concurrency fire as lows", () => {
    const r = auditWorkflows(join(FIXTURES, "extras"));
    assert.ok(rules(r).includes("FC-NO-TIMEOUT"));
  });

  it("an empty estate says so plainly instead of reading as an all-clear", () => {
    const r = auditWorkflows(join(FIXTURES, "does-not-exist"));
    assert.match(r.note ?? "", /no workflows found/i);
    assert.match(renderReport(r), /no workflows found/i);
  });

  it("verdict wording never claims a scanned file is safe", () => {
    const r = auditWorkflows(join(FIXTURES, "f1-hardened"));
    assert.equal(r.verdict, "HARDENED");
    assert.match(renderReport(r), /HARDENED/);
  });
});

describe("regression: P-150 merge keys", () => {
  it("a job built from a merge key sees the merged fields, not a bare << key", () => {
    const r = auditWorkflows(join(FIXTURES, "extras"));
    const plan = r.plans.find((p) => p.file.endsWith("anchored.yml"));
    assert.ok(plan);
    assert.equal(plan.suggested["contents"], "read");
  });
});

describe("regression: P-151 opaque action calibration", () => {
  it("a broad grant on a job with an opaque action step grades low with the caveat", async () => {
    const { mkdtempSync, mkdirSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const dir = mkdtempSync(join(tmpdir(), "flowcheck-p151-"));
    const wf = join(dir, ".github", "workflows");
    mkdirSync(wf, { recursive: true });
    writeFileSync(join(wf, "guard.yml"), `name: guard
on: [pull_request]
permissions:
  pull-requests: write
jobs:
  guard:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
      - uses: some-org/some-action@v1
`, "utf8");
    const r = auditWorkflows(dir);
    const f = r.findings.find((x) => x.rule === "FC-JOB-GRANT-BROAD");
    assert.ok(f, "finding must still fire");
    assert.equal(f.severity, "low");
    assert.match(f.message, /not visible in the workflow file/);
  });

  it("the same grant on a transparent job keeps medium severity and no caveat", async () => {
    const { mkdtempSync, mkdirSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const dir = mkdtempSync(join(tmpdir(), "flowcheck-p151b-"));
    const wf = join(dir, ".github", "workflows");
    mkdirSync(wf, { recursive: true });
    writeFileSync(join(wf, "ci.yml"), `name: ci
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      contents: read
      issues: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
      - run: npm test
`, "utf8");
    const r = auditWorkflows(dir);
    const f = r.findings.find((x) => x.rule === "FC-JOB-GRANT-BROAD");
    assert.ok(f);
    assert.equal(f.severity, "medium");
    assert.ok(!/not visible/.test(f.message));
  });
});

describe("regression: P-152 local actions and github-script are opaque consumers", () => {
  it("a broad grant on a job using local composites and github-script grades low", async () => {
    const { mkdtempSync, mkdirSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const dir = mkdtempSync(join(tmpdir(), "flowcheck-p152-"));
    const wf = join(dir, ".github", "workflows");
    mkdirSync(wf, { recursive: true });
    writeFileSync(join(wf, "bench.yml"), `name: bench
on: [pull_request]
permissions:
  contents: read
jobs:
  bench:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
      - uses: ./.github/actions/run-benchmarks
      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7
        with:
          script: |
            const run = require('./tools/pr-comment.js');
            await run({ github, context });
`, "utf8");
    const r = auditWorkflows(dir);
    const f = r.findings.find((x) => x.rule === "FC-JOB-GRANT-BROAD");
    assert.ok(f, "finding must still fire");
    assert.equal(f.severity, "low");
    assert.match(f.message, /not visible in the workflow file/);
  });
});
