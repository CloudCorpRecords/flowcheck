/**
 * flowcheck core: parse GitHub workflow files with a real YAML parser
 * (the `yaml` package, with a line counter so every finding carries the
 * line it came from), audit permissions and trigger shapes against the
 * least-privilege rules, and infer a hardened permissions block per job
 * from what the job's steps actually do.
 *
 * The question is deliberately different from actionpin's: actionpin asks
 * whether action refs are pinned. flowcheck asks whether the token and
 * the triggers are least-privilege. No code is shared at runtime.
 *
 * Parsing notes that matter:
 * - `on` is read through the document node tree, so the YAML 1.1 boolean
 *   reading of the bare key `on` cannot hide the triggers.
 * - Anchors, aliases, and merge keys are resolved by the parser, so a
 *   step hidden behind an alias is still a step (tranche 1 lesson).
 * - Block scalars arrive as their full text, so run steps written with
 *   `run: |` are inspected exactly like single-line steps (the P-002
 *   lesson from hookcheck: block scalars are the dominant real style).
 * - Static analysis only. Nothing in a scanned repo is ever executed.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, join, relative, resolve } from "node:path";
import { LineCounter, parseDocument, isMap, isSeq, type Node, type Scalar } from "yaml";
import type { AuditReport, Finding, HardenPlan, JobPlan, Severity, Verdict } from "./types.js";

export const VERSION = "0.1.0";

export const MAX_FILES = 500;
export const MAX_FILE_BYTES = 2 * 1024 * 1024;

const PERMISSION_SCOPES = [
  "actions",
  "attestations",
  "checks",
  "contents",
  "deployments",
  "discussions",
  "id-token",
  "issues",
  "packages",
  "pages",
  "pull-requests",
  "repository-projects",
  "security-events",
  "statuses",
] as const;

/** Triggers where code or text from an untrusted author can reach the job. */
const UNTRUSTED_TRIGGERS = new Set([
  "pull_request",
  "pull_request_target",
  "pull_request_review",
  "pull_request_review_comment",
  "issue_comment",
  "issues",
  "workflow_run",
  "discussion",
  "discussion_comment",
  "fork",
]);

/** Triggers that run in the privileged base-repo context by design. */
const PRIVILEGED_CONTEXT_TRIGGERS = new Set(["pull_request_target", "workflow_run", "issue_comment"]);

/** A ref expression that points at the PR author's code, not the base. */
const HEAD_REF_RE = /pull_request\.head|head_ref|workflow_run\.head|pull_request\.head_sha|event\.pull_request/;

/* ------------------------------------------------------------------ */
/* Discovery                                                           */
/* ------------------------------------------------------------------ */

interface DiscoveredFile {
  abs: string;
  rel: string;
}

function isWorkflowName(name: string): boolean {
  return name.endsWith(".yml") || name.endsWith(".yaml");
}

function collectFromDir(dir: string, root: string, out: DiscoveredFile[]): void {
  let entries: string[];
  try {
    entries = readdirSync(dir).sort();
  } catch {
    return;
  }
  for (const name of entries) {
    if (isWorkflowName(name)) {
      const abs = join(dir, name);
      out.push({ abs, rel: relative(root, abs).split("\\").join("/") });
    }
  }
}

/**
 * Resolve the audit target to a list of workflow files. The target may be
 * a repo root (workflows under .github/workflows), a workflows directory,
 * or a single workflow file.
 */
export function discoverWorkflows(target: string): { files: DiscoveredFile[]; filesSeen: number; root: string } {
  const root = resolve(target);
  const files: DiscoveredFile[] = [];
  let st;
  try {
    st = statSync(root);
  } catch {
    return { files, filesSeen: 0, root };
  }
  if (st.isFile()) {
    if (isWorkflowName(basename(root))) files.push({ abs: root, rel: basename(root) });
    return { files, filesSeen: files.length, root };
  }
  const wfDir = join(root, ".github", "workflows");
  let wfStat;
  try {
    wfStat = statSync(wfDir);
  } catch {
    wfStat = undefined;
  }
  if (wfStat?.isDirectory()) {
    collectFromDir(wfDir, root, files);
  } else {
    // A workflows directory passed directly, or a bare directory of
    // workflow files (the shape test fixtures and extracted estates use).
    collectFromDir(root, root, files);
  }
  files.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  return { files, filesSeen: files.length, root };
}

/* ------------------------------------------------------------------ */
/* YAML helpers: plain values plus a path to line index                */
/* ------------------------------------------------------------------ */

type Plain = Record<string, unknown> | unknown[] | string | number | boolean | null | undefined;

function keyName(keyNode: Node | Scalar | unknown): string {
  if (keyNode && typeof keyNode === "object" && "value" in (keyNode as Scalar)) {
    const v = (keyNode as Scalar).value;
    // YAML 1.1 reads the bare key `on` as boolean true.
    if (v === true) return "on";
    return String(v);
  }
  return String(keyNode);
}

/** Build a map from dotted document path to 1-based line number. */
function buildLineIndex(doc: ReturnType<typeof parseDocument>, lineCounter: LineCounter): Map<string, number> {
  const index = new Map<string, number>();
  const walk = (node: unknown, path: string): void => {
    if (!node || typeof node !== "object") return;
    const n = node as Node & { range?: [number, number, number] };
    if (Array.isArray(n.range)) {
      index.set(path, lineCounter.linePos(n.range[0]).line);
    }
    if (isMap(node)) {
      for (const item of node.items) {
        const k = keyName(item.key as Node);
        walk(item.value as Node, path ? `${path}.${k}` : k);
        // The key node itself carries the line of keys like `permissions:`.
        const keyNode = item.key as Node & { range?: [number, number, number] };
        if (Array.isArray(keyNode?.range)) {
          index.set(path ? `${path}.${k}` : k, lineCounter.linePos(keyNode.range[0]).line);
        }
      }
    } else if (isSeq(node)) {
      node.items.forEach((item, i) => walk(item, `${path}[${i}]`));
    }
  };
  walk(doc.contents, "");
  return index;
}

function lineAt(index: Map<string, number>, path: string, fallback = 1): number {
  return index.get(path) ?? fallback;
}

/* ------------------------------------------------------------------ */
/* Permission model                                                    */
/* ------------------------------------------------------------------ */

type PermKind = "absent" | "write-all" | "read-all" | "none" | "map" | "other";

interface PermSet {
  kind: PermKind;
  grants: Map<string, string>;
}

function parsePermissions(value: Plain): PermSet {
  if (value === undefined || value === null) return { kind: "absent", grants: new Map() };
  if (typeof value === "string") {
    const v = value.trim().toLowerCase();
    if (v === "write-all") return { kind: "write-all", grants: new Map(PERMISSION_SCOPES.map((s) => [s, "write"])) };
    if (v === "read-all") return { kind: "read-all", grants: new Map(PERMISSION_SCOPES.map((s) => [s, "read"])) };
    return { kind: "other", grants: new Map() };
  }
  if (typeof value === "object" && !Array.isArray(value)) {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return { kind: "none", grants: new Map() };
    const grants = new Map<string, string>();
    for (const [scope, level] of entries) {
      grants.set(scope, typeof level === "string" ? level.toLowerCase() : String(level));
    }
    // In a permissions map, any scope not listed is set to none.
    return { kind: "map", grants };
  }
  return { kind: "other", grants: new Map() };
}

function describePerms(p: PermSet): string {
  switch (p.kind) {
    case "absent":
      return "no permissions block (GitHub default token permissions apply)";
    case "write-all":
      return "permissions: write-all";
    case "read-all":
      return "permissions: read-all";
    case "none":
      return "permissions: {} (no grants)";
    case "map":
      return `permissions: { ${[...p.grants.entries()].map(([s, l]) => `${s}: ${l}`).join(", ")} }`;
    default:
      return "unrecognized permissions value";
  }
}

/* ------------------------------------------------------------------ */
/* Step analysis: what a job actually needs                            */
/* ------------------------------------------------------------------ */

interface StepInfo {
  uses?: string;
  run?: string;
  withObj?: Record<string, unknown>;
  index: number;
}

function asRecord(v: Plain): Record<string, unknown> {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function str(v: unknown): string {
  return typeof v === "string" ? v : v === undefined || v === null ? "" : String(v);
}

/** Actions whose token needs are understood by inferJobNeeds. */
const KNOWN_ACTIONS = new Set([
  "actions/checkout",
  "actions/cache",
  "actions/cache/save",
  "actions/cache/restore",
  "actions/upload-artifact",
  "actions/download-artifact",
  "actions/github-script",
  "actions/deploy-pages",
  "actions/stale",
  "actions/labeler",
  "actions/attest-build-provenance",
  "docker/build-push-action",
  "docker/login-action",
  "docker/setup-buildx-action",
  "docker/setup-qemu-action",
  "peaceiris/actions-gh-pages",
  "softprops/action-gh-release",
  "aws-actions/configure-aws-credentials",
  "azure/login",
  "google-github-actions/auth",
]);

function isOpaqueActionStep(step: StepInfo): boolean {
  if (!step.uses) return false;
  const action = step.uses.toLowerCase().split("@")[0];
  // Local composite actions run with the job token, and their steps live
  // in the action's own file, which flowcheck does not follow in v0.1.0.
  if (action.startsWith("./") || action.startsWith("../")) return true;
  // A github-script step is arbitrary JavaScript with an authenticated
  // client; it routinely delegates to repo files (require(...)) whose API
  // calls no YAML-level heuristic can see.
  if (action === "actions/github-script") return true;
  if (/^actions\/setup-/.test(action)) return false;
  if (action.includes("release-please") || action.endsWith("/action-gh-release") || action.includes("comment")) return false;
  return !KNOWN_ACTIONS.has(action);
}

/** Apply run-script heuristics to a grants map (mutates `needs`). */
function applyScriptHeuristics(text: string, needs: Map<string, string>, markers: Set<string>): void {
  const need = (scope: string, level: string) => {
    const cur = needs.get(scope);
    if (cur !== "write") needs.set(scope, level);
    if (level === "write") needs.set(scope, "write");
  };
  if (/\bgh\s+release\s+(create|upload|edit|delete)\b/.test(text)) {
    need("contents", "write");
    markers.add("release");
  }
  if (/\bgh\s+pr\s+(create|merge|close|edit|comment|review|ready|reopen)\b/.test(text)) {
    need("pull-requests", "write");
    if (/\bgh\s+pr\s+merge\b/.test(text)) need("contents", "write");
    markers.add("pr-write");
  }
  if (/\bgh\s+issue\s+(create|close|edit|comment|label|pin|lock)\b/.test(text)) {
    need("issues", "write");
    markers.add("issue-write");
  }
  if (/\bgit\s+push\b/.test(text)) {
    need("contents", "write");
    markers.add("git-push");
  }
  if (/\b(docker|podman)\s+push\b/.test(text) || /buildx\s+build[^|\n]*--push/.test(text)) {
    need("packages", "write");
    markers.add("image-push");
  }
  if (/\bnpm\s+publish\b/.test(text) || /\b(pnpm|yarn)\s+(publish|npm\s+publish)\b/.test(text)) {
    markers.add("package-publish");
  }
  if (/createComment|issues\.create|pulls\.create|createReview|createRelease|repos\.create/.test(text)) {
    if (/createComment/.test(text)) {
      need("issues", "write");
      need("pull-requests", "write");
    }
    if (/createRelease|repos\.create/.test(text)) need("contents", "write");
    markers.add("api-write");
  }
  if (/\bdeploy\b|\bnetlify\b|\bvercel\s+deploy\b|\bfirebase\s+deploy\b/.test(text)) {
    markers.add("deploy");
  }
  if (/\boidc\b/i.test(text)) {
    need("id-token", "write");
    markers.add("oidc");
  }
}

/** Infer the least-privilege grants a job needs from its steps. */
export function inferJobNeeds(steps: StepInfo[], jobLevelUses: string | undefined): { needs: Map<string, string>; markers: Set<string> } {
  const needs = new Map<string, string>();
  const markers = new Set<string>();
  const need = (scope: string, level: string) => {
    if (needs.get(scope) !== "write") needs.set(scope, level);
    if (level === "write") needs.set(scope, "write");
  };
  for (const step of steps) {
    const uses = (step.uses ?? "").toLowerCase();
    const action = uses.split("@")[0];
    if (action === "actions/checkout") need("contents", "read");
    if (action === "softprops/action-gh-release" || action.endsWith("/action-gh-release")) {
      need("contents", "write");
      markers.add("release");
    }
    if (action.includes("release-please")) {
      need("contents", "write");
      need("pull-requests", "write");
      markers.add("release");
    }
    if (action === "docker/build-push-action") {
      const push = step.withObj?.push;
      if (push !== false && push !== "false") {
        need("packages", "write");
        markers.add("image-push");
      }
    }
    if (action === "actions/deploy-pages") {
      need("pages", "write");
      need("id-token", "write");
      markers.add("deploy");
    }
    if (action === "peaceiris/actions-gh-pages") {
      need("contents", "write");
      markers.add("deploy");
    }
    if (action === "actions/attest-build-provenance") {
      need("attestations", "write");
      need("id-token", "write");
    }
    if (action === "aws-actions/configure-aws-credentials" && step.withObj?.["role-to-assume"]) {
      need("id-token", "write");
      markers.add("oidc");
    }
    if (action === "azure/login" || action === "google-github-actions/auth") {
      need("id-token", "write");
      markers.add("oidc");
    }
    if (action === "actions/stale") {
      need("issues", "write");
      need("pull-requests", "write");
    }
    if (action === "actions/labeler") need("pull-requests", "write");
    if (action.includes("comment") && !action.startsWith("actions/")) {
      need("pull-requests", "write");
      need("issues", "write");
      markers.add("pr-write");
    }
    if (action === "actions/cache" || action === "actions/cache/save" || action === "actions/cache/restore") {
      markers.add("cache");
    }
    if (action === "actions/upload-artifact") markers.add("upload-artifact");
    if (action === "actions/github-script" && step.withObj?.script) {
      applyScriptHeuristics(str(step.withObj.script), needs, markers);
    }
    if (step.run) applyScriptHeuristics(step.run, needs, markers);
    // setup-* actions with a cache option pull from the same cache surface.
    if (/^actions\/setup-/.test(action) && step.withObj && "cache" in step.withObj) markers.add("cache");
  }
  if (jobLevelUses) markers.add("reusable");
  return { needs, markers };
}

function sortedGrants(grants: Map<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const scope of PERMISSION_SCOPES) {
    const v = grants.get(scope);
    if (v) out[scope] = v;
  }
  for (const [k, v] of [...grants.entries()].sort()) {
    if (!(k in out)) out[k] = v;
  }
  return out;
}

function grantsYaml(grants: Map<string, string>, indent: string): string {
  const rec = sortedGrants(grants);
  const keys = Object.keys(rec);
  if (keys.length === 0) return `${indent}permissions: {}`;
  const lines = [`${indent}permissions:`];
  for (const k of keys) lines.push(`${indent}  ${k}: ${rec[k]}`);
  return lines.join("\n");
}

/* ------------------------------------------------------------------ */
/* Per-file audit                                                      */
/* ------------------------------------------------------------------ */

interface FileAudit {
  findings: Finding[];
  plans: JobPlan[];
  jobCount: number;
  triggers: string[];
  needsUnion: Map<string, string>;
}

function triggerNames(onValue: Plain): string[] {
  if (typeof onValue === "string") return [onValue];
  if (Array.isArray(onValue)) return onValue.map((v) => str(v)).filter(Boolean);
  if (onValue && typeof onValue === "object") return Object.keys(onValue as Record<string, unknown>);
  return [];
}

function auditFile(rel: string, content: string): FileAudit {
  const findings: Finding[] = [];
  const plans: JobPlan[] = [];
  const lineCounter = new LineCounter();
  const doc = parseDocument(content, { lineCounter, merge: true });
  const lines = buildLineIndex(doc, lineCounter);
  const data = (doc.toJS() ?? {}) as Record<string, unknown>;
  const onValue = (data["on"] ?? (data as Record<string, unknown>)[String(true)]) as Plain;
  const triggers = triggerNames(onValue);
  const triggerSet = new Set(triggers);
  const hasUntrusted = triggers.some((t) => UNTRUSTED_TRIGGERS.has(t));
  const hasPrivilegedContext = triggers.some((t) => PRIVILEGED_CONTEXT_TRIGGERS.has(t));
  const hasPrTrigger = triggerSet.has("pull_request") || triggerSet.has("pull_request_target");

  for (const err of doc.errors) {
    findings.push({
      rule: "FC-PARSE-ERROR",
      severity: "medium",
      file: rel,
      line: err.linePos?.[0]?.line ?? 1,
      message: `Workflow YAML does not parse cleanly: ${err.message.split("\n")[0]}`,
    });
  }

  const topPerms = parsePermissions(data["permissions"] as Plain);
  const topLine = lineAt(lines, "permissions");
  const workflowConcurrency = data["concurrency"] !== undefined;

  if (topPerms.kind === "write-all") {
    findings.push({
      rule: "FC-PERMS-WRITE-ALL",
      severity: "critical",
      file: rel,
      line: topLine,
      message: "Top-level permissions: write-all grants every scope write access to every job in this workflow.",
    });
  }
  if (topPerms.kind === "read-all") {
    findings.push({
      rule: "FC-PERMS-READ-ALL",
      severity: "low",
      file: rel,
      line: topLine,
      message: "Top-level permissions: read-all grants read on every scope; an explicit scope list is tighter.",
    });
  }

  const jobsObj = asRecord(data["jobs"] as Plain);
  const jobNames = Object.keys(jobsObj);
  const needsUnion = new Map<string, string>();
  let anyCacheStep = false;
  let anyPrivilegedUse = false;

  // First pass: collect per-job facts so cross-job rules (cache) can see
  // the whole file before findings are emitted.
  interface JobFacts {
    name: string;
    job: Record<string, unknown>;
    steps: StepInfo[];
    needs: Map<string, string>;
    markers: Set<string>;
    perms: PermSet;
    jobUses?: string;
  }
  const facts: JobFacts[] = [];
  for (const name of jobNames) {
    const job = asRecord(jobsObj[name] as Plain);
    const rawSteps = Array.isArray(job["steps"]) ? (job["steps"] as unknown[]) : [];
    const steps: StepInfo[] = rawSteps.map((s, i) => {
      const rec = asRecord(s as Plain);
      return {
        uses: rec["uses"] !== undefined ? str(rec["uses"]) : undefined,
        run: rec["run"] !== undefined ? str(rec["run"]) : undefined,
        withObj: rec["with"] !== undefined ? asRecord(rec["with"] as Plain) : undefined,
        index: i,
      };
    });
    const jobUses = job["uses"] !== undefined ? str(job["uses"]) : undefined;
    const { needs, markers } = inferJobNeeds(steps, jobUses);
    const perms = parsePermissions(job["permissions"] as Plain);
    for (const [s, l] of needs) {
      if (l === "write") needsUnion.set(s, "write");
      else if (!needsUnion.has(s)) needsUnion.set(s, l);
    }
    if (markers.has("cache")) anyCacheStep = true;
    if ([...needs.values()].includes("write") || markers.has("release") || markers.has("deploy") || markers.has("image-push") || markers.has("package-publish")) {
      anyPrivilegedUse = true;
    }
    facts.push({ name, job, steps, needs, markers, perms, jobUses });
  }
  if (topPerms.kind === "write-all" || (topPerms.kind === "map" && [...topPerms.grants.values()].includes("write"))) {
    anyPrivilegedUse = true;
  }

  if (topPerms.kind === "absent" && jobNames.length > 0) {
    findings.push({
      rule: "FC-NO-TOP-PERMISSIONS",
      severity: hasPrivilegedContext || hasUntrusted ? "high" : "medium",
      file: rel,
      line: 1,
      message:
        "No top-level permissions block. On many repos the default GITHUB_TOKEN is permissive (write-all on legacy settings), so every job inherits broader access than it needs. Add an explicit top-level block, conventionally permissions: contents: read, and elevate per job.",
    });
  }

  for (const f of facts) {
    const jobPath = `jobs.${f.name}`;
    const jobLine = lineAt(lines, jobPath);
    const effective = f.perms.kind !== "absent" ? f.perms : topPerms;
    const effectiveDesc = f.perms.kind !== "absent" ? describePerms(f.perms) : `inherited: ${describePerms(topPerms)}`;

    // write-all at job level
    if (f.perms.kind === "write-all") {
      findings.push({
        rule: "FC-PERMS-WRITE-ALL",
        severity: "high",
        file: rel,
        job: f.name,
        line: lineAt(lines, `${jobPath}.permissions`, jobLine),
        message: `Job "${f.name}" sets permissions: write-all, granting every scope write access.`,
      });
    }

    // Grants broader than the steps need. Only explicit map grants are
    // compared scope by scope; write-all and absent are handled above.
    // Calibration (ledger P-151, P-152): a grant may be consumed by a
    // step whose token use is not visible in the YAML: a third-party
    // action, a local composite action (its steps live in its own file),
    // or a github-script step (arbitrary JS, often delegating to repo
    // files). When the job has such an opaque step the finding drops to
    // low and says so; on a fully transparent job (run steps and known
    // actions only) the finding stands at full severity.
    if (effective.kind === "map") {
      const opaque = f.steps.some((s) => isOpaqueActionStep(s));
      for (const [scope, level] of [...effective.grants.entries()].sort()) {
        if (level !== "write") continue;
        const needed = f.needs.get(scope);
        if (needed === "write") continue;
        const ownLine = f.perms.kind !== "absent" ? lineAt(lines, `${jobPath}.permissions`, jobLine) : topLine;
        findings.push({
          rule: "FC-JOB-GRANT-BROAD",
          severity: opaque ? "low" : scope === "id-token" ? "high" : "medium",
          file: rel,
          job: f.name,
          line: ownLine,
          message: `Job "${f.name}" is granted ${scope}: write but no step in the job needs ${scope} write access (inferred need: ${needed ?? "none"}). Drop it to ${needed ?? "none"} in the hardened plan.${opaque ? " Caveat: this job runs an action whose token use is not visible in the workflow file, and that action may be what consumes the grant; verify before removing." : ""}`,
        });
      }
    }

    // pull_request_target / workflow_run / issue_comment + PR head checkout
    if (hasPrivilegedContext) {
      f.steps.forEach((step, i) => {
        const action = (step.uses ?? "").toLowerCase().split("@")[0];
        if (action !== "actions/checkout") return;
        const ref = str(step.withObj?.ref);
        if (ref && HEAD_REF_RE.test(ref)) {
          findings.push({
            rule: "FC-PR-HEAD-CHECKOUT",
            severity: "critical",
            file: rel,
            job: f.name,
            line: lineAt(lines, `${jobPath}.steps[${i}]`, jobLine),
            message: `Privileged trigger context (${triggers.filter((t) => PRIVILEGED_CONTEXT_TRIGGERS.has(t)).join(", ")}) combined with a checkout of the PR head (${ref}). The workflow runs with base-repo secrets and a write token while checking out untrusted PR code; any later run step executes that code with those privileges.`,
          });
        }
      });
    }

    // secrets passed wholesale to a reusable workflow
    if (f.jobUses) {
      const secretsVal = f.job["secrets"];
      if (typeof secretsVal === "string" && secretsVal.trim().toLowerCase() === "inherit") {
        findings.push({
          rule: "FC-SECRETS-INHERIT",
          severity: hasUntrusted ? "high" : "medium",
          file: rel,
          job: f.name,
          line: lineAt(lines, `${jobPath}.secrets`, jobLine),
          message: `Job "${f.name}" calls reusable workflow ${f.jobUses} with secrets: inherit, passing every repo secret to the called workflow${hasUntrusted ? " in a workflow reachable from untrusted triggers" : ""}. Pass only the secrets the called workflow names.`,
        });
      }
    }

    // self-hosted runner reachable from PR triggers
    const runsOnRaw = f.job["runs-on"];
    const runsOn = Array.isArray(runsOnRaw) ? runsOnRaw.map((v) => str(v)) : [str(runsOnRaw)];
    if (runsOn.some((r) => r.toLowerCase() === "self-hosted") && (hasPrTrigger || hasPrivilegedContext || triggerSet.has("issue_comment"))) {
      findings.push({
        rule: "FC-SELF-HOSTED-PR",
        severity: "high",
        file: rel,
        job: f.name,
        line: lineAt(lines, `${jobPath}.runs-on`, jobLine),
        message: `Job "${f.name}" runs on a self-hosted runner in a workflow with PR-reachable triggers (${triggers.join(", ")}). Fork PR code executing on a self-hosted runner reaches the machine and the network behind it.`,
      });
    }

    // missing timeout
    if (f.job["timeout-minutes"] === undefined && !f.jobUses) {
      findings.push({
        rule: "FC-NO-TIMEOUT",
        severity: "low",
        file: rel,
        job: f.name,
        line: jobLine,
        message: `Job "${f.name}" sets no timeout-minutes. The platform default is 360 minutes, so a hung or looping job burns runner time and holds its token for hours.`,
      });
    }

    // deploy-shaped job without a concurrency guard
    const deployShaped =
      f.markers.has("deploy") || f.markers.has("release") || f.markers.has("image-push") || f.markers.has("package-publish") || f.job["environment"] !== undefined;
    if (deployShaped && !workflowConcurrency && f.job["concurrency"] === undefined && !f.jobUses) {
      findings.push({
        rule: "FC-NO-CONCURRENCY",
        severity: "low",
        file: rel,
        job: f.name,
        line: jobLine,
        message: `Job "${f.name}" looks deploy-shaped (release, publish, image push, or an environment) but neither the job nor the workflow sets a concurrency guard, so two runs can deploy over each other.`,
      });
    }

    // cache steps (rule emitted after the loop when privileged use exists)
    // whole-workspace artifact uploads
    f.steps.forEach((step, i) => {
      const action = (step.uses ?? "").toLowerCase().split("@")[0];
      if (action !== "actions/upload-artifact") return;
      const pathVal = step.withObj?.path;
      const tokens =
        pathVal === undefined
          ? ["."]
          : str(pathVal)
              .split(/\r?\n/)
              .map((t) => t.trim())
              .filter(Boolean);
      const whole = tokens.filter((t) => t === "." || t === "./" || t === "**" || t === "*" || t === "./**");
      if (whole.length > 0 || pathVal === undefined) {
        findings.push({
          rule: "FC-ARTIFACT-WORKSPACE",
          severity: "medium",
          file: rel,
          job: f.name,
          line: lineAt(lines, `${jobPath}.steps[${i}]`, jobLine),
          message: `Job "${f.name}" uploads the whole workspace as an artifact (${pathVal === undefined ? "no path given, which defaults to the workspace" : `path: ${whole.join(", ")}`}). Workspace artifacts routinely carry .git, local config, and any secret material a prior step wrote to disk. Upload named paths instead.`,
        });
      }
    });

    // workflow_dispatch inputs flowing into run steps
    if (triggerSet.has("workflow_dispatch")) {
      f.steps.forEach((step, i) => {
        if (step.run && /\$\{\{\s*(github\.event\.)?inputs\./.test(step.run)) {
          findings.push({
            rule: "FC-DISPATCH-INPUT-INJECTION",
            severity: "low",
            file: rel,
            job: f.name,
            line: lineAt(lines, `${jobPath}.steps[${i}]`, jobLine),
            message: `Job "${f.name}" interpolates a workflow_dispatch input directly into a run step. Dispatch inputs are free text for anyone with dispatch access; pass them through an env var and validate, or quote them as data, not shell.`,
          });
        }
      });
    }

    // Harden plan for this job.
    const notes: string[] = [];
    if (f.jobUses) {
      notes.push("Reusable workflow call: the called workflow's steps were not inspected, so the suggestion keeps only what the call itself implies. Review the called workflow separately.");
    }
    if (hasPrivilegedContext && f.steps.some((s) => (s.uses ?? "").toLowerCase().startsWith("actions/checkout"))) {
      notes.push("This workflow runs in a privileged trigger context. If any checkout targets the PR head, treat that job as untrusted code execution: split it, run the untrusted part with permissions: {} and no secrets, and do privileged work in a separate job on data, not code.");
    }
    const excess = effective.kind === "map" ? [...effective.grants.entries()].filter(([s, l]) => l === "write" && f.needs.get(s) !== "write").map(([s]) => s) : [];
    if (excess.length > 0) notes.push(`Removes write grants no step needs: ${excess.join(", ")}.`);
    if (f.needs.size === 0 && !f.jobUses) notes.push("No step in this job uses the GITHUB_TOKEN, so the job can run with permissions: {} (every scope none).");
    plans.push({
      file: rel,
      job: f.name,
      current: effectiveDesc,
      suggested: sortedGrants(f.needs),
      suggestedYaml: grantsYaml(f.needs, "    "),
      notes,
    });
  }

  // Cache poisoning surface: cache written from PR-triggered runs and a
  // privileged consumer in the same workflow.
  if (anyCacheStep && hasPrTrigger && anyPrivilegedUse) {
    for (const f of facts) {
      f.steps.forEach((step, i) => {
        const action = (step.uses ?? "").toLowerCase().split("@")[0];
        const isCache = action === "actions/cache" || action === "actions/cache/save" || (/^actions\/setup-/.test(action) && step.withObj && "cache" in step.withObj);
        if (!isCache) return;
        findings.push({
          rule: "FC-CACHE-POISON",
          severity: "medium",
          file: rel,
          job: f.name,
          line: lineAt(lines, `jobs.${f.name}.steps[${i}]`, 1),
          message: `Cache step in job "${f.name}" runs under a PR trigger while this workflow also has a privileged (write) consumer. A poisoned cache entry written from a PR run can be restored by a later privileged run and execute inside it. Scope cache keys by branch trust or split the PR and privileged workflows.`,
        });
      });
    }
  }

  // Secrets referenced under a plain pull_request trigger.
  if (triggerSet.has("pull_request")) {
    const rawLines = content.split(/\r?\n/);
    let firstLine = 0;
    let count = 0;
    rawLines.forEach((l, i) => {
      const m = l.match(/secrets\.[A-Za-z0-9_]+/g);
      if (m) {
        count += m.length;
        if (!firstLine) firstLine = i + 1;
      }
    });
    if (count > 0) {
      findings.push({
        rule: "FC-SECRETS-ON-PR",
        severity: "medium",
        file: rel,
        line: firstLine,
        message: `${count} secret reference(s) in a workflow triggered by pull_request. Fork PRs do not receive secrets, but same-repo PR branches run with them before merge, and any step that checks out or executes PR code in the same job can reach them. Keep secret use in jobs that never touch PR code.`,
      });
    }
  }

  return { findings, plans, jobCount: jobNames.length, triggers, needsUnion };
}

/* ------------------------------------------------------------------ */
/* Whole-estate audit                                                  */
/* ------------------------------------------------------------------ */

function verdictFor(findings: Finding[]): Verdict {
  if (findings.some((f) => f.severity === "critical" || f.severity === "high")) return "EXPOSED";
  if (findings.length > 0) return "REVIEW";
  return "HARDENED";
}

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function auditWorkflows(target: string): AuditReport {
  const { files, filesSeen, root } = discoverWorkflows(target);
  const truncated = filesSeen > MAX_FILES;
  const kept = files.slice(0, MAX_FILES);
  const findings: Finding[] = [];
  const plans: JobPlan[] = [];
  const skippedOversize: string[] = [];
  let jobs = 0;
  for (const file of kept) {
    let size = 0;
    try {
      size = statSync(file.abs).size;
    } catch {
      continue;
    }
    if (size > MAX_FILE_BYTES) {
      skippedOversize.push(file.rel);
      continue;
    }
    let content: string;
    try {
      content = readFileSync(file.abs, "utf8");
    } catch {
      continue;
    }
    const r = auditFile(file.rel, content);
    findings.push(...r.findings);
    plans.push(...r.plans);
    jobs += r.jobCount;
  }
  findings.sort(
    (a, b) =>
      (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) ||
      a.line - b.line ||
      SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
      (a.rule < b.rule ? -1 : a.rule > b.rule ? 1 : 0) ||
      (a.job ?? "").localeCompare(b.job ?? ""),
  );
  plans.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || a.job.localeCompare(b.job));
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) bySeverity[f.severity] += 1;
  const notes: string[] = [];
  if (files.length === 0) {
    notes.push("No workflows found under the target path (looked for .github/workflows/*.yml and *.yaml). Nothing was audited; the verdict covers an empty estate.");
  }
  if (truncated) {
    notes.push(`Estate cap reached: ${filesSeen} workflow files found, only the first ${MAX_FILES} (sorted by path) were audited. The remaining files were NOT scanned; split the target to cover them.`);
  }
  if (skippedOversize.length > 0) {
    notes.push(`Skipped ${skippedOversize.length} oversize workflow file(s) over ${MAX_FILE_BYTES} bytes: ${skippedOversize.join(", ")}. They were NOT scanned.`);
  }
  void root;
  return {
    tool: "flowcheck",
    version: VERSION,
    target,
    verdict: verdictFor(findings),
    counts: { files: kept.length - skippedOversize.length, jobs, findings: findings.length, bySeverity },
    findings,
    plans,
    caps: { maxFiles: MAX_FILES, maxFileBytes: MAX_FILE_BYTES, filesSeen, truncated, skippedOversize },
    ...(notes.length > 0 ? { note: notes.join(" ") } : {}),
  };
}

export function buildHardenPlan(target: string): HardenPlan {
  const report = auditWorkflows(target);
  const union = new Map<string, string>();
  for (const plan of report.plans) {
    for (const [scope, level] of Object.entries(plan.suggested)) {
      if (level === "write") union.set(scope, "write");
      else if (!union.has(scope)) union.set(scope, level);
    }
  }
  return {
    tool: "flowcheck",
    version: VERSION,
    target,
    verdict: report.verdict,
    jobs: report.plans,
    topLevelYaml: grantsYaml(union, ""),
    findings: report.findings,
    ...(report.note ? { note: report.note } : {}),
  };
}

/* ------------------------------------------------------------------ */
/* Rendering                                                           */
/* ------------------------------------------------------------------ */

export function renderReport(report: AuditReport): string {
  const out: string[] = [];
  out.push(`flowcheck audit ${report.target}: ${report.verdict}`);
  out.push(
    `  workflows: ${report.counts.files}, jobs: ${report.counts.jobs}, findings: ${report.counts.findings} (critical: ${report.counts.bySeverity.critical}, high: ${report.counts.bySeverity.high}, medium: ${report.counts.bySeverity.medium}, low: ${report.counts.bySeverity.low})`,
  );
  if (report.note) out.push(`  note: ${report.note}`);
  for (const f of report.findings) {
    out.push(`  [${f.severity.toUpperCase()}] ${f.file}:${f.line} ${f.rule}${f.job ? ` (job ${f.job})` : ""} ${f.message}`);
  }
  if (report.plans.length > 0) {
    out.push("  hardened permissions plan:");
    for (const p of report.plans) {
      out.push(`    ${p.file} job ${p.job}: currently ${p.current}`);
      for (const line of p.suggestedYaml.split("\n")) out.push(`  ${line}`);
    }
  }
  if (report.verdict === "HARDENED") out.push("HARDENED: every workflow carries explicit least-privilege permissions and no dangerous trigger shape was found.");
  else if (report.verdict === "EXPOSED") out.push("EXPOSED: at least one critical or high finding. A token or trigger shape gives untrusted code or an over-broad grant a path to write access.");
  else out.push("REVIEW: no critical or high findings, but medium or low findings need a human decision.");
  return out.join("\n");
}

export function renderPlan(plan: HardenPlan): string {
  const out: string[] = [];
  out.push(`flowcheck harden plan ${plan.target}: ${plan.verdict}`);
  if (plan.note) out.push(`  note: ${plan.note}`);
  out.push("  suggested top-level block (union of every job's inferred needs; per-job blocks below are tighter):");
  for (const line of plan.topLevelYaml.split("\n")) out.push(`    ${line}`);
  for (const p of plan.jobs) {
    out.push(`  ${p.file} job ${p.job}: currently ${p.current}`);
    for (const line of p.suggestedYaml.split("\n")) out.push(`    ${line}`);
    for (const n of p.notes) out.push(`    note: ${n}`);
  }
  return out.join("\n");
}
