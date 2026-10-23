/**
 * Regression: P-178 non-directory targets must not verdict HARDENED.
 *
 * flowcheck 0.1.0 audit on a FIFO, on /dev/null, and on a regular file
 * each returned verdict HARDENED at exit 0 with files 0. A non-directory
 * target is a usage error in every factory sibling (hookcheck,
 * actionpin, injectcheck scan, and tracewatch all exit 2), and a
 * mistyped or attacker-chosen target must not return the strongest
 * possible assurance. The core therefore throws on any target that is
 * not a directory or a single workflow file, the CLI maps that throw
 * to a stderr-only usage error at exit 2 with no report, and the MCP
 * tools surface it as an error result instead of a success verdict.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync, spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { auditWorkflows, buildHardenPlan } from "../src/core.js";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURES = join(REPO_ROOT, "test", "fixtures");

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "flowcheck-p178-"));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function makeFifo(): string {
  const p = join(dir, "target.fifo");
  execFileSync("mkfifo", [p]);
  return p;
}

function makeRegularFile(): string {
  const p = join(dir, "notes.txt");
  writeFileSync(p, "not a workflow\n", "utf8");
  return p;
}

describe("P-178: core rejects non-directory targets", () => {
  it("P-178 FIFO target throws instead of verdicting HARDENED", () => {
    const fifo = makeFifo();
    assert.throws(() => auditWorkflows(fifo), /neither a file nor a directory|not a directory/i);
  });

  it("P-178 /dev/null target throws instead of verdicting HARDENED", () => {
    assert.throws(() => auditWorkflows("/dev/null"), /neither a file nor a directory|not a directory/i);
  });

  it("P-178 regular file target throws instead of verdicting HARDENED", () => {
    const f = makeRegularFile();
    assert.throws(() => auditWorkflows(f), /not a workflow file/i);
    assert.throws(() => buildHardenPlan(f), /not a workflow file/i);
  });

  it("P-178 nonexistent target throws instead of verdicting HARDENED", () => {
    assert.throws(() => auditWorkflows(join(dir, "does-not-exist")), /does not exist/i);
  });

  it("P-178 directory control still verdicts HARDENED", () => {
    const r = auditWorkflows(join(FIXTURES, "f1-hardened"));
    assert.equal(r.verdict, "HARDENED");
    assert.equal(r.counts.files, 2);
  });

  it("P-178 single workflow file control still audits", () => {
    const r = auditWorkflows(join(FIXTURES, "f2-prt-head", "danger.yml"));
    assert.equal(r.verdict, "EXPOSED");
    assert.equal(r.counts.files, 1);
  });
});

interface CliResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

function runCli(args: string[]): Promise<CliResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, ["--import", "tsx", "src/cli.ts", ...args], {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      rejectPromise(new Error("CLI timed out"));
    }, 60000);
    child.stdout.on("data", (c: Buffer) => {
      out += c.toString("utf8");
    });
    child.stderr.on("data", (c: Buffer) => {
      err += c.toString("utf8");
    });
    child.on("error", (e) => {
      clearTimeout(timer);
      rejectPromise(e);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolvePromise({ code, stdout: out, stderr: err });
    });
  });
}

describe("P-178: CLI exits 2 with no HARDENED report on non-directory targets", () => {
  it("P-178 CLI FIFO exits 2", { timeout: 70000 }, async () => {
    const res = await runCli(["audit", makeFifo(), "--json"]);
    assert.equal(res.code, 2, `stderr: ${res.stderr}`);
    assert.ok(!/HARDENED/.test(res.stdout), "no report claiming HARDENED may be emitted");
    assert.match(res.stderr, /error:/i);
  });

  it("P-178 CLI /dev/null exits 2", { timeout: 70000 }, async () => {
    const res = await runCli(["audit", "/dev/null", "--json"]);
    assert.equal(res.code, 2, `stderr: ${res.stderr}`);
    assert.ok(!/HARDENED/.test(res.stdout));
    assert.match(res.stderr, /error:/i);
  });

  it("P-178 CLI regular file exits 2", { timeout: 70000 }, async () => {
    const res = await runCli(["audit", makeRegularFile(), "--json"]);
    assert.equal(res.code, 2, `stderr: ${res.stderr}`);
    assert.ok(!/HARDENED/.test(res.stdout));
    assert.match(res.stderr, /error:/i);
  });

  it("P-178 CLI nonexistent path exits 2", { timeout: 70000 }, async () => {
    const res = await runCli(["audit", join(dir, "does-not-exist"), "--json"]);
    assert.equal(res.code, 2, `stderr: ${res.stderr}`);
    assert.ok(!/HARDENED/.test(res.stdout));
    assert.match(res.stderr, /error:/i);
  });

  it("P-178 CLI harden on a regular file also exits 2", { timeout: 70000 }, async () => {
    const res = await runCli(["harden", makeRegularFile(), "--json"]);
    assert.equal(res.code, 2, `stderr: ${res.stderr}`);
    assert.ok(!/HARDENED/.test(res.stdout));
  });

  it("P-178 CLI directory control still exits 0 HARDENED", { timeout: 70000 }, async () => {
    const res = await runCli(["audit", join(FIXTURES, "f1-hardened"), "--json"]);
    assert.equal(res.code, 0, `stderr: ${res.stderr}`);
    assert.match(res.stdout, /HARDENED/);
  });
});
