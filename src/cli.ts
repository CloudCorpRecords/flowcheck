#!/usr/bin/env node
/**
 * flowcheck CLI.
 *
 *   flowcheck audit [path] [--json]
 *   flowcheck harden [path] [--json]
 *   flowcheck mcp
 *   flowcheck --version
 *
 * Exit codes: 0 HARDENED, 1 REVIEW or EXPOSED, 2 usage error,
 * 141 when the reader closed the output pipe before the report was
 * delivered (the shell-visible equivalent of death by SIGPIPE).
 *
 * Every report goes through emit(), which waits for stdout to flush
 * before the exit code takes effect. Calling process.exit() right after
 * console.log() truncates piped output once it passes one pipe buffer
 * (64 KiB on Linux). That bug shipped in all three tranche 1 tools
 * (ledger P-001, P-017, P-021); the contract in FACTORY-NOTES.md is
 * inherited here from day one, with the spawned-CLI pipe regression
 * tests in test/pipe.test.ts.
 */
import { auditWorkflows, buildHardenPlan, renderPlan, renderReport, VERSION } from "./core.js";

function exitBrokenPipe(): never {
  process.exit(141);
}

process.stdout.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EPIPE") exitBrokenPipe();
  throw err;
});

/** Write one full report and resolve only after stdout has flushed it. */
async function emit(text: string, code: number): Promise<void> {
  process.exitCode = code;
  await new Promise<void>((resolve, reject) => {
    process.stdout.write(`${text}\n`, (err) => {
      if (!err) {
        resolve();
        return;
      }
      if ((err as NodeJS.ErrnoException).code === "EPIPE") exitBrokenPipe();
      reject(err);
    });
  });
}

function usage(): never {
  console.error(`Usage:
  flowcheck audit [path] [--json]
  flowcheck harden [path] [--json]
  flowcheck mcp
  flowcheck --version`);
  process.exit(2);
}

function has(args: string[], name: string): boolean {
  return args.includes(name);
}

function positional(args: string[]): string[] {
  return args.filter((a) => !a.startsWith("--"));
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "--version" || cmd === "-v" || cmd === "version") {
    console.log(VERSION);
    return;
  }
  if (cmd === "mcp") {
    await import("./mcp.js");
    return;
  }
  if (!cmd) usage();
  try {
    if (cmd === "audit") {
      const [target] = positional(rest);
      const report = auditWorkflows(target ?? ".");
      const text = has(rest, "--json") ? JSON.stringify(report, null, 2) : renderReport(report);
      await emit(text, report.verdict === "HARDENED" ? 0 : 1);
    } else if (cmd === "harden") {
      const [target] = positional(rest);
      const plan = buildHardenPlan(target ?? ".");
      const text = has(rest, "--json") ? JSON.stringify(plan, null, 2) : renderPlan(plan);
      await emit(text, 0);
    } else {
      usage();
    }
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 2;
  }
}

void main();
